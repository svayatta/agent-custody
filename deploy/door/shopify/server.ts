// The agent-custody door for one Shopify store. A Shopify storefront is hosted by Shopify, so no proxy can stand in
// front of it. This app is a server that we run, so it runs the in-process door in front of two agent routes:
//   POST /orders   makes a draft order (draftOrderCreate); no money moves until the buyer pays at Shopify checkout
//   POST /refunds  refunds part of an order (refundCreate), once for each Idempotency-Key
// The door decides first (policy.cedar) and signs a receipt for each decision. This file runs only for an allowed request.
// start.ts runs it. This file does not import the door, so the tests can give it the door from the source tree.
// All Shopify access comes from the environment. See README.md in this directory.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { join } from "node:path";

/** The one Admin API version that this app is written for. */
export const API_VERSION = "2026-10";
const RECEIPT_HEADER = "x-agent-custody-receipt";
const TIMEOUT_MS = 10_000;
const MAX_BODY = 16 * 1024;

/** The in-process door, as far as this file needs it: a Connect-style middleware. */
type Guard = (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;

export interface ShopifyEnv {
  SHOPIFY_SHOP?: string;
  SHOPIFY_ADMIN_TOKEN?: string;
  SHOPIFY_CLIENT_ID?: string;
  SHOPIFY_CLIENT_SECRET?: string;
  /** replaces `https://${SHOPIFY_SHOP}`, so that a test can point the app at a stand-in */
  SHOPIFY_BASE_URL?: string;
}

/** A failure that the agent sees. `definite` is true when Shopify did nothing, so a retry is safe. */
class Failure extends Error {
  status: number;
  definite: boolean;
  constructor(message: string, status: number, definite: boolean) {
    super(message);
    this.status = status;
    this.definite = definite;
  }
}

/** Shopify's decimal string for an amount in minor units, with the exponent of the currency: 1999 USD is "19.99", 500 JPY is "500". */
export function toDecimal(minor: number, currency: string): string {
  const digits = new Intl.NumberFormat("en", { style: "currency", currency }).resolvedOptions().maximumFractionDigits ?? 2;
  if (digits === 0) return String(minor);
  const s = String(minor).padStart(digits + 1, "0");
  return `${s.slice(0, -digits)}.${s.slice(-digits)}`;
}

function toMinor(decimal: string, currency: string): number {
  const digits = new Intl.NumberFormat("en", { style: "currency", currency }).resolvedOptions().maximumFractionDigits ?? 2;
  const [whole = "0", fraction = ""] = decimal.split(".");
  return Number(whole + fraction.padEnd(digits, "0").slice(0, digits));
}

const gid = (kind: string, id: string) => (id.startsWith("gid://") ? id : `gid://shopify/${kind}/${id}`);
const text = (e: unknown) => (e instanceof Error ? e.message : String(e)).slice(0, 300);

type Stored = { fingerprint: string; state: "pending" } | { fingerprint: string; state: "done"; status: number; body: unknown };

/**
 * The app: both routes, behind `guard`. `dataDir` holds `idempotency.json`, the refund keys.
 */
export function shopifyServer(guard: Guard, env: ShopifyEnv, dataDir: string): Server {
  const shop = env.SHOPIFY_SHOP ?? "";
  const base = env.SHOPIFY_BASE_URL ?? `https://${shop}`;
  if (!env.SHOPIFY_BASE_URL && !/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(shop)) throw new Error("SHOPIFY_SHOP is the store's myshopify.com domain, for example x.myshopify.com");
  if (!env.SHOPIFY_ADMIN_TOKEN && !(env.SHOPIFY_CLIENT_ID && env.SHOPIFY_CLIENT_SECRET)) throw new Error("set SHOPIFY_ADMIN_TOKEN, or SHOPIFY_CLIENT_ID with SHOPIFY_CLIENT_SECRET");

  let cached: { token: string; expires: number } | undefined;
  async function accessToken(): Promise<string> {
    if (env.SHOPIFY_ADMIN_TOKEN) return env.SHOPIFY_ADMIN_TOKEN;
    if (cached && cached.expires > Date.now() + 60_000) return cached.token;
    // the client-credentials grant: the app's own id and secret for a token that expires
    const res = await fetch(`${base}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ client_id: env.SHOPIFY_CLIENT_ID, client_secret: env.SHOPIFY_CLIENT_SECRET, grant_type: "client_credentials" }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    }).catch((e: unknown) => { throw new Failure(`Shopify gave no token: ${text(e)}`, 502, true); });
    const j = (await res.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
    if (!res.ok || !j?.access_token) throw new Failure(`Shopify gave no token (${res.status})`, 502, true);
    cached = { token: j.access_token, expires: Date.now() + (j.expires_in ?? 3600) * 1000 };
    return cached.token;
  }

  async function graphql(query: string, variables: unknown): Promise<any> {
    const token = await accessToken();
    let res: Response;
    try {
      res = await fetch(`${base}/admin/api/${API_VERSION}/graphql.json`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-shopify-access-token": token },
        body: JSON.stringify({ query, variables }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (e) {
      throw new Failure(`Shopify did not answer: ${text(e)}`, 502, false);
    }
    // a 4xx did nothing; after a 5xx, or a lost answer, Shopify may have acted
    if (!res.ok) throw new Failure(`Shopify answered ${res.status}`, 502, res.status < 500);
    const j = (await res.json().catch(() => null)) as { data?: any; errors?: unknown } | null;
    if (!j) throw new Failure("Shopify's answer was not JSON", 502, false);
    if (j.errors || !j.data) throw new Failure(`Shopify refused the query: ${text(JSON.stringify(j.errors))}`, 502, true);
    return j.data;
  }

  const userErrors = (errors: { message: string }[] | undefined) => {
    if (errors?.length) throw new Failure(`Shopify refused: ${errors.map((e) => e.message).join("; ")}`, 422, true);
  };

  async function placeOrder(body: any, receiptId: string) {
    const lines: unknown = body?.lines;
    if (!Array.isArray(lines) || lines.length < 1 || lines.length > 50) throw new Failure("lines is 1 to 50 of { variant_id, quantity }", 400, true);
    const lineItems = lines.map((l: any) => {
      if (!/^(gid:\/\/shopify\/ProductVariant\/)?\d+$/.test(String(l?.variant_id)) || !Number.isInteger(l?.quantity) || l.quantity < 1 || l.quantity > 1000) throw new Failure("a line is { variant_id, quantity }: a variant id and a whole quantity from 1 to 1000", 400, true);
      return { variantId: gid("ProductVariant", String(l.variant_id)), quantity: l.quantity };
    });
    if (typeof body.email !== "string" || !/^[^\s@]{1,64}@[^\s@]{1,255}$/.test(body.email)) throw new Failure("email is the buyer's address", 400, true);
    // the tag marks the order as an agent's; the note points the store's record at the door receipt
    const data = await graphql(
      `mutation($input: DraftOrderInput!) { draftOrderCreate(input: $input) { draftOrder { id invoiceUrl totalPriceSet { shopMoney { amount currencyCode } } } userErrors { message } } }`,
      { input: { email: body.email, lineItems, tags: ["agent-custody"], note: `agent-custody receipt ${receiptId}` } },
    );
    userErrors(data.draftOrderCreate?.userErrors);
    const d = data.draftOrderCreate?.draftOrder;
    if (!d?.id) throw new Failure("Shopify made no draft order", 502, false);
    const money = d.totalPriceSet.shopMoney as { amount: string; currencyCode: string };
    return { draft_order_id: d.id as string, total: { amount: toMinor(money.amount, money.currencyCode), currency: money.currencyCode }, invoice_url: d.invoiceUrl as string };
  }

  async function refund(body: any, receiptId: string) {
    if (!/^(gid:\/\/shopify\/Order\/)?\d+$/.test(String(body?.order_id))) throw new Failure("order_id is the order's id", 400, true);
    if (!Number.isSafeInteger(body.amount) || body.amount <= 0) throw new Failure("amount is a whole number of minor units above 0", 400, true);
    if (body.reason !== undefined && (typeof body.reason !== "string" || body.reason.length > 200)) throw new Failure("reason is text of at most 200 characters", 400, true);
    const orderId = gid("Order", String(body.order_id));
    const found = await graphql(`query($id: ID!) { order(id: $id) { transactions { id kind status gateway amountSet { presentmentMoney { currencyCode } } } } }`, { id: orderId });
    if (!found.order) throw new Failure("no such order", 404, true);
    const sale = (found.order.transactions as { id: string; kind: string; status: string; gateway: string; amountSet: { presentmentMoney: { currencyCode: string } } }[]).find((t) => (t.kind === "SALE" || t.kind === "CAPTURE") && t.status === "SUCCESS");
    if (!sale) throw new Failure("the order has no successful sale or capture to refund", 422, true);
    const currency = sale.amountSet.presentmentMoney.currencyCode;
    const data = await graphql(
      `mutation($input: RefundInput!) { refundCreate(input: $input) { refund { id } userErrors { message } } }`,
      { input: { orderId, currency, note: `agent-custody receipt ${receiptId}${body.reason ? `: ${body.reason}` : ""}`, transactions: [{ orderId, parentId: sale.id, gateway: sale.gateway, kind: "REFUND", amount: toDecimal(body.amount, currency) }] } },
    );
    userErrors(data.refundCreate?.userErrors);
    if (!data.refundCreate?.refund?.id) throw new Failure("Shopify made no refund", 502, false);
    return { refund_id: data.refundCreate.refund.id as string, amount: body.amount as number, currency };
  }

  // ponytail: the keys live in one process's memory and one file; two processes on one data directory would not see each other's pending keys, so run one process per store
  const file = join(dataDir, "idempotency.json");
  const keys = new Map<string, Stored>(existsSync(file) ? Object.entries(JSON.parse(readFileSync(file, "utf8")) as Record<string, Stored>) : []);
  const save = () => {
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(`${file}.tmp`, JSON.stringify(Object.fromEntries(keys)));
    renameSync(`${file}.tmp`, file);
  };

  /**
   * A refund once for each key. The lookup and the "pending" write run with no await between them, so no second
   * request with the key gets in; that is the lock. A key whose Shopify call may have acted stays pending, and a retry
   * with it gets 409, because a second refund is worse than a refund that someone must look at.
   */
  async function refundOnce(key: string, body: any, receiptId: string): Promise<{ status: number; body: unknown }> {
    const fingerprint = createHash("sha256").update(`${body?.order_id}|${body?.amount}`).digest("hex");
    const seen = keys.get(key);
    if (seen) {
      if (seen.fingerprint !== fingerprint) return { status: 422, body: { error: "this Idempotency-Key was used for another refund" } };
      return seen.state === "done" ? { status: seen.status, body: seen.body } : { status: 409, body: { error: "a refund with this Idempotency-Key is in progress, or did not finish; check the order in Shopify before another try" } };
    }
    keys.set(key, { fingerprint, state: "pending" });
    save();
    try {
      const result = await refund(body, receiptId);
      keys.set(key, { fingerprint, state: "done", status: 201, body: result });
      save();
      return { status: 201, body: result };
    } catch (e) {
      if (e instanceof Failure && e.definite) {
        keys.delete(key);
        save();
      }
      throw e;
    }
  }

  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = (req.url ?? "").split("?")[0];
    if (req.method !== "POST" || (path !== "/orders" && path !== "/refunds")) return json(res, 404, { error: "not found" });
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > MAX_BODY) return json(res, 413, { error: "body too large" });
      chunks.push(c as Buffer);
    }
    let body: unknown;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return json(res, 400, { error: "the body is JSON" });
    }
    const receiptId = String(req.headers[RECEIPT_HEADER]);
    if (path === "/orders") return json(res, 201, await placeOrder(body, receiptId));
    const key = req.headers["idempotency-key"];
    if (typeof key !== "string" || !/^[\x21-\x7e]{1,128}$/.test(key)) return json(res, 400, { error: "a refund needs an Idempotency-Key header: 1 to 128 printable characters" });
    const r = await refundOnce(key, body, receiptId);
    json(res, r.status, r.body);
  }

  return createServer((req, res) => {
    guard(req, res, (err) => {
      if (err) return json(res, 500, { error: "the door failed" });
      handle(req, res).catch((e: unknown) => {
        if (res.headersSent) return res.destroy();
        if (e instanceof Failure) return json(res, e.status, { error: e.message });
        json(res, 502, { error: `the app failed: ${text(e)}` });
      });
    });
  });
}
