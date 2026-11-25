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

/** A failure that the agent sees. `definite` is true when Shopify did nothing. */
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

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/**
 * The agent that the door verified. The door passes the app no subject. It keeps `Signature-Input` on the request, and it
 * checked that signature: a refund route admits only a `verified` arrival, so the keyid of the signature is the did:key
 * of the agent that holds the passport. Exactly one keyid is required, so a second, unchecked signature cannot name another agent.
 */
function verifiedAgent(req: IncomingMessage): string | null {
  const ids = [...String(req.headers["signature-input"] ?? "").matchAll(/keyid="([^"]+)"/g)];
  return ids.length === 1 ? ids[0]![1]! : null;
}

/**
 * The app: both routes, behind `guard`. `dataDir` holds `idempotency.json`, the refund keys.
 */
export function shopifyServer(guard: Guard, env: ShopifyEnv, dataDir: string): Server {
  const shop = env.SHOPIFY_SHOP ?? "";
  const base = env.SHOPIFY_BASE_URL ?? `https://${shop}`;
  if (!env.SHOPIFY_BASE_URL && !/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(shop)) throw new Error("SHOPIFY_SHOP is the store's myshopify.com domain, for example x.myshopify.com");
  if (!env.SHOPIFY_ADMIN_TOKEN && !(env.SHOPIFY_CLIENT_ID && env.SHOPIFY_CLIENT_SECRET)) throw new Error("set SHOPIFY_CLIENT_ID with SHOPIFY_CLIENT_SECRET, or SHOPIFY_ADMIN_TOKEN for a legacy custom app");

  let cached: { token: string; expires: number } | undefined;
  async function accessToken(): Promise<string> {
    if (env.SHOPIFY_ADMIN_TOKEN) return env.SHOPIFY_ADMIN_TOKEN;
    if (cached && cached.expires > Date.now() + 60_000) return cached.token;
    // the client-credentials grant, form-encoded: the app's own id and secret for a token that expires
    const res = await fetch(`${base}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: env.SHOPIFY_CLIENT_ID!, client_secret: env.SHOPIFY_CLIENT_SECRET! }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    }).catch((e: unknown) => { throw new Failure(`Shopify gave no token: ${text(e)}`, 502, true); });
    const j = (await res.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
    if (!res.ok || !j?.access_token) throw new Failure(`Shopify gave no token (${res.status})`, 502, true);
    cached = { token: j.access_token, expires: Date.now() + (j.expires_in ?? 3600) * 1000 };
    return cached.token;
  }

  /** Shopify's answer, with its `data` and `errors` as given. A 401 drops the cached token once and sends the call again: the callers send a read or an idempotent mutation. */
  async function graphql(query: string, variables: unknown): Promise<{ data?: any; errors?: unknown }> {
    for (let attempt = 0; ; attempt++) {
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
      if (res.status === 401 && attempt === 0 && !env.SHOPIFY_ADMIN_TOKEN) {
        cached = undefined;
        continue;
      }
      // a 4xx did nothing; after a 5xx, or a lost answer, Shopify may have acted
      if (!res.ok) throw new Failure(`Shopify answered ${res.status}`, 502, res.status < 500);
      const j = (await res.json().catch(() => null)) as { data?: any; errors?: unknown } | null;
      if (!j) throw new Failure("Shopify's answer was not JSON", 502, false);
      return j;
    }
  }

  /** The data of a call, or a failure when Shopify gave none. The detail goes to the log, not to the agent. */
  const dataOf = (j: { data?: any; errors?: unknown }) => {
    if (j.errors || !j.data) {
      console.error(`agent-custody shopify: Shopify refused the query: ${text(JSON.stringify(j.errors))}`);
      throw new Failure("Shopify refused the query", 502, true);
    }
    return j.data;
  };

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
    const data = dataOf(await graphql(
      `mutation($input: DraftOrderInput!) { draftOrderCreate(input: $input) { draftOrder { id invoiceUrl totalPriceSet { shopMoney { amount currencyCode } } } userErrors { message } } }`,
      { input: { email: body.email, lineItems, tags: ["agent-custody"], note: `agent-custody receipt ${receiptId}` } },
    ));
    userErrors(data.draftOrderCreate?.userErrors);
    const d = data.draftOrderCreate?.draftOrder;
    if (!d?.id) throw new Failure("Shopify made no draft order", 502, false);
    // the total is in the shop's currency, never the buyer's presentment currency
    const money = d.totalPriceSet.shopMoney as { amount: string; currencyCode: string };
    return { draft_order_id: d.id as string, total: { amount: toMinor(money.amount, money.currencyCode), currency: money.currencyCode }, invoice_url: d.invoiceUrl as string };
  }

  /** The order's sale or capture, and its presentment currency. A read: it fails before anything is pending. */
  async function saleOf(orderId: string) {
    const found = dataOf(await graphql(`query($id: ID!) { order(id: $id) { transactions { id kind status gateway amountSet { presentmentMoney { currencyCode } } } } }`, { id: orderId }));
    if (!found.order) throw new Failure("no such order", 404, true);
    const sale = (found.order.transactions as { id: string; kind: string; status: string; gateway: string | null; amountSet: { presentmentMoney: { currencyCode: string } } }[]).find((t) => (t.kind === "SALE" || t.kind === "CAPTURE") && t.status === "SUCCESS");
    if (!sale) throw new Failure("the order has no successful sale or capture to refund", 422, true);
    return sale;
  }

  // ponytail: the lock and the keys live in one process; two processes on one data directory would not see each other's in-flight refunds (Shopify still dedupes by key), so run one process per store
  const file = join(dataDir, "idempotency.json");
  const keys = new Map<string, Stored>(existsSync(file) ? Object.entries(JSON.parse(readFileSync(file, "utf8")) as Record<string, Stored>) : []);
  const save = () => {
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(`${file}.tmp`, JSON.stringify(Object.fromEntries(keys)));
    renameSync(`${file}.tmp`, file);
  };
  const inFlightKeys = new Set<string>();
  const inFlightOrders = new Set<string>();

  /**
   * A refund once for each key of each agent. Shopify dedupes the mutation by `@idempotent`, so a retry with a key that
   * did not finish sends the same mutation with the same Shopify key. The checks and the in-flight marks run with no
   * await between them, so no second request gets in; that is the lock.
   */
  async function refundOnce(agent: string, key: string, body: any, receiptId: string): Promise<{ status: number; body: unknown }> {
    if (!/^(gid:\/\/shopify\/Order\/)?\d+$/.test(String(body?.order_id))) throw new Failure("order_id is the order's id", 400, true);
    if (!Number.isSafeInteger(body.amount) || body.amount <= 0) throw new Failure("amount is a whole number of minor units above 0", 400, true);
    if (body.reason !== undefined && (typeof body.reason !== "string" || body.reason.length > 200)) throw new Failure("reason is text of at most 200 characters", 400, true);
    const orderId = gid("Order", String(body.order_id));
    const fingerprint = sha256(`${orderId}|${body.amount}`);
    // the Shopify key: 64 hex characters, from the agent and its key, so one agent cannot read or block another's key
    const shopifyKey = sha256(`${agent}|${key}`);
    const seen = keys.get(shopifyKey);
    if (seen) {
      if (seen.fingerprint !== fingerprint) return { status: 422, body: { error: "this Idempotency-Key was used for another refund" } };
      if (seen.state === "done") return { status: seen.status, body: seen.body };
    }
    if (inFlightKeys.has(shopifyKey)) return { status: 409, body: { error: "a refund with this Idempotency-Key is in flight" } };
    if (inFlightOrders.has(orderId)) return { status: 409, body: { error: "a refund of this order is in flight" } };
    inFlightKeys.add(shopifyKey);
    inFlightOrders.add(orderId);
    try {
      const sale = await saleOf(orderId);
      const currency = sale.amountSet.presentmentMoney.currencyCode;
      keys.set(shopifyKey, { fingerprint, state: "pending" });
      save();
      let j: { data?: any; errors?: unknown };
      try {
        j = await graphql(
          `mutation($input: RefundInput!, $key: String!) @idempotent(key: $key) { refundCreate(input: $input) { refund { id } userErrors { message } } }`,
          { key: shopifyKey, input: { orderId, currency, note: `agent-custody receipt ${receiptId}${body.reason ? `: ${body.reason}` : ""}`, transactions: [{ orderId, parentId: sale.id, ...(sale.gateway ? { gateway: sale.gateway } : {}), kind: "REFUND", amount: toDecimal(body.amount, currency) }] } },
        );
      } catch (e) {
        if (e instanceof Failure && !e.definite) throw new Failure(e.message, 504, false);
        throw e;
      }
      const refundId = j.data?.refundCreate?.refund?.id as string | undefined;
      if (!refundId) {
        // no refund: a refusal is definite; any other answer may hide one, and the key stays for the retry
        userErrors(j.data?.refundCreate?.userErrors);
        if (j.errors) console.error(`agent-custody shopify: refundCreate errors: ${text(JSON.stringify(j.errors))}`);
        throw j.data ? new Failure("Shopify made no refund", 504, false) : new Failure("Shopify refused the query", 502, true);
      }
      const result = { refund_id: refundId, amount: body.amount as number, currency };
      keys.set(shopifyKey, { fingerprint, state: "done", status: 201, body: result });
      save();
      return { status: 201, body: result };
    } catch (e) {
      if (e instanceof Failure && e.definite && keys.get(shopifyKey)?.state === "pending") {
        keys.delete(shopifyKey);
        save();
      }
      throw e;
    } finally {
      inFlightKeys.delete(shopifyKey);
      inFlightOrders.delete(orderId);
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
    const agent = verifiedAgent(req);
    if (!agent) return json(res, 400, { error: "a refund needs one signature that names the agent's key" });
    const r = await refundOnce(agent, key, body, receiptId);
    json(res, r.status, r.body);
  }

  return createServer((req, res) => {
    guard(req, res, (err) => {
      if (err) return json(res, 500, { error: "the door failed" });
      handle(req, res).catch((e: unknown) => {
        if (res.headersSent) return res.destroy();
        if (e instanceof Failure) return json(res, e.status, e.status === 504 ? { error: e.message, outcome_unknown: true, retry: "same Idempotency-Key" } : { error: e.message });
        console.error(`agent-custody shopify: ${text(e)}`);
        json(res, 502, { error: "the app failed" });
      });
    });
  });
}
