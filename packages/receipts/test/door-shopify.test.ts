// The Shopify app's door (deploy/door/shopify). Its server runs the in-process door with the policy and the config that it
// ships, in front of two routes that call Shopify's Admin GraphQL API. Here Shopify is a stand-in on loopback that records
// every mutation it gets, so each test can say whether Shopify was called, and with what. No test uses the network.
import { mkdirSync, mkdtempSync, copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair, loadPublicKey, writeKeyPair, type Envelope, type KeyPair } from "../src/crypto.ts";
import { didKeyOf } from "../src/did-key.ts";
import { door, type InProcessDoor } from "../src/door-app.ts";
import { RECEIPT_HEADER } from "../src/door.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { issuePassport, type AgentEntry } from "../src/registry.ts";
import { localSigner } from "../src/signer.ts";
import { verifyBundle } from "../src/verify.ts";
import { agentHeaders } from "../scripts/door-fixture.ts";
import { toDecimal, shopifyServer } from "../../../deploy/door/shopify/server.ts";

const shipped = resolve(import.meta.dirname, "..", "..", "..", "deploy", "door", "shopify");
const AUTHORITY = "agents.shop.test";
const REGISTRY = "https://registry.example.test/";
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

interface Call { query: string; variables: any }
type Answer = { status: number; body: unknown };

describe("the Shopify door", () => {
  let shopify: Server;
  let app: Server;
  let guard: InProcessDoor;
  let appUrl: URL;
  let dir: string;
  let doorPub: string;
  let n = 0;
  const calls: Call[] = [];
  /** what the stand-in answers to the next call that this returns an answer for; the default is success */
  let next: ((c: Call) => Answer | undefined) | undefined;
  const mutations = (name: string) => calls.filter((c) => c.query.includes(`${name}(`));
  const currencyOf: Record<string, string> = {};

  const registryKey = generateKeyPair();
  const signer = localSigner(registryKey);
  const register = async (id: string) => {
    const key = generateKeyPair();
    const entry: AgentEntry = { id, owner: "carted", name: `agent ${id}`, contact: "agents@carted.example", capabilities: ["orders"], agent: didKeyOf(key.publicKey), createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(), revokedAt: null };
    return { key, id, passport: await issuePassport(signer, REGISTRY, entry, 3600) };
  };
  let listed: { key: KeyPair; id: string; passport: Envelope };
  let unlisted: { key: KeyPair; id: string; passport: Envelope };
  let bare: KeyPair;

  beforeAll(async () => {
    shopify = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const call = JSON.parse(Buffer.concat(chunks).toString()) as Call;
        calls.push(call);
        const scripted = next?.(call);
        if (scripted) next = undefined;
        const answer: Answer = scripted ?? defaultAnswer(call);
        res.writeHead(answer.status, { "content-type": "application/json" });
        res.end(JSON.stringify(answer.body));
      });
    });
    const defaultAnswer = (c: Call): Answer => {
      if (c.query.includes("draftOrderCreate(")) return { status: 200, body: { data: { draftOrderCreate: { draftOrder: { id: "gid://shopify/DraftOrder/1", invoiceUrl: "https://shop.test/invoices/1", totalPriceSet: { shopMoney: { amount: "39.98", currencyCode: "USD" } } }, userErrors: [] } } } };
      if (c.query.includes("order(")) return { status: 200, body: { data: { order: { transactions: [{ id: "gid://shopify/OrderTransaction/9", kind: "SALE", status: "SUCCESS", gateway: "bogus", amountSet: { presentmentMoney: { currencyCode: currencyOf[c.variables.id] ?? "USD" } } }] } } } };
      return { status: 200, body: { data: { refundCreate: { refund: { id: `gid://shopify/Refund/${calls.length}` }, userErrors: [] } } } };
    };
    await new Promise<void>((r) => shopify.listen(0, "127.0.0.1", r));

    dir = mkdtempSync(join(tmpdir(), "agent-custody-shopify-"));
    mkdirSync(join(dir, "keys"));
    doorPub = writeKeyPair(generateKeyPair(), join(dir, "data", "keys"), "door").pubFile;
    writeKeyPair(registryKey, join(dir, "keys"), "registry");
    copyFileSync(join(shipped, "policy.cedar"), join(dir, "policy.cedar"));
    const config = JSON.parse(readFileSync(join(shipped, "door.json"), "utf8"));
    config.webBotAuth.authorities = [AUTHORITY];
    writeFileSync(join(dir, "door.json"), JSON.stringify(config));
    listed = await register("agt_00000000000000a1");
    unlisted = await register("agt_00000000000000b2");
    bare = generateKeyPair();
    writeFileSync(join(dir, "admission.json"), JSON.stringify({ lists: { agents: [{ registry: REGISTRY, agentId: listed.id }, { agent: didKeyOf(bare.publicKey) }] } }));

    guard = door(join(dir, "door.json"), { autoFlush: false });
    app = shopifyServer(guard, { SHOPIFY_SHOP: "x.myshopify.com", SHOPIFY_ADMIN_TOKEN: "shpat_test", SHOPIFY_BASE_URL: `http://127.0.0.1:${(shopify.address() as AddressInfo).port}` }, join(dir, "data"));
    await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
    appUrl = new URL(`http://127.0.0.1:${(app.address() as AddressInfo).port}`);
  });
  afterAll(async () => {
    guard?.close();
    for (const s of [app, shopify]) await new Promise<void>((r) => { s?.closeAllConnections?.(); s ? s.close(() => r()) : r(); });
  });

  const send = (path: string, payload: unknown, who: { key: KeyPair; passport?: Envelope }, extra: Record<string, string> = {}) => new Promise<{ status: number; body: any; receipt: string }>((resolveSend, reject) => {
    const body = JSON.stringify(payload);
    const req = httpRequest({ host: appUrl.hostname, port: appUrl.port, method: "POST", path, headers: { host: AUTHORITY, "content-type": "application/json", ...agentHeaders(who.key, { method: "POST", target: path, authority: AUTHORITY, body, ...(who.passport ? { passport: who.passport } : {}), nonce: `shopify-${process.pid}-${++n}` }), ...extra } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolveSend({ status: res.statusCode!, body: JSON.parse(Buffer.concat(chunks).toString() || "null"), receipt: String(res.headers[RECEIPT_HEADER]) }));
    });
    req.on("error", reject);
    req.end(body);
  });
  /** the receipt of an answer is written after the app has answered, so wait for the file */
  const receipt = async (id: string) => {
    const file = join(dir, "data", "receipts", `${id}.json`);
    for (let i = 0; i < 300 && !existsSync(file); i++) await new Promise((r) => setTimeout(r, 10));
    const bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
    const result = verifyBundle(bundle, { issuerKeys: [loadPublicKey(doorPub)], principalKeys: [], logFile: join(dir, "data", "log.jsonl") });
    return { predicate: decode(bundle).predicate, failed: result.checks.filter((c) => !c.ok), ok: result.ok };
  };
  const order = { lines: [{ variant_id: "4411", quantity: 2 }], email: "buyer@example.com" };
  const refund = (amount: number, orderId = "1001") => ({ order_id: orderId, amount, reason: "late" });

  it("admits an agent with a passport that is on the list: one draft order that points to the receipt, and a receipt that verifies", async () => {
    const before = mutations("draftOrderCreate").length;
    const r = await send("/orders", order, listed);
    expect(r.status).toBe(201);
    expect(r.body).toEqual({ draft_order_id: "gid://shopify/DraftOrder/1", total: { amount: 3998, currency: "USD" }, invoice_url: "https://shop.test/invoices/1" });
    const made = mutations("draftOrderCreate").slice(before);
    expect(made).toHaveLength(1);
    expect(made[0]!.variables.input).toMatchObject({ email: "buyer@example.com", tags: ["agent-custody"], note: `agent-custody receipt ${r.receipt}`, lineItems: [{ variantId: "gid://shopify/ProductVariant/4411", quantity: 2 }] });
    expect(mutations("draftOrderCreate").some((c) => JSON.stringify(c.variables).includes("completed"))).toBe(false);
    const rc = await receipt(r.receipt);
    expect(rc.failed).toEqual([]);
    expect(rc.ok).toBe(true);
    expect(rc.predicate.policy?.decision).toBe("allow");
    expect(rc.predicate.execution.status).toBe("executed");
  });

  it("refuses an agent with a signature and no passport (even one that the list names by its key), and an agent with a passport that is not on the list, and calls Shopify for neither", async () => {
    const before = calls.length;
    for (const who of [{ key: bare }, unlisted]) {
      const r = await send("/orders", order, who);
      expect(r.status).toBe(403);
      const rc = await receipt(r.receipt);
      expect(rc.ok).toBe(true);
      expect(rc.predicate.policy?.decision).toBe("deny");
    }
    expect(calls.length).toBe(before);
  });

  it("refuses a refund over the limit and a refund of nothing, and calls Shopify for neither", async () => {
    const before = calls.length;
    for (const amount of [50001, 0, -5]) expect((await send("/refunds", refund(amount), listed, { "idempotency-key": `over-${amount}` })).status).toBe(403);
    expect(calls.length).toBe(before);
  });

  it("refunds within the limit with the decimal of the currency: USD has two places, JPY has none", async () => {
    currencyOf["gid://shopify/Order/2001"] = "USD";
    currencyOf["gid://shopify/Order/2002"] = "JPY";
    const before = mutations("refundCreate").length;
    const usd = await send("/refunds", refund(1999, "2001"), listed, { "idempotency-key": "usd-1" });
    const jpy = await send("/refunds", refund(500, "2002"), listed, { "idempotency-key": "jpy-1" });
    expect([usd.status, jpy.status]).toEqual([201, 201]);
    const made = mutations("refundCreate").slice(before).map((c) => c.variables.input);
    expect(made).toHaveLength(2);
    expect(made[0]).toMatchObject({ orderId: "gid://shopify/Order/2001", currency: "USD", transactions: [{ kind: "REFUND", amount: "19.99", parentId: "gid://shopify/OrderTransaction/9", gateway: "bogus" }] });
    expect(made[1]).toMatchObject({ currency: "JPY", transactions: [{ kind: "REFUND", amount: "500" }] });
    expect(made[0].note).toContain(usd.receipt);
    expect((await receipt(usd.receipt)).failed).toEqual([]);
    expect(toDecimal(5, "USD")).toBe("0.05");
    expect(toDecimal(1234, "KWD")).toBe("1.234");
  });

  it("makes one refund for a retry with the same Idempotency-Key, and answers the retry with the first answer", async () => {
    const before = mutations("refundCreate").length;
    const first = await send("/refunds", refund(700, "3001"), listed, { "idempotency-key": "retry-1" });
    const again = await send("/refunds", refund(700, "3001"), listed, { "idempotency-key": "retry-1" });
    expect(first.status).toBe(201);
    expect(again.status).toBe(201);
    expect(again.body).toEqual(first.body);
    expect(mutations("refundCreate").length - before).toBe(1);
    // the same key for another refund is refused, and the record is on disk
    expect((await send("/refunds", refund(800, "3001"), listed, { "idempotency-key": "retry-1" })).status).toBe(422);
    expect(JSON.parse(readFileSync(join(dir, "data", "idempotency.json"), "utf8"))["retry-1"]).toMatchObject({ state: "done" });
    expect(mutations("refundCreate").length - before).toBe(1);
  });

  it("refuses a refund without an Idempotency-Key, and answers 409 to a retry while the first try is pending", async () => {
    const before = calls.length;
    expect((await send("/refunds", refund(100), listed)).status).toBe(400);
    expect(calls.length).toBe(before);
    // Shopify answers the first try slowly: the second try arrives while the key is pending
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const slow = createServer((_req, res) => void held.then(() => { res.writeHead(500); res.end(); }));
    await new Promise<void>((r) => slow.listen(0, "127.0.0.1", r));
    const other = shopifyServer((_q, _s, nextFn) => nextFn(), { SHOPIFY_SHOP: "x.myshopify.com", SHOPIFY_ADMIN_TOKEN: "t", SHOPIFY_BASE_URL: `http://127.0.0.1:${(slow.address() as AddressInfo).port}` }, mkdtempSync(join(tmpdir(), "agent-custody-shopify-pending-")));
    await new Promise<void>((r) => other.listen(0, "127.0.0.1", r));
    const post = (key: string) => fetch(`http://127.0.0.1:${(other.address() as AddressInfo).port}/refunds`, { method: "POST", headers: { "idempotency-key": key }, body: JSON.stringify(refund(100)) });
    const first = post("k1");
    await new Promise((r) => setTimeout(r, 100));
    expect((await post("k1")).status).toBe(409);
    release();
    // a 500 may have acted: the key stays pending, so a later retry is 409 too
    expect((await first).status).toBe(502);
    expect((await post("k1")).status).toBe(409);
    for (const s of [other, slow]) { s.closeAllConnections(); s.close(); }
  });

  it("shows the agent a Shopify error, and the receipt records it: userErrors is 422, a 500 answer is 502", async () => {
    next = () => ({ status: 200, body: { data: { draftOrderCreate: { draftOrder: null, userErrors: [{ message: "Variant is not available" }] } } } });
    const refused = await send("/orders", order, listed);
    expect(refused.status).toBe(422);
    expect(refused.body.error).toContain("Variant is not available");
    const a = await receipt(refused.receipt);
    expect(a.ok).toBe(true);
    expect(a.predicate.execution).toMatchObject({ status: "executed", result: { status: 422 } });

    next = () => ({ status: 500, body: {} });
    const down = await send("/orders", order, listed);
    expect(down.status).toBe(502);
    const b = await receipt(down.receipt);
    expect(b.ok).toBe(true);
    expect(b.predicate.execution).toMatchObject({ status: "failed", result: { status: 502 } });

    // userErrors on a refund frees the key, since Shopify did nothing: the retry is made
    const before = mutations("refundCreate").length;
    next = (c) => (c.query.includes("refundCreate(") ? { status: 200, body: { data: { refundCreate: { refund: null, userErrors: [{ message: "Refund amount is too large" }] } } } } : undefined);
    const bad = await send("/refunds", refund(900, "4001"), listed, { "idempotency-key": "err-1" });
    expect(bad.status).toBe(422);
    const ok = await send("/refunds", refund(900, "4001"), listed, { "idempotency-key": "err-1" });
    expect(ok.status).toBe(201);
    expect(mutations("refundCreate").length - before).toBe(2);
  });
});
