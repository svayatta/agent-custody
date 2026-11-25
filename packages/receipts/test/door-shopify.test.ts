// The Shopify app's door (deploy/door/shopify). Its server runs the in-process door with the policy and the config that it
// ships, in front of two routes that call Shopify's Admin GraphQL API. Here Shopify is a stand-in on loopback that records
// every mutation it gets, so each test can say whether Shopify was called, and with what. No test uses the network.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
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
  /** while set, the stand-in holds each refundCreate until it is released */
  let hold: Promise<void> | undefined;
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
  let listed2: { key: KeyPair; id: string; passport: Envelope };
  let unlisted: { key: KeyPair; id: string; passport: Envelope };
  let bare: KeyPair;

  beforeAll(async () => {
    shopify = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        const call = JSON.parse(Buffer.concat(chunks).toString()) as Call;
        calls.push(call);
        if (hold && call.query.includes("refundCreate(")) await hold;
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
    listed2 = await register("agt_00000000000000c3");
    unlisted = await register("agt_00000000000000b2");
    bare = generateKeyPair();
    writeFileSync(join(dir, "admission.json"), JSON.stringify({ lists: { agents: [{ registry: REGISTRY, agentId: listed.id }, { registry: REGISTRY, agentId: listed2.id }, { agent: didKeyOf(bare.publicKey) }] } }));

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

  const keyOf = (who: { key: KeyPair }, header: string) => createHash("sha256").update(`${didKeyOf(who.key.publicKey)}|${header}`).digest("hex");
  const keysOnDisk = () => (existsSync(join(dir, "data", "idempotency.json")) ? JSON.parse(readFileSync(join(dir, "data", "idempotency.json"), "utf8")) : {});

  it("sends refundCreate with @idempotent and a key from the agent and its Idempotency-Key", async () => {
    const before = mutations("refundCreate").length;
    await send("/refunds", refund(100, "5001"), listed, { "idempotency-key": "derive-1" });
    const c = mutations("refundCreate")[before]!;
    expect(c.query).toContain("@idempotent(key: $key)");
    expect(c.variables.key).toBe(keyOf(listed, "derive-1"));
    expect(c.variables.key).toMatch(/^[0-9a-f]{64}$/);
  });

  it("makes one refund for a retry with the same Idempotency-Key, and answers it with the first answer", async () => {
    const before = mutations("refundCreate").length;
    const first = await send("/refunds", refund(700, "3001"), listed, { "idempotency-key": "retry-1" });
    const again = await send("/refunds", refund(700, "3001"), listed, { "idempotency-key": "retry-1" });
    expect([first.status, again.status]).toEqual([201, 201]);
    expect(again.body).toEqual(first.body);
    expect(mutations("refundCreate").length - before).toBe(1);
    // the same key for another amount, or for the order as a gid with another amount, is refused
    expect((await send("/refunds", refund(800, "3001"), listed, { "idempotency-key": "retry-1" })).status).toBe(422);
    // a gid and a number name one order: the retry is the same refund
    expect((await send("/refunds", refund(700, "gid://shopify/Order/3001"), listed, { "idempotency-key": "retry-1" })).status).toBe(201);
    expect(mutations("refundCreate").length - before).toBe(1);
  });

  it("refuses a refund without an Idempotency-Key", async () => {
    const before = calls.length;
    expect((await send("/refunds", refund(100), listed)).status).toBe(400);
    expect(calls.length).toBe(before);
  });

  it("keeps the keys of two agents apart: the same header makes two refunds with two Shopify keys", async () => {
    const before = mutations("refundCreate").length;
    const a = await send("/refunds", refund(300, "6001"), listed, { "idempotency-key": "shared" });
    const b = await send("/refunds", refund(300, "6001"), listed2, { "idempotency-key": "shared" });
    expect([a.status, b.status]).toEqual([201, 201]);
    expect(b.body.refund_id).not.toBe(a.body.refund_id);
    const made = mutations("refundCreate").slice(before);
    expect(made.map((c) => c.variables.key)).toEqual([keyOf(listed, "shared"), keyOf(listed2, "shared")]);
  });

  it("answers 504 with outcome_unknown when Shopify may have refunded, and a retry sends the same Shopify key, also after a restart", async () => {
    const before = mutations("refundCreate").length;
    next = (c) => (c.query.includes("refundCreate(") ? { status: 500, body: {} } : undefined);
    const lost = await send("/refunds", refund(250, "7001"), listed, { "idempotency-key": "lost-1" });
    expect(lost.status).toBe(504);
    expect(lost.body).toMatchObject({ outcome_unknown: true, retry: "same Idempotency-Key" });
    expect(keysOnDisk()[keyOf(listed, "lost-1")]).toMatchObject({ state: "pending" });
    const retry = await send("/refunds", refund(250, "7001"), listed, { "idempotency-key": "lost-1" });
    expect(retry.status).toBe(201);
    const made = mutations("refundCreate").slice(before);
    expect(made).toHaveLength(2);
    expect(made[1]!.variables.key).toBe(made[0]!.variables.key);
    // the receipt of the lost try says failed: the door maps a 5xx to failed
    expect((await receipt(lost.receipt)).predicate.execution).toMatchObject({ status: "failed", result: { status: 504 } });

    // a restart: a new server on the same data directory, with a key that is pending
    next = (c) => (c.query.includes("refundCreate(") ? { status: 200, body: { errors: [{ message: "boom" }] } } : undefined);
    const lost2 = await send("/refunds", refund(260, "7002"), listed, { "idempotency-key": "lost-2" });
    expect(lost2.status).toBe(502);
    next = (c) => (c.query.includes("refundCreate(") ? { status: 500, body: {} } : undefined);
    expect((await send("/refunds", refund(270, "7003"), listed, { "idempotency-key": "lost-3" })).status).toBe(504);
    const restarted = shopifyServer(guard, { SHOPIFY_SHOP: "x.myshopify.com", SHOPIFY_ADMIN_TOKEN: "t", SHOPIFY_BASE_URL: `http://127.0.0.1:${(shopify.address() as AddressInfo).port}` }, join(dir, "data"));
    await new Promise<void>((r) => restarted.listen(0, "127.0.0.1", r));
    const old = appUrl;
    appUrl = new URL(`http://127.0.0.1:${(restarted.address() as AddressInfo).port}`);
    const n0 = mutations("refundCreate").length;
    try {
      expect((await send("/refunds", refund(270, "7003"), listed, { "idempotency-key": "lost-3" })).status).toBe(201);
    } finally {
      appUrl = old;
      restarted.closeAllConnections();
      restarted.close();
    }
    expect(mutations("refundCreate").length - n0).toBe(1);
  });

  it("answers 409 to a second refund of an order, or with a key, while one is in flight", async () => {
    let release!: () => void;
    hold = new Promise<void>((r) => (release = r));
    const first = send("/refunds", refund(100, "8001"), listed, { "idempotency-key": "flight-1" });
    for (let i = 0; i < 200 && !calls.some((c) => c.query.includes("refundCreate(") && c.variables.key === keyOf(listed, "flight-1")); i++) await new Promise((r) => setTimeout(r, 10));
    const sameOrder = await send("/refunds", refund(50, "8001"), listed2, { "idempotency-key": "flight-2" });
    const sameKey = await send("/refunds", refund(100, "8001"), listed, { "idempotency-key": "flight-1" });
    const elsewhere = send("/refunds", refund(50, "8002"), listed2, { "idempotency-key": "flight-3" });
    release();
    hold = undefined;
    expect([sameOrder.status, sameKey.status]).toEqual([409, 409]);
    expect((await first).status).toBe(201);
    expect((await elsewhere).status).toBe(201);
    expect(mutations("refundCreate").filter((c) => c.variables.key === keyOf(listed2, "flight-2"))).toHaveLength(0);
  });

  it("leaves no pending key when the order lookup fails", async () => {
    const keysBefore = Object.keys(keysOnDisk()).length;
    next = (c) => (c.query.includes("order(") ? { status: 500, body: {} } : undefined);
    const r = await send("/refunds", refund(100, "9001"), listed, { "idempotency-key": "lookup-1" });
    expect(r.status).toBe(502);
    expect(Object.keys(keysOnDisk())).toHaveLength(keysBefore);
    expect(keysOnDisk()[keyOf(listed, "lookup-1")]).toBeUndefined();
  });

  it("counts a refund that Shopify made as done, also when the answer has errors or userErrors beside it", async () => {
    next = (c) => (c.query.includes("refundCreate(") ? { status: 200, body: { data: { refundCreate: { refund: { id: "gid://shopify/Refund/77" }, userErrors: [{ message: "note too long" }] } }, errors: [{ message: "partial" }] } } : undefined);
    const r = await send("/refunds", refund(120, "9101"), listed, { "idempotency-key": "partial-1" });
    expect(r.status).toBe(201);
    expect(r.body.refund_id).toBe("gid://shopify/Refund/77");
    expect(keysOnDisk()[keyOf(listed, "partial-1")]).toMatchObject({ state: "done" });
  });

  it("sends no gateway when the transaction has none", async () => {
    next = (c) => (c.query.includes("order(") ? { status: 200, body: { data: { order: { transactions: [{ id: "gid://shopify/OrderTransaction/5", kind: "CAPTURE", status: "SUCCESS", gateway: null, amountSet: { presentmentMoney: { currencyCode: "USD" } } }] } } } } : undefined);
    const before = mutations("refundCreate").length;
    expect((await send("/refunds", refund(100, "9201"), listed, { "idempotency-key": "gw-1" })).status).toBe(201);
    const t = mutations("refundCreate")[before]!.variables.input.transactions[0];
    expect(t.parentId).toBe("gid://shopify/OrderTransaction/5");
    expect("gateway" in t).toBe(false);
  });

  it("shows the agent a Shopify error, and the receipt records it: userErrors is 422, a 500 answer is 502, and the detail of an app error stays in the log", async () => {
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
    expect((await send("/refunds", refund(900, "4001"), listed, { "idempotency-key": "err-1" })).status).toBe(422);
    expect((await send("/refunds", refund(900, "4001"), listed, { "idempotency-key": "err-1" })).status).toBe(201);
    expect(mutations("refundCreate").length - before).toBe(2);

    // an error in the app is a generic 502
    const broken = shopifyServer(guard, { SHOPIFY_SHOP: "x.myshopify.com", SHOPIFY_ADMIN_TOKEN: "t", SHOPIFY_BASE_URL: `http://127.0.0.1:${(shopify.address() as AddressInfo).port}` }, join(dir, "no", "such", "\0dir"));
    await new Promise<void>((r) => broken.listen(0, "127.0.0.1", r));
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const old = appUrl;
    appUrl = new URL(`http://127.0.0.1:${(broken.address() as AddressInfo).port}`);
    try {
      const r = await send("/refunds", refund(100, "4101"), listed, { "idempotency-key": "boom-1" });
      expect(r.status).toBe(502);
      expect(JSON.stringify(r.body)).not.toContain("\0");
      expect(r.body).toEqual({ error: "the app failed" });
      expect(spy).toHaveBeenCalled();
    } finally {
      spy.mockRestore();
      appUrl = old;
      broken.closeAllConnections();
      broken.close();
    }
  });

  it("keeps the buyer's email out of the order receipt, and the amount in the refund receipt", async () => {
    const o = await send("/orders", order, listed);
    expect(JSON.stringify((await receipt(o.receipt)).predicate)).not.toContain("buyer@example.com");
    const r = await send("/refunds", refund(1234, "9301"), listed, { "idempotency-key": "rcpt-1" });
    expect(JSON.stringify((await receipt(r.receipt)).predicate.request.args)).toContain("1234");
  });
});

describe("the Shopify access token", () => {
  it("is asked for form-encoded, cached, and dropped once on a 401", async () => {
    const seen: { url: string; type: string | undefined; body: string; auth?: string }[] = [];
    let issued = 0;
    let rejectOnce = true;
    const stand = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({ url: req.url!, type: req.headers["content-type"], body, auth: req.headers["x-shopify-access-token"] as string | undefined });
        if (req.url!.includes("oauth")) {
          res.writeHead(200, { "content-type": "application/json" });
          return void res.end(JSON.stringify({ access_token: `tok${++issued}`, scope: "write_draft_orders", expires_in: 86399 }));
        }
        if (rejectOnce) {
          rejectOnce = false;
          res.writeHead(401);
          return void res.end("{}");
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ data: { draftOrderCreate: { draftOrder: { id: "gid://shopify/DraftOrder/2", invoiceUrl: "u", totalPriceSet: { shopMoney: { amount: "1.00", currencyCode: "USD" } } }, userErrors: [] } } }));
      });
    });
    await new Promise<void>((r) => stand.listen(0, "127.0.0.1", r));
    const app2 = shopifyServer((_q, _s, go) => go(), { SHOPIFY_SHOP: "x.myshopify.com", SHOPIFY_CLIENT_ID: "cid", SHOPIFY_CLIENT_SECRET: "sec", SHOPIFY_BASE_URL: `http://127.0.0.1:${(stand.address() as AddressInfo).port}` }, mkdtempSync(join(tmpdir(), "agent-custody-shopify-token-")));
    await new Promise<void>((r) => app2.listen(0, "127.0.0.1", r));
    const place = () => fetch(`http://127.0.0.1:${(app2.address() as AddressInfo).port}/orders`, { method: "POST", body: JSON.stringify({ lines: [{ variant_id: "1", quantity: 1 }], email: "b@example.com" }) });
    try {
      expect((await place()).status).toBe(201);
      expect((await place()).status).toBe(201);
    } finally {
      for (const s of [app2, stand]) { s.closeAllConnections(); s.close(); }
    }
    const tokens = seen.filter((c) => c.url.includes("oauth"));
    expect(tokens).toHaveLength(2);
    expect(tokens[0]!.type).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(tokens[0]!.body))).toEqual({ grant_type: "client_credentials", client_id: "cid", client_secret: "sec" });
    // tok1 was rejected and dropped; tok2 made the call, and the second order reused it
    expect(seen.filter((c) => !c.url.includes("oauth")).map((c) => c.auth)).toEqual(["tok1", "tok2", "tok2"]);
  });
});
