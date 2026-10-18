// A REST API behind the gateway gets exactly what an MCP upstream gets: scope, policy on facts the gateway fetched
// itself, pre-commit, and a receipt per call. The agent never holds the API's credentials.
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY, type Gateway } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { buildRequest, restUpstream } from "../src/rest.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture, type Fixture } from "../scripts/fixture.ts";
import { OPERATION_META_KEY } from "../src/operations.ts";

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

/** A stand-in for a payments API: a customer lookup, a refund that needs a bearer token, and a 402 for one customer. */
function fakeApi(): Promise<{ server: Server; url: string; seen: { method: string; path: string; auth: string | undefined; body: string }[] }> {
  const seen: { method: string; path: string; auth: string | undefined; body: string }[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method!, path: req.url!, auth: req.headers.authorization, body });
      const send = (status: number, v: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(v));
      };
      const m = /^\/v1\/customers\/([^/?]+)/.exec(req.url!);
      if (req.method === "GET" && m) return send(200, { id: decodeURIComponent(m[1]!), verified: m[1] !== "cust_bad", plan: "pro" });
      if (req.method === "POST" && req.url === "/v1/refunds") {
        if (req.headers.authorization !== "Bearer sk_test_777") return send(401, { error: "no key" });
        const b = JSON.parse(body) as { customer_id: string; amount: number };
        if (b.customer_id === "cust_broke") return send(402, { error: "insufficient funds" });
        return send(200, { refund_id: "re_1", customer_id: b.customer_id, amount: b.amount, status: "succeeded" });
      }
      send(404, { error: "no such route" });
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, seen })));
}

describe("buildRequest", () => {
  const tool = { name: "t", method: "GET" as const, path: "/v1/customers/{id}/orders", body: "json" as const, inputSchema: { type: "object" } };
  it("substitutes path parameters, sends the rest as query on GET and as a JSON body otherwise, and refuses a missing path argument", () => {
    const g = buildRequest("https://api.example.com/", tool, { id: "cust 1", limit: 5 });
    expect(g.url.toString()).toBe("https://api.example.com/v1/customers/cust%201/orders?limit=5");
    expect(g.body).toBeNull();
    const p = buildRequest("https://api.example.com", { ...tool, method: "POST", path: "/v1/refunds" }, { customer_id: "c", amount: 5 });
    expect(p.url.pathname).toBe("/v1/refunds");
    expect(JSON.parse(p.body!)).toEqual({ customer_id: "c", amount: 5 });
    const q = buildRequest("https://api.example.com", { ...tool, method: "POST", path: "/v1/search", query: ["q"] }, { q: "x", page: 2 });
    expect(q.url.search).toBe("?q=x");
    expect(JSON.parse(q.body!)).toEqual({ page: 2 });
    expect(() => buildRequest("https://api.example.com", tool, { limit: 5 })).toThrow(/needs argument "id"/);
  });
});

describe("REST durable operation keys", () => {
  const tool = { name: "payments.transfer", method: "POST" as const, path: "/transfers", body: "json" as const, inputSchema: {}, idempotencyHeader: "Idempotency-Key" };
  const operation = { id: "39f5d833-a34d-4aae-897a-148f3cbcd648", idempotencyKey: "a".repeat(64) };

  it("sets the durable key after case-insensitive static and environment headers, without putting metadata in the body", async () => {
    const seen: RequestInit[] = [];
    const client = restUpstream("payments", {
      baseUrl: "https://payments.example", timeoutMs: 1000,
      headers: { "IDEMPOTENCY-KEY": "static" }, headerEnv: { "Idempotency-Key": "OPERATION_HEADER" }, tools: [tool],
    }, { env: { OPERATION_HEADER: "environment" }, fetch: (async (_url, init) => { seen.push(init!); return new Response('{"status":"pending"}'); }) as typeof fetch });
    await client.callTool({ name: tool.name, arguments: { amount: 50, currency: "USD" }, _meta: { [OPERATION_META_KEY]: operation, unrelated: "metadata" } });
    expect(new Headers(seen[0]!.headers).get("idempotency-key")).toBe(operation.idempotencyKey);
    expect(JSON.parse(seen[0]!.body as string)).toEqual({ amount: 50, currency: "USD" });
    expect(seen[0]!.signal).toBeInstanceOf(AbortSignal);
  });

  it("refuses missing and malformed operation keys before making a request", async () => {
    let calls = 0;
    const client = restUpstream("payments", { baseUrl: "https://payments.example", timeoutMs: 1000, tools: [tool] }, { fetch: (async () => { calls++; return new Response("{}"); }) as typeof fetch });
    for (const value of [undefined, {}, { ...operation, id: "not-a-uuid" }, { ...operation, idempotencyKey: "caller-controlled" }, { ...operation, idempotencyKey: "a".repeat(64) + "\r\nother: value" }]) {
      await expect(client.callTool({ name: tool.name, _meta: { [OPERATION_META_KEY]: value } })).rejects.toThrow(/operation metadata/);
    }
    expect(calls).toBe(0);
  });

  it("adds no operation header to a tool without a configured idempotency header", async () => {
    let headers: Headers | undefined;
    const client = restUpstream("payments", { baseUrl: "https://payments.example", timeoutMs: 1000, tools: [{ ...tool, idempotencyHeader: undefined }] }, { fetch: (async (_url, init) => { headers = new Headers(init!.headers); return new Response("{}"); }) as typeof fetch });
    await client.callTool({ name: tool.name, _meta: { [OPERATION_META_KEY]: operation } });
    expect(headers?.has("idempotency-key")).toBe(false);
  });
});

describe("REST upstream behind the gateway", () => {
  let api: Awaited<ReturnType<typeof fakeApi>>;
  let fx: Fixture;
  let gw: Gateway;
  beforeAll(async () => {
    api = await fakeApi();
    process.env.TEST_PAYMENTS_BEARER = "Bearer sk_test_777";
    fx = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-rest-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.upstream = {
      rest: {
        baseUrl: api.url,
        headerEnv: { authorization: "TEST_PAYMENTS_BEARER" },
        tools: [
          { name: "customer.lookup", method: "GET", path: "/v1/customers/{customer_id}", inputSchema: { type: "object", properties: { customer_id: { type: "string" } }, required: ["customer_id"] } },
          { name: "stripe.refund", method: "POST", path: "/v1/refunds", description: "Refund a customer", inputSchema: { type: "object", properties: { customer_id: { type: "string" }, amount: { type: "integer" } }, required: ["customer_id", "amount"] } },
        ],
      },
    };
    cfg.precommit = ["stripe.refund"];
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    gw = await createGateway(loadConfig(fx.configFile));
  }, 30_000);
  afterAll(async () => {
    await gw?.close();
    api.server.close();
  });

  it("advertises the declared tools within scope, and a missing header variable fails at startup", async () => {
    expect((await gw.listTools()).map((t) => t.name)).toEqual(["customer.lookup", "stripe.refund"]);
    expect(() => restUpstream("x", { baseUrl: api.url, headerEnv: { authorization: "NOT_SET_ANYWHERE_REST" }, timeoutMs: 1000, tools: [{ name: "t", method: "GET", path: "/", body: "json", inputSchema: {} }] })).toThrow(/NOT_SET_ANYWHERE_REST/);
  });

  it("a refund goes out with the API's own credentials, after a lookup the gateway made itself and a committed authorization, and the receipt verifies", async () => {
    const before = api.seen.length;
    const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
    expect(res.isError).toBeFalsy();
    expect(JSON.parse((res.content[0] as { text: string }).text)).toMatchObject({ refund_id: "re_1", status: "succeeded" });
    const calls = api.seen.slice(before);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /v1/customers/cust_123", "POST /v1/refunds"]);
    expect(calls[1]!.auth).toBe("Bearer sk_test_777");
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(res._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
    const p = decode(bundle).predicate;
    expect(p.facts.customer?.value).toMatchObject({ verified: true });
    expect(p.execution.status).toBe("executed");
    expect(p.authorization).toBeDefined();
    const r = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
    expect(r.checks.filter((c) => !c.ok)).toEqual([]);
  });

  it("policy denies on the gateway's own lookup before any request reaches the API", async () => {
    const before = api.seen.length;
    const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_bad", amount: 2500 } });
    expect(res.isError).toBe(true);
    expect((res.content[0] as { text: string }).text).toMatch(/Denied by policy/);
    expect(api.seen.slice(before).map((c) => `${c.method} ${c.path}`)).toEqual(["GET /v1/customers/cust_bad"]);
  });

  it("an API error is a failed execution with the API's answer in the receipt", async () => {
    const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_broke", amount: 100 } });
    expect(res.isError).toBe(true);
    expect(JSON.parse((res.content[0] as { text: string }).text)).toEqual({ error: "insufficient funds" });
    const p = decode(JSON.parse(readFileSync(join(fx.receiptsDir, `${String(res._meta?.[RECEIPT_META_KEY])}.json`), "utf8"))).predicate;
    expect(p.execution.status).toBe("failed");
  });
});
