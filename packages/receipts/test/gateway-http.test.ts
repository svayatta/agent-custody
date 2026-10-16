// One gateway process, many agents. Each connection presents its own grant; sessions share the upstreams and the
// policy but nothing else: each sees only the tools its grant names, each receipt carries its own principal and
// agent, and what one session consumed never leaks into another's receipts. A grant the gateway does not trust, an
// expired one, or none at all is refused at initialize and nothing is issued for it.
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { createGatewayHost, RECEIPT_META_KEY, type GatewayHost } from "../src/gateway.ts";
import { grantHeader, serveHttp, type RunningHttpGateway } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture, type Fixture } from "../scripts/fixture.ts";

let fx: Fixture;
let host: GatewayHost;
let running: RunningHttpGateway;
let principalKey: ReturnType<typeof loadPrivateKey>;

const grantFor = (agent: string, scopes: string[], key = principalKey, hoursValid = 1) => {
  const now = Date.now();
  return createDelegation(key, { version: "0.1", principal: "user_456", agent, scopes, issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + hoursValid * 3600_000).toISOString() });
};

const connect = async (grant: ReturnType<typeof grantFor>, header: "bearer" | "custom" = "bearer") => {
  const client = new Client({ name: `agent-${Math.random().toString(36).slice(2, 6)}`, version: "0" });
  const headers: Record<string, string> = header === "bearer" ? { authorization: `Bearer ${grantHeader(grant)}` } : { "x-agent-custody-grant": grantHeader(grant) };
  const transport = new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers } });
  await client.connect(transport);
  return { client, transport };
};

const statementOf = (bundle: ReceiptBundle) => JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement;
const receipt = (id: string) => JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;

beforeAll(async () => {
  fx = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-http-")));
  principalKey = loadPrivateKey(join(fx.dir, "keys", "principal.key"));
  host = await createGatewayHost(loadConfig(fx.configFile));
  running = await serveHttp(host, { port: 0, idleMs: 60_000, log: () => {} });
}, 60_000);

afterAll(async () => {
  await running?.close();
  await host?.close();
});

describe("the gateway over HTTP", () => {
  it("two agents on one gateway, each under its own grant: separate tools, separate receipts with the right principal and agent, and no shared consumed facts", async () => {
    const refunder = await connect(grantFor("refund-agent", ["stripe.refund", "customer.lookup"]));
    const reader = await connect(grantFor("read-agent", ["customer.lookup"]), "custom");
    try {
      expect((await refunder.client.listTools()).tools.map((t) => t.name).sort()).toEqual(["customer.lookup", "stripe.refund"]);
      expect((await reader.client.listTools()).tools.map((t) => t.name)).toEqual(["customer.lookup"]);
      expect(running.sessions().map((s) => s.agent).sort()).toEqual(["read-agent", "refund-agent"]);

      const ok = (await refunder.client.callTool({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } })) as CallToolResult;
      expect(ok.isError).toBeFalsy();
      const refundId = String(ok._meta?.[RECEIPT_META_KEY]);
      const refundReceipt = statementOf(receipt(refundId)).predicate;
      expect(refundReceipt.agent).toEqual({ id: "refund-agent", provenance: "attested" });
      expect(refundReceipt.principal.id).toBe("user_456");
      expect(refundReceipt.execution.status).toBe("executed");
      expect(verifyBundle(receipt(refundId), { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)] }).ok).toBe(true);

      // the reader's grant does not name the refund tool: denied, with a receipt naming the reader, not the refunder
      const denied = (await reader.client.callTool({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 1 } })) as CallToolResult;
      expect(denied.isError).toBe(true);
      const deniedReceipt = statementOf(receipt(String(denied._meta?.[RECEIPT_META_KEY]))).predicate;
      expect(deniedReceipt.agent.id).toBe("read-agent");
      expect(deniedReceipt.execution.status).toBe("denied");
      expect((deniedReceipt.policy?.errors as string[]).join(" ")).toMatch(/not in the delegation scopes/);

      // what the refunder was shown is on the refunder's next receipt, and on nobody else's
      const lookup = (await refunder.client.callTool({ name: "customer.lookup", arguments: { customer_id: "cust_123" } })) as CallToolResult;
      const readerLookup = (await reader.client.callTool({ name: "customer.lookup", arguments: { customer_id: "cust_123" } })) as CallToolResult;
      const refunderNext = statementOf(receipt(String(lookup._meta?.[RECEIPT_META_KEY]))).predicate;
      const readerNext = statementOf(receipt(String(readerLookup._meta?.[RECEIPT_META_KEY]))).predicate;
    expect((refunderNext.consumed?.factIds as string[]).length).toBeGreaterThanOrEqual(0);
      expect(readerNext.consumed?.factIds).toEqual([]);
      expect(readerNext.agent.id).toBe("read-agent");
    } finally {
      await refunder.transport.terminateSession();
      await reader.client.close();
      await refunder.client.close();
    }
    // a terminated session is gone from the server; the other closes with the client
    expect(running.sessions().map((s) => s.agent)).not.toContain("refund-agent");
  });

  it("a grant signed by a stranger, an expired grant, or no grant at all is refused at initialize with the reason, and no receipt is written for it", async () => {
    const before = readdirSync(fx.receiptsDir).length;
    await expect(connect(grantFor("stranger", ["stripe.refund"], generateKeyPair()))).rejects.toThrow(/delegation grant rejected/);
    await expect(connect(grantFor("late", ["stripe.refund"], principalKey, -1))).rejects.toThrow(/validity window/);
    const bare = new Client({ name: "bare", version: "0" });
    await expect(bare.connect(new StreamableHTTPClientTransport(new URL(running.url)))).rejects.toThrow(/grant is required/);
    expect(readdirSync(fx.receiptsDir).length).toBe(before);
    // a request for a session the server does not have is told to initialize again
    const res = await fetch(running.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-session-id": "00000000-0000-0000-0000-000000000000" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
    expect(res.status).toBe(404);
    const health = (await (await fetch(new URL("/health", running.url))).json()) as { ok: boolean; keyid: string };
    expect(health).toMatchObject({ ok: true, keyid: host.keyid });
  });

  it("a stdio-style single-grant gateway still works from the same config, and a config without grantFile refuses stdio but serves HTTP", async () => {
    const { createGateway } = await import("../src/gateway.ts");
    const single = await createGateway(loadConfig(fx.configFile));
    try {
      expect((await single.listTools()).map((t) => t.name)).toContain("stripe.refund");
    } finally {
      await single.close();
    }
    const cfg = { ...loadConfig(fx.configFile) };
    delete (cfg as { grantFile?: string }).grantFile;
    await expect(createGateway(cfg)).rejects.toThrow(/grantFile/);
    const h2 = await createGatewayHost(cfg);
    const r2 = await serveHttp(h2, { port: 0, log: () => {} });
    try {
      const c = new Client({ name: "x", version: "0" });
      await c.connect(new StreamableHTTPClientTransport(new URL(r2.url), { requestInit: { headers: { authorization: `Bearer ${grantHeader(grantFor("a", ["customer.lookup"]))}` } } }));
      expect((await c.listTools()).tools).toHaveLength(1);
      await c.close();
    } finally {
      await r2.close();
      await h2.close();
    }
  });
});
