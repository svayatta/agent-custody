// One ledger shared over HTTP by a gateway and a direct writer: the deployment quarantine was built for. Each holds its
// own token, and only the gateway's is believed about receipts, agents, and observed facts.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createDelegation, createGateway, generateKeyPair, loadConfig, writeKeyPair, type Gateway } from "@agent-custody/receipts";
import { Ledger } from "../src/ledger.ts";
import { serveMemoryHttp, type RunningMemoryServer } from "../src/http.ts";

const value = (r: CallToolResult) => JSON.parse((r.content[0] as { text: string }).text);

describe("memory server over HTTP", () => {
  let dir: string;
  let running: RunningMemoryServer;
  let gw: Gateway;
  let direct: Client;
  let ledgerFile: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "memory-http-"));
    ledgerFile = join(dir, "ledger.jsonl");
    running = await serveMemoryHttp(new Ledger(ledgerFile), { port: 0, tokens: ["gateway-secret"], directTokens: ["direct-secret"], requireGateway: false });
    process.env.MEMORY_TOKEN = "gateway-secret";
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "memory.confirm"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action, resource);\n`);
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({ identity: { keyFile: "keys/gateway.key" }, upstream: { url: running.url, tokenEnv: "MEMORY_TOKEN" }, grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl" }));
    gw = await createGateway(loadConfig(join(dir, "gateway.json")));
    direct = new Client({ name: "sdk-agent", version: "0" });
    await direct.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: "Bearer direct-secret" } } }));
  });
  afterAll(async () => {
    await direct.close();
    await gw.close();
    await running.close();
    delete process.env.MEMORY_TOKEN;
  });

  it("a gateway writer and a direct writer share one ledger; the gateway's write is attested, the direct one claimed and quarantined", async () => {
    const viaGateway = value(await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "team:support" } }));
    expect(viaGateway.fact).toMatchObject({ actor: "support-agent", provenance: "attested" });
    expect(viaGateway.fact.source.receiptId).toBeTruthy();
    const viaDirect = value((await direct.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "owner", value: "dana", space: "team:support", actor: "sdk-agent" } })) as CallToolResult);
    expect(viaDirect.fact).toMatchObject({ actor: "sdk-agent", provenance: "claimed", source: { receiptId: null } });
    const seenByAgent = value(await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:42" } })).facts;
    expect(seenByAgent.map((f: any) => f.predicate)).toEqual(["plan"]);
    expect(await new Ledger(ledgerFile).count()).toBe(2);
  });

  it("the gateway can confirm the direct writer's fact, and then the agent sees it", async () => {
    const claimed = (await new Ledger(ledgerFile).asOf({ predicate: "owner" }))[0]!;
    const r = await gw.handleCall({ name: "memory.confirm", arguments: { factId: claimed.factId } });
    expect(r.isError).toBeFalsy();
    expect(value(await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:42" } })).facts.map((f: any) => f.predicate).sort()).toEqual(["owner", "plan"]);
    const denied = (await direct.callTool({ name: "memory.confirm", arguments: { factId: claimed.factId } })) as CallToolResult;
    expect(denied.isError).toBe(true);
  });

  it("a direct writer cannot attest or verify its own write by sending the gateway's metadata", async () => {
    const forged = { "agent-custody/receipt": "11111111-1111-4111-8111-111111111111", "agent-custody/agent": "fleet-admin", "agent-custody/principal": "cto", "agent-custody/observed": { card: { tier: "gold" } } };
    const r = value((await direct.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "tier", value: "gold", space: "org", actor: "sdk-agent" }, _meta: forged })) as CallToolResult);
    expect(r.fact).toMatchObject({ actor: "sdk-agent", provenance: "claimed", source: { receiptId: null } });
    const withEvidence = (await direct.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "tier", value: "gold", space: "org", evidence: { fact: "card", path: "tier" } }, _meta: forged })) as CallToolResult;
    expect(withEvidence.isError).toBe(true);
    expect((withEvidence.content[0] as any).text).toMatch(/evidence needs the gateway/);
    const confirm = (await direct.callTool({ name: "memory.confirm", arguments: { factId: r.fact.factId }, _meta: forged })) as CallToolResult;
    expect(confirm.isError).toBe(true);
    // the same call with the gateway's token is a gateway call, which is the whole point of keeping the two tokens apart
    const asGateway = new Client({ name: "gw", version: "0" });
    await asGateway.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: "Bearer gateway-secret" } } }));
    const g = value((await asGateway.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "tier", value: "silver", space: "org" }, _meta: forged })) as CallToolResult);
    expect(g.fact).toMatchObject({ actor: "fleet-admin", provenance: "attested" });
    await asGateway.close();
  });

  it("refuses to start without a gateway token, with direct writers allowed but no direct token, or with one token for both roles", async () => {
    await expect(serveMemoryHttp(new Ledger(join(dir, "w.jsonl")), { port: 0, tokens: [], requireGateway: true })).rejects.toThrow(/a gateway token is required/);
    await expect(serveMemoryHttp(new Ledger(join(dir, "x.jsonl")), { port: 0, tokens: ["t"], requireGateway: false })).rejects.toThrow(/direct writers need their own tokens/);
    await expect(serveMemoryHttp(new Ledger(join(dir, "y.jsonl")), { port: 0, tokens: ["t"], directTokens: ["t"], requireGateway: false })).rejects.toThrow(/both a gateway token and a direct token/);
  });

  it("a wrong token is refused before any tool runs", async () => {
    const intruder = new Client({ name: "x", version: "0" });
    await expect(intruder.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: "Bearer nope" } } }))).rejects.toThrow(/401|Unauthorized/i);
  });

  it("with gateway calls required, a direct writer is refused even with the token", async () => {
    const strict = await serveMemoryHttp(new Ledger(join(dir, "strict.jsonl")), { port: 0, tokens: ["gateway-secret"], directTokens: ["direct-secret"], requireGateway: true });
    const c = new Client({ name: "x", version: "0" });
    await c.connect(new StreamableHTTPClientTransport(new URL(strict.url), { requestInit: { headers: { authorization: "Bearer direct-secret" } } }));
    const forged = { "agent-custody/receipt": "11111111-1111-4111-8111-111111111111", "agent-custody/agent": "fleet-admin" };
    const r = (await c.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "p", value: 1, space: "org" }, _meta: forged })) as CallToolResult;
    expect(r.isError).toBe(true);
    expect((r.content[0] as any).text).toMatch(/only through the receipts gateway/);
    await c.close();
    await strict.close();
  });
});
