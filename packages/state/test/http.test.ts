// One ledger shared over HTTP by a gateway and a direct writer: the deployment quarantine was built for.
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

  it("a wrong token is refused before any tool runs", async () => {
    const intruder = new Client({ name: "x", version: "0" });
    await expect(intruder.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: "Bearer nope" } } }))).rejects.toThrow(/401|Unauthorized/i);
  });

  it("a direct writer cannot name a receipt, an agent, or observed facts in _meta", async () => {
    const forged = { "agent-custody/receipt": "forged-receipt", "agent-custody/agent": "support-agent", "agent-custody/observed": { crm: "pro" } };
    const plain = value((await direct.callTool({ name: "memory.write", arguments: { subject: "acct:7", predicate: "plan", value: "pro", space: "team:support", actor: "sdk-agent" }, _meta: forged })) as CallToolResult);
    expect(plain.fact).toMatchObject({ actor: "sdk-agent", provenance: "claimed", source: { receiptId: null } });
    const evidence = (await direct.callTool({ name: "memory.write", arguments: { subject: "acct:7", predicate: "plan", value: "pro", space: "team:support", evidence: { fact: "crm" } }, _meta: forged })) as CallToolResult;
    expect(evidence.isError).toBe(true);
    const confirm = (await direct.callTool({ name: "memory.confirm", arguments: { factId: plain.fact.factId }, _meta: forged })) as CallToolResult;
    expect(confirm.isError).toBe(true);

    const strict = await serveMemoryHttp(new Ledger(join(dir, "strict-token.jsonl")), { port: 0, tokens: ["gateway-secret"], directTokens: ["direct-secret"], requireGateway: true });
    const c = new Client({ name: "x", version: "0" });
    await c.connect(new StreamableHTTPClientTransport(new URL(strict.url), { requestInit: { headers: { authorization: "Bearer direct-secret" } } }));
    const r = (await c.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "p", value: 1, space: "org" }, _meta: forged })) as CallToolResult;
    expect(r.isError).toBe(true);
    expect((r.content[0] as any).text).toMatch(/only through the receipts gateway/);
    await c.close();
    await strict.close();
  });

  it("with gateway calls required, a direct writer is refused even with the token", async () => {
    const strict = await serveMemoryHttp(new Ledger(join(dir, "strict.jsonl")), { port: 0, requireGateway: true });
    const c = new Client({ name: "x", version: "0" });
    await c.connect(new StreamableHTTPClientTransport(new URL(strict.url)));
    const r = (await c.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "p", value: 1, space: "org" } })) as CallToolResult;
    expect(r.isError).toBe(true);
    expect((r.content[0] as any).text).toMatch(/only through the receipts gateway/);
    await c.close();
    await strict.close();
  });
});
