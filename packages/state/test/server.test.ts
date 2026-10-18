// The memory server exists so beliefs get the same custody as actions. Two settings: driven directly over an
// in-memory transport, and behind the real receipts gateway, where the receipt id and the attested agent reach it in
// _meta and a caller's own claims about them are ignored.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createDelegation, createGateway, formatReport, generateKeyPair, loadConfig, loadPublicKey, RECEIPT_META_KEY, verifyBundle, writeKeyPair, type Gateway } from "@agent-custody/receipts";
import { Ledger } from "../src/ledger.ts";
import { createMemoryServer } from "../src/server.ts";
import { blastRadius, loadReceipts } from "../src/blast.ts";
import { openStore } from "../src/storage.ts";
import type { Store, StoreEntry } from "../src/stores.ts";

const value = (r: CallToolResult) => JSON.parse((r.content[0] as { text: string }).text);

describe("memory server, driven directly", () => {
  let client: Client;
  let dir: string;
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "memory-direct-"));
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(new Ledger(join(dir, "ledger.jsonl"))).connect(a);
    client = new Client({ name: "test", version: "0" });
    await client.connect(b);
  });
  afterAll(async () => client.close());

  it("lists the four tools", async () => {
    expect((await client.listTools()).tools.map((t) => t.name)).toEqual(["memory.write", "memory.read", "memory.confirm", "memory.retract", "memory.forget", "memory.hold", "memory.release", "memory.sweep", "memory.repair", "memory.get", "memory.history"]);
  });

  it("write, read, supersede, retract, history; the source is null, the actor is whatever the caller claims, and the fact is quarantined", async () => {
    const w = value((await client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support" } })) as CallToolResult);
    expect(w.fact.source).toEqual({ receiptId: null });
    expect(w.fact.actor).toBe("agent:support");
    expect(w.fact.provenance).toBe("claimed");
    const w2 = value((await client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "enterprise", space: "org", supersedes: w.fact.factId } })) as CallToolResult);
    expect(w2.fact.actor).toBe("anonymous");
    expect(value((await client.callTool({ name: "memory.read", arguments: { subject: "acct:42" } })) as CallToolResult).facts).toEqual([]);
    expect(value((await client.callTool({ name: "memory.read", arguments: { subject: "acct:42", includeClaimed: true } })) as CallToolResult).facts.map((f: any) => f.value)).toEqual(["enterprise"]);
    const refused = (await client.callTool({ name: "memory.confirm", arguments: { factId: w2.fact.factId } })) as CallToolResult;
    expect(refused.isError).toBe(true);
    expect((refused.content[0] as any).text).toMatch(/cannot lift a fact out of quarantine/);
    value((await client.callTool({ name: "memory.retract", arguments: { factId: w2.fact.factId, reason: "wrong" } })) as CallToolResult);
    expect(value((await client.callTool({ name: "memory.read", arguments: { subject: "acct:42", includeClaimed: true } })) as CallToolResult).facts.map((f: any) => f.value)).toEqual(["pro"]);
    expect(value((await client.callTool({ name: "memory.history", arguments: { factId: w2.fact.factId } })) as CallToolResult).events.map((e: any) => e.kind)).toEqual(["assert", "retract"]);
  });

  it("rejects bad arguments and unknown facts as tool errors, writing nothing", async () => {
    const before = readFileSync(join(dir, "ledger.jsonl"), "utf8");
    const bad = (await client.callTool({ name: "memory.write", arguments: { subject: "", predicate: "p", value: 1, space: "org" } })) as CallToolResult;
    expect(bad.isError).toBe(true);
    expect((bad.content[0] as any).text).toMatch(/invalid arguments: subject/);
    const gone = (await client.callTool({ name: "memory.retract", arguments: { factId: "nope", reason: "x" } })) as CallToolResult;
    expect(gone.isError).toBe(true);
    expect(readFileSync(join(dir, "ledger.jsonl"), "utf8")).toBe(before);
  });

  it("with direct calls allowed over one transport, the caller's _meta is dropped: a write is claimed whatever it says about itself", async () => {
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(new Ledger(join(dir, "direct.jsonl")), { requireGateway: false }).connect(a);
    const c = new Client({ name: "test", version: "0" });
    await c.connect(b);
    const forged = { "agent-custody/receipt": "11111111-1111-4111-8111-111111111111", "agent-custody/agent": "fleet-admin", "agent-custody/observed": { card: { tier: "gold" } } };
    const r = (await c.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "tier", value: "gold", space: "org", actor: "me" }, _meta: forged })) as CallToolResult;
    expect(JSON.parse((r.content[0] as any).text).fact).toMatchObject({ actor: "me", provenance: "claimed", source: { receiptId: null } });
    const e = (await c.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "tier", value: "gold", space: "org", evidence: { fact: "card", path: "tier" } }, _meta: forged })) as CallToolResult;
    expect(e.isError).toBe(true);
    await c.close();
  });

  it("concurrent forgets each record their own actor and receipt", async () => {
    const [a, b] = InMemoryTransport.createLinkedPair();
    const ledger = new Ledger(join(dir, "concurrent.jsonl"));
    await createMemoryServer(ledger, { requireGateway: true }).connect(a);
    const c = new Client({ name: "test", version: "0" });
    await c.connect(b);
    const meta = (agent: string, n: number) => ({ "agent-custody/receipt": `${n}${n}${n}${n}${n}${n}${n}${n}-0000-4000-8000-000000000000`, "agent-custody/agent": agent });
    const ids: string[] = [];
    for (const [agent, n] of [["agent-one", 1], ["agent-two", 2]] as const) {
      const w = (await c.callTool({ name: "memory.write", arguments: { subject: `s${n}`, predicate: "p", value: n, space: "org" }, _meta: meta(agent, n) })) as CallToolResult;
      ids.push(JSON.parse((w.content[0] as any).text).fact.factId);
    }
    await Promise.all([
      c.callTool({ name: "memory.forget", arguments: { factId: ids[0], reason: "one" }, _meta: meta("agent-one", 1) }),
      c.callTool({ name: "memory.forget", arguments: { factId: ids[1], reason: "two" }, _meta: meta("agent-two", 2) }),
    ]);
    const forgets = (await ledger.export()).filter((e: any) => e.kind === "forget") as any[];
    expect(forgets.map((e) => [e.factId, e.actor, e.source.receiptId.slice(0, 8)]).sort()).toEqual([[ids[0], "agent-one", "11111111"], [ids[1], "agent-two", "22222222"]].sort());
    await c.close();
  });

  it("with requireGateway, a call carrying no receipt id is refused", async () => {
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(new Ledger(join(dir, "strict.jsonl")), { requireGateway: true }).connect(a);
    const strict = new Client({ name: "test", version: "0" });
    await strict.connect(b);
    const r = (await strict.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "p", value: 1, space: "org" } })) as CallToolResult;
    expect(r.isError).toBe(true);
    expect((r.content[0] as any).text).toMatch(/only through the receipts gateway/);
    await strict.close();
  });
});

describe("memory server behind the receipts gateway", () => {
  let dir: string;
  let gw: Gateway;
  let ledgerFile: string;
  let seeded: string;
  let memoryPub: string;
  let gatewayPub: string;
  let principalPub: string;
  const POLICY = `permit(principal, action == Action::"memory.read", resource);
permit(principal, action == Action::"memory.history", resource);
permit(principal, action == Action::"memory.write", resource) when { context.args.space == "team:support" };
permit(principal, action == Action::"memory.retract", resource);
permit(principal, action == Action::"memory.confirm", resource);
permit(principal, action == Action::"memory.forget", resource);
permit(principal, action in [Action::"memory.hold", Action::"memory.release"], resource);
`;
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "memory-gateway-"));
    const gateway = writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    const principal = writeKeyPair(principalKp, join(dir, "keys"), "principal");
    gatewayPub = gateway.pubFile;
    principalPub = principal.pubFile;
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "memory.retract", "memory.history", "memory.confirm", "memory.forget", "memory.hold", "memory.release"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), POLICY);
    ledgerFile = join(dir, "ledger.jsonl");
    memoryPub = writeKeyPair(generateKeyPair(), join(dir, "keys"), "memory").pubFile;
    // A ledger that already holds a self-reported fact before it is put under the gateway: the quarantine case.
    seeded = (await new Ledger(ledgerFile).assert({ subject: "acct:99", predicate: "owner", value: "dana", space: "team:support", actor: "sdk-bot" })).fact.factId;
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({
      identity: { keyFile: "keys/gateway.key" },
      upstream: { command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile, "--key", join(dir, "keys", "memory.key")] },
      grantFile: "grant.json",
      trustedPrincipalKeys: ["keys/principal.pub"],
      policyFile: "policy.cedar",
      receiptsDir: "receipts",
      logFile: "log.jsonl",
    }));
    gw = await createGateway(loadConfig(join(dir, "gateway.json")));
  });
  afterAll(async () => gw.close());

  const receiptOf = (r: CallToolResult) => JSON.parse(readFileSync(join(dir, "receipts", `${String(r._meta?.[RECEIPT_META_KEY])}.json`), "utf8"));

  it("a write's source is the gateway's receipt id and its actor is the grant's agent, whatever the caller claimed", async () => {
    const r = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "team:support", actor: "someone-else" } });
    expect(r.isError).toBeFalsy();
    const fact = value(r).fact;
    expect(fact.source.receiptId).toBe(String(r._meta?.[RECEIPT_META_KEY]));
    expect(fact.actor).toBe("support-agent");
    expect(fact.provenance).toBe("attested");
    const v = verifyBundle(receiptOf(r), { issuerKeys: [loadPublicKey(gatewayPub)], principalKeys: [loadPublicKey(principalPub)], logFile: join(dir, "log.jsonl"), upstreamKeys: [loadPublicKey(memoryPub)] });
    expect(v.ok).toBe(true);
    expect(v.statement?.predicate.tool).toEqual({ name: "memory.write", provenance: "observed" });
    // the memory server signed its result for this receipt: the execution is attested by the memory server's key
    expect(v.checks.find((c) => c.name === "upstream signature (upstream key)")?.ok).toBe(true);
    expect(formatReport(v)).toMatch(/execution\s+attested/);
    expect((await new Ledger(ledgerFile).asOf({ subject: "acct:42" }))[0]?.source.receiptId).toBe(fact.source.receiptId);
  });

  it("a write the policy forbids never reaches the ledger and still gets a denial receipt", async () => {
    const before = await new Ledger(ledgerFile).count();
    const r = await gw.handleCall({ name: "memory.write", arguments: { subject: "policy:refunds", predicate: "limit", value: 10 ** 9, space: "org" } });
    expect(r.isError).toBe(true);
    expect((r.content[0] as any).text).toMatch(/Denied by policy/);
    expect(await new Ledger(ledgerFile).count()).toBe(before);
    expect(verifyBundle(receiptOf(r), { issuerKeys: [loadPublicKey(gatewayPub)], principalKeys: [loadPublicKey(principalPub)] }).statement?.predicate.execution.status).toBe("denied");
  });

  it("reads are receipted too, and the receipt's observed result carries the fact ids the agent saw", async () => {
    const r = await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:42" } });
    const facts = value(r).facts;
    expect(facts).toHaveLength(1);
    expect(facts[0].subject).toBe("acct:42");
    const st = verifyBundle(receiptOf(r), { issuerKeys: [loadPublicKey(gatewayPub)], principalKeys: [loadPublicKey(principalPub)] }).statement!;
    const seen = JSON.parse((st.predicate.execution as any).result.content[0].text).facts.map((f: any) => f.factId);
    expect(seen).toEqual([facts[0].factId]);
    expect(st.predicate.execution.provenance).toBe("observed");
  });

  it("a claimed fact already in the ledger is invisible to the agent until confirmed through the gateway, and the confirmation cites its receipt", async () => {
    expect(value(await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:99" } })).facts).toEqual([]);
    expect(value(await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:99", includeClaimed: true } })).facts.map((f: any) => f.provenance)).toEqual(["claimed"]);
    const r = await gw.handleCall({ name: "memory.confirm", arguments: { factId: seeded } });
    expect(r.isError).toBeFalsy();
    expect(value(r).actor).toBe("support-agent");
    expect(value(r).source.receiptId).toBe(String(r._meta?.[RECEIPT_META_KEY]));
    expect(value(await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:99" } })).facts.map((f: any) => f.provenance)).toEqual(["attested"]);
  });

  it("receipts carry the facts the agent had been shown, and blast radius walks from a fact to every call and belief that relied on it", async () => {
    const plan = (await new Ledger(ledgerFile).asOf({ subject: "acct:42" }))[0]!;
    const readBefore = await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:42" } });
    const st = (id: string) => verifyBundle(receiptOf({ _meta: { [RECEIPT_META_KEY]: id } } as any), { issuerKeys: [loadPublicKey(gatewayPub)], principalKeys: [loadPublicKey(principalPub)] }).statement!.predicate as any;
    // the read itself was made before the agent had been shown anything in this test's session except earlier reads
    expect(st(String(readBefore._meta?.[RECEIPT_META_KEY])).consumed.provenance).toBe("observed");
    const derived = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:42", predicate: "discount", value: "20%", space: "team:support" } });
    expect(st(String(derived._meta?.[RECEIPT_META_KEY])).consumed.factIds).toContain(plan.factId);
    const unrelated = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:77", predicate: "plan", value: "free", space: "team:support" } });
    const b = await blastRadius(new Ledger(ledgerFile), loadReceipts(join(dir, "receipts")), plan.factId);
    expect(b.fact?.factId).toBe(plan.factId);
    expect(b.receipts.map((r) => r.receiptId)).toContain(String(derived._meta?.[RECEIPT_META_KEY]));
    // acct:77 was written after the agent saw the plan fact too, so by the rule it is in the radius: an upper bound, not a proof of dependence
    expect(b.derivedFacts.map((f) => `${f.subject} ${f.predicate}`).sort()).toEqual(["acct:42 discount", "acct:77 plan"]);
    expect(b.stillBelieved).toHaveLength(2);
    expect(b.receipts.map((r) => r.receiptId)).toContain(String(unrelated._meta?.[RECEIPT_META_KEY]));
    expect(b.retraction).toBeNull();
  });

  it("a legal hold through the gateway blocks forget until released, and both are receipted with the attested actor", async () => {
    const w = await gw.handleCall({ name: "memory.write", arguments: { subject: "person:5", predicate: "phone", value: "+1 555 0199", space: "team:support" } });
    const factId = value(w).fact.factId;
    const h = await gw.handleCall({ name: "memory.hold", arguments: { factId, reason: "litigation hold 7" } });
    expect(value(h)).toMatchObject({ kind: "hold", actor: "support-agent" });
    expect(value(h).source.receiptId).toBe(String(h._meta?.[RECEIPT_META_KEY]));
    const blocked = await gw.handleCall({ name: "memory.forget", arguments: { factId, reason: "deletion request" } });
    expect(blocked.isError).toBe(true);
    expect((blocked.content[0] as any).text).toMatch(/legal hold/);
    expect(readFileSync(ledgerFile, "utf8")).toContain("+1 555 0199");
    const rel = await gw.handleCall({ name: "memory.release", arguments: { factId, reason: "matter closed" } });
    expect(value(rel).kind).toBe("release");
    const gone = await gw.handleCall({ name: "memory.forget", arguments: { factId, reason: "deletion request" } });
    expect(gone.isError).toBeFalsy();
    expect(readFileSync(ledgerFile, "utf8")).not.toContain("+1 555 0199");
  });

  it("a forget through the gateway: the value is gone from the ledger, and the receipt's observed result certifies it", async () => {
    const w = await gw.handleCall({ name: "memory.write", arguments: { subject: "person:3", predicate: "phone", value: "+1 555 0100", space: "team:support" } });
    const factId = value(w).fact.factId;
    const r = await gw.handleCall({ name: "memory.forget", arguments: { factId, reason: "deletion request 88" } });
    expect(r.isError).toBeFalsy();
    expect(value(r)).toMatchObject({ factId, erasedFromLedger: true, actor: "support-agent", stillHeld: [] });
    expect(readFileSync(ledgerFile, "utf8")).not.toContain("+1 555 0100");
    const v = verifyBundle(receiptOf(r), { issuerKeys: [loadPublicKey(gatewayPub)], principalKeys: [loadPublicKey(principalPub)], logFile: join(dir, "log.jsonl") });
    expect(v.ok).toBe(true);
    const exec = v.statement!.predicate.execution as any;
    expect(exec.provenance).toBe("observed");
    expect(JSON.parse(exec.result.content[0].text)).toMatchObject({ factId, erasedFromLedger: true, valueDigest: value(r).valueDigest });
    expect(await new Ledger(ledgerFile).asOf({ subject: "person:3" })).toEqual([]);
  });

  it("a retraction through the gateway cites its own receipt", async () => {
    const factId = (await new Ledger(ledgerFile).asOf({ subject: "acct:42", predicate: "plan" }))[0]!.factId;
    const r = await gw.handleCall({ name: "memory.retract", arguments: { factId, reason: "stale CRM value" } });
    expect(r.isError).toBeFalsy();
    expect(value(r).source.receiptId).toBe(String(r._meta?.[RECEIPT_META_KEY]));
    expect(value(r).actor).toBe("support-agent");
    expect(await new Ledger(ledgerFile).asOf({ subject: "acct:42", predicate: "plan" })).toEqual([]);
    const b = await blastRadius(new Ledger(ledgerFile), loadReceipts(join(dir, "receipts")), factId);
    expect(b.retraction?.reason).toBe("stale CRM value");
    expect(b.stillBelieved.length).toBeGreaterThan(0);
  });
});

describe("policy over provenance: the gateway looks up the fact a write supersedes or a retraction targets", () => {
  let dir: string;
  let gw: Gateway;
  let ledgerFile: string;
  let attestedOrg: string;
  let claimedOrg: string;
  const POLICY = `permit(principal, action == Action::"memory.read", resource);
permit(principal, action == Action::"memory.get", resource);
// writes and retractions are fine unless they touch an attested org-space fact
permit(principal, action == Action::"memory.write", resource);
permit(principal, action == Action::"memory.retract", resource);
forbid(principal, action in [Action::"memory.write", Action::"memory.retract"], resource)
when { context.facts has target && context.facts.target.space == "org" && context.facts.target.provenance == "attested" };
`;
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "memory-provenance-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "memory.retract", "memory.get"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), POLICY);
    ledgerFile = join(dir, "ledger.jsonl");
    const seed = new Ledger(ledgerFile);
    attestedOrg = (await seed.assert({ subject: "policy:refunds", predicate: "limit", value: 100000, space: "org", actor: "finance-agent", provenance: "attested", source: { receiptId: "earlier" } })).fact.factId;
    claimedOrg = (await seed.assert({ subject: "policy:refunds", predicate: "note", value: "draft", space: "org", actor: "sdk-bot" })).fact.factId;
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({
      identity: { keyFile: "keys/gateway.key" },
      upstream: { command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile] },
      grantFile: "grant.json",
      trustedPrincipalKeys: ["keys/principal.pub"],
      policyFile: "policy.cedar",
      facts: [
        { name: "target", tool: "memory.get", args: { factId: "$args.supersedes" }, forTools: ["memory.write"], optional: true },
        { name: "target", tool: "memory.get", args: { factId: "$args.factId" }, forTools: ["memory.retract"] },
      ],
      receiptsDir: "receipts",
      logFile: "log.jsonl",
    }));
    gw = await createGateway(loadConfig(join(dir, "gateway.json")));
  });
  afterAll(async () => gw.close());

  it("a write that supersedes nothing needs no lookup and is allowed", async () => {
    const r = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:1", predicate: "plan", value: "pro", space: "team:support" } });
    expect(r.isError).toBeFalsy();
  });

  it("superseding an attested org fact is forbidden; the receipt shows the fact the policy saw, observed", async () => {
    const r = await gw.handleCall({ name: "memory.write", arguments: { subject: "policy:refunds", predicate: "limit", value: 10 ** 9, space: "org", supersedes: attestedOrg } });
    expect(r.isError).toBe(true);
    expect((r.content[0] as any).text).toMatch(/Denied by policy/);
    const bundle = JSON.parse(readFileSync(join(dir, "receipts", `${String(r._meta?.[RECEIPT_META_KEY])}.json`), "utf8"));
    const p = verifyBundle(bundle, { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))] }).statement!.predicate as any;
    expect(p.facts.target.provenance).toBe("observed");
    expect(p.facts.target.value).toMatchObject({ factId: attestedOrg, space: "org", provenance: "attested", retracted: false });
    expect((await new Ledger(ledgerFile).asOf({ subject: "policy:refunds", predicate: "limit" }))[0]?.value).toBe(100000);
  });

  it("superseding a claimed org fact, and retracting it, are allowed; retracting the attested one is not", async () => {
    const ok = await gw.handleCall({ name: "memory.write", arguments: { subject: "policy:refunds", predicate: "note", value: "final", space: "org", supersedes: claimedOrg } });
    expect(ok.isError).toBeFalsy();
    // the replacement came through the gateway, so it is attested: this policy now protects it too
    const protectedNow = await gw.handleCall({ name: "memory.retract", arguments: { factId: value(ok).fact.factId, reason: "cleanup" } });
    expect(protectedNow.isError).toBe(true);
    // the claimed original can still be retracted
    const gone = await gw.handleCall({ name: "memory.retract", arguments: { factId: claimedOrg, reason: "cleanup" } });
    expect(gone.isError).toBeFalsy();
    const kept = await gw.handleCall({ name: "memory.retract", arguments: { factId: attestedOrg, reason: "trying" } });
    expect(kept.isError).toBe(true);
    expect(await new Ledger(ledgerFile).asOf({ subject: "policy:refunds", predicate: "limit" })).toHaveLength(1);
  });
});

describe("several upstreams under one grant", () => {
  it("a refund made after the agent read a belief is in that belief's blast radius", async () => {
    const dir = mkdtempSync(join(tmpdir(), "memory-multi-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "stripe.refund"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action, resource);\n`);
    const ledgerFile = join(dir, "ledger.jsonl");
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({
      identity: { keyFile: "keys/gateway.key" },
      upstreams: [
        { name: "memory", command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile] },
        { name: "payments", command: process.execPath, args: [join(import.meta.dirname, "..", "..", "receipts", "scripts", "fake-stripe.ts")] },
      ],
      grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl",
    }));
    const g = await createGateway(loadConfig(join(dir, "gateway.json")));
    try {
      const plan = value(await g.handleCall({ name: "memory.write", arguments: { subject: "cust_123", predicate: "plan", value: "enterprise", space: "team:support" } })).fact;
      const before = await g.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 1 } });
      await g.handleCall({ name: "memory.read", arguments: { subject: "cust_123" } });
      const after = await g.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
      const b = await blastRadius(new Ledger(ledgerFile), loadReceipts(join(dir, "receipts")), plan.factId);
      const ids = b.receipts.map((r) => r.receiptId);
      expect(ids).toContain(String(after._meta?.[RECEIPT_META_KEY]));
      expect(ids).not.toContain(String(before._meta?.[RECEIPT_META_KEY]));
      expect(b.receipts.find((r) => r.receiptId === String(after._meta?.[RECEIPT_META_KEY]))?.tool).toBe("stripe.refund");
      const st = verifyBundle(JSON.parse(readFileSync(join(dir, "receipts", `${String(after._meta?.[RECEIPT_META_KEY])}.json`), "utf8")), { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))] }).statement!.predicate as any;
      expect(st.tool).toEqual({ name: "stripe.refund", provenance: "observed", upstream: "payments" });
      expect(st.consumed.factIds).toEqual([plan.factId]);
    } finally {
      await g.close();
    }
  });
});

describe("value-level quarantine: a write cites what the gateway observed", () => {
  let dir: string;
  let g: Gateway;
  let ledgerFile: string;
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "memory-evidence-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "customer.lookup"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    // org-space writes must cite evidence; the memory server then checks the value against what the gateway fetched
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action == Action::"memory.read", resource);
permit(principal, action == Action::"customer.lookup", resource);
permit(principal, action == Action::"memory.write", resource) when { context.args.space != "org" || context.args has evidence };
`);
    ledgerFile = join(dir, "ledger.jsonl");
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({
      identity: { keyFile: "keys/gateway.key" },
      upstreams: [
        { name: "memory", command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile] },
        { name: "crm", command: process.execPath, args: [join(import.meta.dirname, "..", "..", "receipts", "scripts", "fake-stripe.ts")] },
      ],
      facts: [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["memory.write"], optional: true }],
      grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl",
    }));
    g = await createGateway(loadConfig(join(dir, "gateway.json")));
  });
  afterAll(async () => g.close());

  it("a value equal to what the gateway fetched from the CRM is written as verified", async () => {
    const r = await g.handleCall({ name: "memory.write", arguments: { subject: "cust_123", predicate: "email", value: "alex@example.com", space: "org", customer_id: "cust_123", evidence: { fact: "customer", path: "email" } } });
    expect(r.isError, (r.content[0] as any).text).toBeFalsy();
    expect(value(r).fact.provenance).toBe("verified");
    expect(value(await g.handleCall({ name: "memory.read", arguments: { subject: "cust_123", requireVerified: true } })).facts.map((f: any) => f.predicate)).toEqual(["email"]);
  });

  it("a value that differs from the observation is refused, and so is evidence the gateway did not fetch", async () => {
    const wrong = await g.handleCall({ name: "memory.write", arguments: { subject: "cust_123", predicate: "email", value: "mallory@example.com", space: "org", customer_id: "cust_123", evidence: { fact: "customer", path: "email" } } });
    expect(wrong.isError).toBe(true);
    expect((wrong.content[0] as any).text).toMatch(/differs from what the gateway observed/);
    const none = await g.handleCall({ name: "memory.write", arguments: { subject: "cust_123", predicate: "email", value: "alex@example.com", space: "org", evidence: { fact: "customer", path: "email" } } });
    expect(none.isError).toBe(true);
    expect((none.content[0] as any).text).toMatch(/no fact named "customer" was fetched/);
    expect(await new Ledger(ledgerFile).asOf({ subject: "cust_123" })).toHaveLength(1);
  });

  it("without evidence an org write is denied by policy, while a team write goes through as attested", async () => {
    const org = await g.handleCall({ name: "memory.write", arguments: { subject: "cust_123", predicate: "plan", value: "enterprise", space: "org" } });
    expect(org.isError).toBe(true);
    expect((org.content[0] as any).text).toMatch(/Denied by policy/);
    const team = await g.handleCall({ name: "memory.write", arguments: { subject: "cust_123", predicate: "plan", value: "enterprise", space: "team:support" } });
    expect(value(team).fact.provenance).toBe("attested");
    expect(value(await g.handleCall({ name: "memory.read", arguments: { subject: "cust_123", requireVerified: true } })).facts.map((f: any) => f.predicate)).toEqual(["email"]);
    expect(value(await g.handleCall({ name: "memory.read", arguments: { subject: "cust_123" } })).facts.map((f: any) => f.predicate).sort()).toEqual(["email", "plan"]);
  });
});

describe("retention windows and the receipted sweep trigger", () => {
  it("a sweep with no cutoff uses the server's retention windows per space", async () => {
    const dir = mkdtempSync(join(tmpdir(), "memory-retention-"));
    const file = join(dir, "ledger.jsonl");
    const old = new Ledger(file, { now: () => new Date(Date.now() - 40 * 86_400_000) });
    const oldOrg = (await old.assert({ subject: "p:1", predicate: "email", value: "a@x", space: "org", actor: "x" })).fact.factId;
    const oldTeam = (await old.assert({ subject: "p:2", predicate: "email", value: "b@x", space: "team:support", actor: "x" })).fact.factId;
    const oldOther = (await old.assert({ subject: "p:3", predicate: "email", value: "c@x", space: "user:dana", actor: "x" })).fact.factId;
    const recent = (await new Ledger(file).assert({ subject: "p:4", predicate: "email", value: "d@x", space: "org", actor: "x" })).fact.factId;
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(new Ledger(file), { retention: { org: "P30D", "team:*": "P1D" } }).connect(a);
    const c = new Client({ name: "t", version: "0" });
    await c.connect(b);
    const r = value((await c.callTool({ name: "memory.sweep", arguments: { reason: "retention" } })) as CallToolResult);
    expect(r.before).toBeNull();
    expect(r.retention).toEqual({ org: "P30D", "team:*": "P1D" });
    expect(r.forgotten.map((f: any) => f.factId).sort()).toEqual([oldOrg, oldTeam].sort());
    const after = await new Ledger(file).facts();
    expect(after.find((f) => f.factId === oldOther)?.forgotten).toBeUndefined();
    expect(after.find((f) => f.factId === recent)?.forgotten).toBeUndefined();
    const none = (await c.callTool({ name: "memory.sweep", arguments: { reason: "x" } })) as CallToolResult;
    expect(value(none).forgotten).toEqual([]);
    await c.close();
  });

  it("sweep --via runs retention through a gateway as the principal in its grant, and the receipt is the record", async () => {
    const dir = mkdtempSync(join(tmpdir(), "memory-via-"));
    const ledgerFile = join(dir, "ledger.jsonl");
    const old = new Ledger(ledgerFile, { now: () => new Date(Date.now() - 100 * 86_400_000) });
    const stale = (await old.assert({ subject: "p:1", predicate: "phone", value: "+1 555 0100", space: "org", actor: "x" })).fact.factId;
    const held = (await old.assert({ subject: "p:2", predicate: "phone", value: "+1 555 0200", space: "org", actor: "x" })).fact.factId;
    await new Ledger(ledgerFile).hold({ factId: held, actor: "legal", reason: "matter 9" });
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "ops", agent: "retention-job", scopes: ["memory.sweep"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal == Agent::"retention-job", action == Action::"memory.sweep", resource);\n`);
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({ identity: { keyFile: "keys/gateway.key" }, upstream: { command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile, "--retention", "org=P90D"] }, grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl" }));
    const r = spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "sweep", "--via", join(dir, "gateway.json"), "--reason", "quarterly retention"], { encoding: "utf8", timeout: 60_000 });
    expect(r.status, r.stderr).toBe(0);
    const out = JSON.parse(r.stdout.trim());
    expect(out.forgotten.map((f: any) => f.factId)).toEqual([stale]);
    expect(out.held).toEqual([held]);
    const bundles = readdirSync(join(dir, "receipts")).map((f) => JSON.parse(readFileSync(join(dir, "receipts", f), "utf8")));
    const sweepReceipt = bundles.map((b) => verifyBundle(b, { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))], logFile: join(dir, "log.jsonl") })).find((v) => v.statement?.predicate.tool.name === "memory.sweep")!;
    expect(sweepReceipt.ok).toBe(true);
    expect(sweepReceipt.statement!.predicate.agent).toEqual({ id: "retention-job", provenance: "attested" });
    expect(readFileSync(ledgerFile, "utf8")).not.toContain("+1 555 0100");
    expect(readFileSync(ledgerFile, "utf8")).toContain("+1 555 0200");
  });
});

describe("repair: store entries whose ledger append failed", () => {
  const hourAgo = () => new Date(Date.now() - 3_600_000).toISOString();
  /** A store kept in a map. Its entries look an hour old, and it lists each one twice, as a listing over a changing set can. */
  function memoryStore(name: string): Store & { rows: Map<string, StoreEntry> } {
    const rows = new Map<string, StoreEntry>();
    return {
      name,
      rows,
      async put(fact) {
        rows.set(`${name}-${fact.factId}`, { externalId: `${name}-${fact.factId}`, factId: fact.factId, text: `${fact.subject} ${fact.predicate}`, storedAt: hourAgo() });
        return `${name}-${fact.factId}`;
      },
      async delete(e) {
        rows.delete(e.externalId);
      },
      async verifyDeleted(e) {
        return !rows.has(e.externalId);
      },
      async list() {
        return [...rows.values(), ...rows.values()];
      },
    };
  }
  /** A ledger whose next append fails while `fail.next` is set. */
  function flakyLedger() {
    const fail = { next: false };
    const events = openStore(join(mkdtempSync(join(tmpdir(), "memory-repair-")), "ledger.jsonl"));
    const store = new Proxy(events, { get: (t, k) => (k === "append" ? async (e: any) => (fail.next ? ((fail.next = false), Promise.reject(new Error("disk full"))) : t.append(e)) : Reflect.get(t, k)) });
    return { ledger: new Ledger(store), fail };
  }
  async function connect(ledger: Ledger, stores: Store[]) {
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(ledger, { stores, requireGateway: false, verify: { attempts: 1 } }).connect(a);
    const client = new Client({ name: "test", version: "0" });
    await client.connect(b);
    return client;
  }
  const write = (subject: string) => ({ name: "memory.write", arguments: { subject, predicate: "plan", value: "pro", space: "org" } });
  const repair = async (client: Client, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name: "memory.repair", arguments: { reason: "append failed", ...args } })) as CallToolResult;
    return { isError: r.isError === true, out: JSON.parse((r.content.at(-1) as { text: string }).text) };
  };

  it("removes the entry a failed append left, once, verifies the removal, records it, and keeps every entry the ledger has", async () => {
    const { ledger, fail } = flakyLedger();
    const listed = memoryStore("vec");
    const unlisted = { ...memoryStore("kv"), list: undefined };
    const client = await connect(ledger, [listed, unlisted]);
    const kept = value((await client.callTool(write("acct:1"))) as CallToolResult).fact;
    fail.next = true;
    expect(((await client.callTool(write("acct:2"))) as CallToolResult).isError).toBe(true);
    const [orphan] = [...listed.rows.values()].filter((e) => e.factId !== kept.factId);
    expect(await ledger.get(orphan!.factId)).toBeUndefined();

    const r = await repair(client);
    expect(r.isError).toBe(false);
    expect(r.out.repaired).toEqual([{ store: "vec", externalId: orphan!.externalId, factId: orphan!.factId, outcome: "verified", eventId: expect.any(String) }]);
    expect(r.out.unlisted).toEqual(["kv"]);
    expect([...listed.rows.values()].map((e) => e.factId)).toEqual([kept.factId]);
    const history = value((await client.callTool({ name: "memory.history", arguments: { factId: orphan!.factId } })) as CallToolResult).events;
    expect(history).toMatchObject([{ kind: "repair", store: "vec", externalId: orphan!.externalId, reason: "append failed" }]);
    await client.close();
  });

  it("refuses at startup a store written for remove(externalId, fact), so its old check never certifies an erasure", () => {
    const old = { name: "legacy", put: async () => "id", remove: async () => {}, verifyRemoved: async () => true } as unknown as Store;
    expect(() => createMemoryServer(flakyLedger().ledger, { stores: [old] })).toThrow(/store legacy has no delete\(entry\)/);
  });

  it("refuses a write whose stores took more than five minutes, so repair never meets the entries of a write in progress", async () => {
    const { ledger } = flakyLedger();
    const slow = memoryStore("slow");
    const put = slow.put;
    // The clock jumps from inside the put, which is always after the write noted its start.
    slow.put = async (f) => (vi.spyOn(Date, "now").mockReturnValue(Date.now() + 5 * 60_000 + 1), put(f));
    const client = await connect(ledger, [slow]);
    try {
      const r = (await client.callTool(write("acct:9"))) as CallToolResult;
      expect(r.isError).toBe(true);
      expect((r.content[0] as { text: string }).text).toMatch(/more than 5 minutes/);
      expect(await ledger.count()).toBe(0);
    } finally {
      vi.restoreAllMocks();
      await client.close();
    }
  });

  it("leaves an entry that may be a write in progress: younger than ten minutes, or with a time missing or unreadable, whatever `before` says", async () => {
    const store = memoryStore("vec");
    const orphan = (id: string, storedAt?: string) => store.rows.set(id, { externalId: id, factId: `fact-${id}`, text: "t", ...(storedAt === undefined ? {} : { storedAt }) });
    orphan("young", new Date(Date.now() - 60_000).toISOString());
    orphan("missing");
    orphan("unreadable", "yesterday");
    const client = await connect(flakyLedger().ledger, [store]);
    const r = await repair(client, { before: new Date(Date.now() + 60_000).toISOString() });
    expect(r.out.repaired).toEqual([]);
    expect(Date.parse(r.out.before)).toBeLessThanOrEqual(Date.now() - 10 * 60_000);
    expect([...store.rows.keys()]).toEqual(["young", "missing", "unreadable"]);
    await client.close();
  });

  it("reports a removal that failed, a store that cannot list, and a repair the ledger did not record, and goes on with the rest", async () => {
    const { ledger, fail } = flakyLedger();
    const stuck = { ...memoryStore("stuck"), delete: async (_e: StoreEntry): Promise<void> => Promise.reject(new Error("503")) };
    const broken = { ...memoryStore("broken"), list: async () => Promise.reject(new Error("timeout")) };
    const unlogged = memoryStore("unlogged");
    for (const s of [stuck, unlogged]) s.rows.set("x", { externalId: "x", factId: `fact-${s.name}`, text: "t", storedAt: hourAgo() });
    const client = await connect(ledger, [stuck, broken, unlogged]);
    // The append of the stuck entry's repair event goes through; the next one, the unlogged entry's, fails.
    const original = stuck.delete;
    stuck.delete = async (e) => ((fail.next = true), original(e));
    const r = await repair(client);
    expect(r.isError).toBe(true);
    expect(r.out.repaired).toMatchObject([{ store: "stuck", outcome: "failed" }]);
    expect(r.out.stillHeld).toEqual(["stuck: 503", "broken: cannot list: timeout"]);
    expect(r.out.unrecorded).toEqual([{ store: "unlogged", externalId: "x", factId: "fact-unlogged", error: "disk full" }]);
    expect(unlogged.rows.size).toBe(1);
    await client.close();
  });

  it("keeps the entry of a write whose ledger append is slow, for a repair that starts meanwhile, and the write lands", async () => {
    const events = openStore(join(mkdtempSync(join(tmpdir(), "memory-repair-")), "ledger.jsonl"));
    const gate = { release: () => {}, reached: () => {} };
    const held = new Promise<void>((r) => (gate.release = r));
    const reached = new Promise<void>((r) => (gate.reached = r));
    const ledger = new Ledger(new Proxy(events, { get: (t, k) => (k === "append" ? async (e: any) => (e.kind === "assert" ? (gate.reached(), await held, t.append(e)) : t.append(e)) : Reflect.get(t, k)) }));
    const vec = memoryStore("vec");
    const client = await connect(ledger, [vec]);
    const writing = client.callTool(write("acct:5")) as Promise<CallToolResult>;
    await reached;
    const repairing = repair(client);
    // The repair gets time to finish, if nothing makes it wait for the append.
    await new Promise((r) => setTimeout(r, 50));
    gate.release();
    const [w, r] = [await writing, await repairing];
    expect(w.isError).not.toBe(true);
    expect(r.out.repaired).toEqual([]);
    expect(vec.rows.size).toBe(1);
    expect((await ledger.asOf()).map((f) => f.subject)).toEqual(["acct:5"]);
    expect((await ledger.export()).map((e) => e.kind)).toEqual(["assert"]);
    await client.close();
  });

  it("fails a write whose entry a repair removed first, so the ledger never believes a fact that no store holds", async () => {
    const { ledger } = flakyLedger();
    const vec = memoryStore("vec");
    const other = await connect(ledger, [vec]);
    const put = vec.put;
    // A repair in another server runs after the store took the write and before the ledger append.
    vec.put = async (f) => {
      const id = await put(f);
      await repair(other);
      return id;
    };
    const client = await connect(ledger, [vec]);
    const r = (await client.callTool(write("acct:6"))) as CallToolResult;
    expect(r.isError).toBe(true);
    expect((r.content[0] as { text: string }).text).toMatch(/claimed by a repair/);
    expect(vec.rows.size).toBe(0);
    expect(await ledger.asOf()).toEqual([]);
    expect((await ledger.export()).map((e) => e.kind)).toEqual(["repair"]);
    await client.close();
    await other.close();
  });

  it("records one repair event and no failure when two repairs start together, even if the store fails a delete of a missing entry", async () => {
    const { ledger } = flakyLedger();
    const vec = memoryStore("vec");
    vec.rows.set("x", { externalId: "x", factId: "orphan-x", text: "t", storedAt: hourAgo() });
    vec.delete = async (e) => {
      if (!vec.rows.delete(e.externalId)) throw new Error("404");
    };
    const first = await connect(ledger, [vec]);
    const second = await connect(ledger, [vec]);
    const results = await Promise.all([repair(first), repair(second), repair(first)]);
    expect(results.map((r) => r.isError)).toEqual([false, false, false]);
    expect(results.flatMap((r) => r.out.stillHeld)).toEqual([]);
    expect((await ledger.history("orphan-x")).map((e) => e.kind)).toEqual(["repair"]);
    expect(vec.rows.size).toBe(0);
    await first.close();
    await second.close();
  });

  it("does not certify a delete the store refused because a similarity search misses the entry", async () => {
    const { ledger } = flakyLedger();
    const vec = memoryStore("vec");
    vec.rows.set("x", { externalId: "x", factId: "orphan-x", text: "t", storedAt: hourAgo() });
    vec.delete = async () => Promise.reject(new Error("503"));
    vec.verifyDeleted = async () => true;
    const client = await connect(ledger, [vec]);
    const r = await repair(client);
    expect(r.isError).toBe(true);
    expect(r.out.stillHeld).toEqual(["vec: 503"]);
    expect(r.out.repaired).toMatchObject([{ outcome: "failed" }]);
    expect(vec.rows.size).toBe(1);
    await client.close();
  });

  it("returns the outcomes of the entries it removed when the ledger cannot answer for a later one", async () => {
    const events = openStore(join(mkdtempSync(join(tmpdir(), "memory-repair-")), "ledger.jsonl"));
    const down = { on: false };
    const ledger = new Ledger(new Proxy(events, { get: (t, k) => (k === "eventsFor" ? async (id: string) => (down.on ? Promise.reject(new Error("ledger down")) : t.eventsFor(id)) : Reflect.get(t, k)) }));
    const vec = memoryStore("vec");
    for (const id of ["o1", "o2"]) vec.rows.set(id, { externalId: id, factId: `fact-${id}`, text: "t", storedAt: hourAgo() });
    const del = vec.delete;
    vec.delete = async (e) => ((down.on = true), del(e));
    const client = await connect(ledger, [vec]);
    const r = await repair(client);
    expect(r.isError).toBe(true);
    expect(r.out.repaired).toMatchObject([{ externalId: "o1", outcome: "verified" }]);
    expect(r.out.unrecorded).toMatchObject([{ externalId: "o2", error: "ledger down" }]);
    expect([...vec.rows.keys()]).toEqual(["o2"]);
    await client.close();
  });

  it("runs one sweep at a time in a process, so overlapping sweeps report an entry once", async () => {
    const { ledger } = flakyLedger();
    // A store that lists a snapshot, hands it over late, and accepts a delete of a missing entry, with no check of its own: only the queue
    // keeps the second sweep from listing the entry before the first has removed it.
    const vec = memoryStore("vec");
    vec.rows.set("x", { externalId: "x", factId: "orphan-x", text: "t", storedAt: hourAgo() });
    const list = vec.list!;
    vec.list = async () => {
      const listing = await list();
      await new Promise((r) => setTimeout(r, 20));
      return listing;
    };
    vec.verifyDeleted = undefined;
    const client = await connect(ledger, [vec]);
    const results = await Promise.all([repair(client), repair(client)]);
    expect(results.flatMap((r) => r.out.repaired)).toHaveLength(1);
    await client.close();
  });

  it("retries an entry whose removal failed, with the repair event it already has", async () => {
    const { ledger } = flakyLedger();
    const vec = memoryStore("vec");
    vec.rows.set("x", { externalId: "x", factId: "orphan-x", text: "t", storedAt: hourAgo() });
    const del = vec.delete;
    vec.delete = async () => Promise.reject(new Error("503"));
    const client = await connect(ledger, [vec]);
    const failed = await repair(client);
    expect(failed.isError).toBe(true);
    vec.delete = del;
    const retried = await repair(client);
    expect(retried.isError).toBe(false);
    expect(retried.out.repaired).toMatchObject([{ factId: "orphan-x", outcome: "verified", eventId: failed.out.repaired[0].eventId }]);
    expect((await ledger.history("orphan-x")).map((e) => e.kind)).toEqual(["repair"]);
    await client.close();
  });
});
