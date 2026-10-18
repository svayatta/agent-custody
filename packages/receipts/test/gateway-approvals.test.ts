import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import fs from "node:fs";
import crypto from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { APPROVAL_META_KEY, APPROVAL_TYPE, createApproval, type ApprovalBinding } from "../src/approval.ts";
import { checkCommitment, isCommitment, pathKey, type Commitment } from "../src/capture.ts";
import { GatewayConfigSchema, loadConfig, type GatewayConfig } from "../src/config.ts";
import { dsseCountersign, dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair, type Envelope } from "../src/crypto.ts";
import { verifyBundle } from "../src/verify.ts";
import { createGatewayHost, RECEIPT_META_KEY, type Gateway, type GatewayHost, type GatewayOptions } from "../src/gateway.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { buildFixture, type Fixture } from "../scripts/fixture.ts";

const args = () => ({ amount: 2500, currency: "GBP", beneficiary: "cust_123", customer_id: "cust_123" });
const binding = (a: Record<string, unknown> = args()): ApprovalBinding => ({ principal: "user_456", agent: "support-agent", tool: "stripe.refund", args: a });
const key = generateKeyPair();
const secondKey = generateKeyPair();
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

let server: Server;
let url: string;
let seen: { method: string; path: string; body: unknown }[] = [];
let lookup: (() => void | Promise<void>) | undefined;
const hosts: GatewayHost[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => body += chunk);
    req.on("end", async () => {
      seen.push({ method: req.method!, path: req.url!, body: body ? JSON.parse(body) : null });
      if (req.method === "GET") await lookup?.();
      if (req.method === "POST" && body && JSON.parse(body).customer_id === "cust_transport_error") { res.destroy(); return; }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(req.method === "GET" ? { id: "cust_123", verified: true } : { refund_id: "re_approved" }));
    });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  syncBuiltinESMExports();
  lookup = undefined;
  for (const host of hosts.splice(0)) await host.close();
  seen = [];
});
afterAll(async () => {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

async function fixture(change?: (cfg: GatewayConfig, fx: Fixture) => void, options?: (fx: Fixture) => GatewayOptions) {
  const fx = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-approval-gateway-")));
  writeKeyPair(key, join(fx.dir, "keys"), "approver");
  writeKeyPair(secondKey, join(fx.dir, "keys"), "second-approver");
  const raw = JSON.parse(readFileSync(fx.configFile, "utf8"));
  raw.upstream = { rest: { baseUrl: url, tools: [
    { name: "customer.lookup", path: "/customer/{customer_id}" },
    { name: "stripe.refund", method: "POST", path: "/refund" },
  ] } };
  raw.approvals = { trustedKeys: ["keys/approver.pub", "keys/second-approver.pub"], usedDir: "used-approvals", tools: [{ tool: "stripe.refund" }] };
  writeFileSync(fx.configFile, JSON.stringify(raw));
  writeFileSync(join(fx.dir, "policy.cedar"), "permit(principal, action, resource);");
  const cfg = loadConfig(fx.configFile);
  change?.(cfg, fx);
  const host = await createGatewayHost(cfg, options?.(fx));
  hosts.push(host);
  const grant = JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope;
  const gw = host.open(grant);
  const predicate = (result: Awaited<ReturnType<Gateway["handleCall"]>>): ReceiptPredicate => decode(JSON.parse(readFileSync(join(fx.receiptsDir, `${String(result._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle).predicate;
  return { fx, cfg, host, grant, gw, predicate };
}
const approve = (b: ApprovalBinding = binding(), expiresAt = new Date(Date.now() + 60_000).toISOString()) => createApproval(key, { ...b, expiresAt });
const call = (gw: Gateway, envelope?: Envelope, a = args(), name = "stripe.refund") => gw.handleCall({ name, arguments: a, ...(envelope ? { _meta: { [APPROVAL_META_KEY]: envelope } } : {}) });
const refunds = () => seen.filter((s) => s.method === "POST");

describe("gateway signed approvals", () => {
  it("resolves approval paths and validates unique tools and approver counts", async () => {
    const { cfg, fx } = await fixture();
    expect(cfg.approvals!.trustedKeys[0]).toBe(join(fx.dir, "keys/approver.pub"));
    expect(cfg.approvals!.usedDir).toBe(join(fx.dir, "used-approvals"));
    expect(cfg.approvals!.tools[0]!.minApprovers).toBe(1);
    expect(GatewayConfigSchema.safeParse({ ...cfg, approvals: { ...cfg.approvals, tools: [{ tool: "t" }, { tool: "t" }] } }).success).toBe(false);
    for (const value of [0, 3, 1.5]) expect(GatewayConfigSchema.safeParse({ ...cfg, approvals: { ...cfg.approvals, tools: [{ tool: "t", minApprovers: value }] } }).success).toBe(false);
    for (const approvals of [{ ...cfg.approvals, trustedKeys: [] }, { ...cfg.approvals, usedDir: "" }, { ...cfg.approvals, tools: [] }]) expect(GatewayConfigSchema.safeParse({ ...cfg, approvals }).success).toBe(false);
  });

  it("forwards an approved action once and includes the approval in the precommit authorization", async () => {
    const { gw, predicate, cfg } = await fixture((c) => c.precommit = ["stripe.refund"]);
    const envelope = approve();
    const result = await call(gw, envelope);
    expect(result.isError).toBeFalsy();
    expect(refunds()).toHaveLength(1);
    expect(refunds()[0]!.body).toEqual(args());
    const p = predicate(result);
    expect(p.execution.status).toBe("executed");
    expect(p.approval).toMatchObject({ envelope, status: "approved", requiredApprovers: 1, approverKeyids: [key.keyid], provenance: "observed" });
    expect(p.approval!.consumedAt).toEqual(expect.any(String));
    const authorization = decode(p.authorization as ReceiptBundle).predicate;
    expect(authorization.approval).toMatchObject({ envelope, status: "approved" });
    expect(readdirSync(cfg.approvals!.usedDir)).toHaveLength(1);
  });

  it.each(["amount", "currency", "beneficiary", "extra"])("denies a changed %s despite a permissive Cedar policy", async (field) => {
    const { gw, predicate } = await fixture();
    const a: Record<string, unknown> = args();
    a[field] = field === "amount" ? 9999 : "different";
    const result = await gw.handleCall({ name: "stripe.refund", arguments: a, _meta: { [APPROVAL_META_KEY]: approve() } });
    expect(result.isError).toBe(true);
    expect(refunds()).toHaveLength(0);
    expect(seen).toHaveLength(0);
    expect(predicate(result)).toMatchObject({ approval: { status: "denied" }, execution: { status: "denied" }, policy: { decision: "deny" } });
  });

  it.each(["principal", "agent", "tool"])("denies an approval for another %s", async (field) => {
    const { gw, predicate } = await fixture();
    const result = await call(gw, approve({ ...binding(), [field]: "another" }));
    expect(result.isError).toBe(true);
    expect(refunds()).toHaveLength(0);
    expect(predicate(result).approval!.status).toBe("denied");
  });

  it("requires approval in observe mode and never lets missing or malformed metadata reach upstream", async () => {
    const { gw, predicate } = await fixture((c) => c.mode = "observe");
    for (const value of [undefined, {}, { payloadType: "wrong", payload: "not JSON", signatures: [] }]) {
      const result = await gw.handleCall({ name: "stripe.refund", arguments: args(), _meta: { [APPROVAL_META_KEY]: value } });
      const p = predicate(result);
      expect(result.isError).toBe(true);
      expect(p.execution.status).toBe("denied");
      expect(p.policy).not.toHaveProperty("enforced", false);
      expect(p.approval!.status).toBe("denied");
    }
    expect(seen).toHaveLength(0);
  });

  it("does not accept an unknown signer or two copies of one signer's signature for a two-person rule", async () => {
    const { gw } = await fixture((c) => c.approvals!.tools[0]!.minApprovers = 2);
    const envelope = approve();
    const duplicate = { ...envelope, signatures: [...envelope.signatures, ...envelope.signatures] };
    expect((await call(gw, duplicate)).isError).toBe(true);
    const unknown = dsseCountersign(envelope, generateKeyPair());
    expect((await call(gw, unknown)).isError).toBe(true);
    const two = dsseCountersign(envelope, secondKey);
    expect((await call(gw, two)).isError).toBeFalsy();
    expect(refunds()).toHaveLength(1);
  });

  it("denies expired approvals before gathering facts", async () => {
    const { gw, predicate } = await fixture();
    const envelope = createApproval(key, { ...binding(), issuedAt: new Date(Date.now() - 10_000).toISOString(), expiresAt: new Date(Date.now() - 1000).toISOString() });
    const result = await call(gw, envelope);
    expect(predicate(result)).toMatchObject({ execution: { status: "denied" }, approval: { status: "denied", reason: expect.stringMatching(/expir/i) } });
    expect(seen).toHaveLength(0);
  });

  it("consumes one approval once under concurrent calls and persists that claim across sessions and restart", async () => {
    const { gw, predicate, host, grant, cfg } = await fixture();
    const envelope = approve();
    const results = await Promise.all([call(gw, envelope), call(gw, envelope)]);
    expect(results.filter((r) => !r.isError)).toHaveLength(1);
    expect(results.map((r) => predicate(r).execution.status).sort()).toEqual(["executed", "withheld"]);
    expect((await call(host.open(grant), envelope)).isError).toBe(true);
    await host.close();
    hosts.splice(hosts.indexOf(host), 1);
    const restarted = await createGatewayHost(cfg);
    hosts.push(restarted);
    expect((await call(restarted.open(grant), envelope)).isError).toBe(true);
    expect(refunds()).toHaveLength(1);
  });

  it("does not consume a valid approval when Cedar denies the action", async () => {
    const { gw, cfg } = await fixture((_c, fx) => writeFileSync(join(fx.dir, "policy.cedar"), "forbid(principal, action, resource);"));
    expect((await call(gw, approve())).isError).toBe(true);
    expect(refunds()).toHaveLength(0);
    expect(() => readdirSync(cfg.approvals!.usedDir)).toThrow();
  });

  it.each([["in clear", undefined], ["under a private args rule", { "*": { args: { mode: "digest" as const } } }]])("a Cedar refusal that carried a valid approval verifies without approval keys, %s", async (_name, capture) => {
    const { fx, gw, predicate } = await fixture((c, f) => {
      writeFileSync(join(f.dir, "policy.cedar"), "forbid(principal, action, resource);");
      if (capture) c.capture = capture;
    });
    const result = await call(gw, approve());
    expect(predicate(result)).toMatchObject({ approval: { status: "approved" }, execution: { status: "denied" } });
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(result._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
    const verified = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)] });
    expect(verified.checks.filter((check) => !check.ok)).toEqual([]);
  });

  it("keeps the approved envelope in clear when the rule keeps the arguments in clear, and verifies the binding", async () => {
    const { fx, gw, predicate } = await fixture((c) => { c.capture = { "*": { args: { mode: "clear" }, result: { mode: "digest" } } }; });
    const envelope = approve();
    const result = await call(gw, envelope);
    expect(result.isError).toBeFalsy();
    expect(predicate(result).approval!.envelope).toEqual(envelope);
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(result._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
    const verified = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], approvalKeys: [loadPublicKey(join(fx.dir, "keys/approver.pub"))] });
    expect(verified.checks.filter((check) => !check.ok)).toEqual([]);
    expect(verified.checks.find((check) => check.name === "approval payload binding")?.detail).toMatch(/full arguments/);
  });

  it("refuses an approval whose lifetime exceeds the default cap, and honors approvals.maxLifetimeSeconds", async () => {
    const { gw, predicate } = await fixture();
    const tooLong = approve(binding(), new Date(Date.now() + 3_700_000).toISOString());
    const refused = await call(gw, tooLong);
    expect(refused.isError).toBe(true);
    expect(predicate(refused)).toMatchObject({ execution: { status: "denied" }, approval: { status: "denied", reason: expect.stringMatching(/lifetime exceeds the maximum of 3600 seconds/) } });
    expect(seen).toHaveLength(0);

    const capped = await fixture((c) => { c.approvals!.maxLifetimeSeconds = 30; });
    expect((await call(capped.gw, approve())).isError).toBe(true);
    expect((await call(capped.gw, approve(binding(), new Date(Date.now() + 20_000).toISOString()))).isError).toBeFalsy();
    for (const value of [0, -1, 1.5]) expect(GatewayConfigSchema.safeParse({ ...capped.cfg, approvals: { ...capped.cfg.approvals, maxLifetimeSeconds: value } }).success).toBe(false);
  });

  it("keeps approval consumed when forwarding ends in a transport error", async () => {
    const { gw, predicate } = await fixture();
    const a = { ...args(), customer_id: "cust_transport_error" };
    const envelope = approve(binding(a));
    const result = await call(gw, envelope, a);
    expect(result.isError).toBe(true);
    expect(predicate(result)).toMatchObject({ execution: { status: "error" }, approval: { status: "approved", consumedAt: expect.any(String) } });
    expect((await call(gw, envelope, a)).isError).toBe(true);
    expect(refunds()).toHaveLength(1);
  });

  it.each(["facts", "precommit"])("withholds approval that expires during awaited %s", async (stage) => {
    const now = Date.now();
    let advances = 0;
    const advance = () => { advances++; vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now + 5000); };
    const f = await fixture((c) => { if (stage === "precommit") c.precommit = ["stripe.refund"]; }, stage === "precommit" ? (fx) => {
      const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys/gateway.key")));
      const log: LogSink = { kind: inner.kind, where: inner.where, async append(leaf) { const result = await inner.append(leaf); advance(); return result; } };
      return { log };
    } : undefined);
    if (stage === "facts") lookup = advance;
    const result = await call(f.gw, approve(binding(), new Date(now + 2000).toISOString()));
    expect(advances).toBeGreaterThan(0);
    expect(result.isError).toBe(true);
    expect(f.predicate(result)).toMatchObject({ execution: { status: "withheld" }, approval: { status: "denied", reason: expect.stringMatching(/expir/i) } });
    expect(refunds()).toHaveLength(0);
  });

  it("withholds a call when the persistent claim cannot be written, including observe mode", async () => {
    const { gw, predicate } = await fixture((c, fx) => { c.mode = "observe"; c.approvals!.usedDir = join(fx.dir, "not-a-directory"); writeFileSync(c.approvals!.usedDir, "blocked"); });
    const result = await call(gw, approve());
    expect(result.isError).toBe(true);
    expect(predicate(result)).toMatchObject({ execution: { status: "withheld" }, approval: { status: "denied", reason: expect.stringMatching(/consum/i) } });
    expect(refunds()).toHaveLength(0);
  });

  it.each(["expiry", "revocation"])("rechecks %s after a synchronous durable claim blocks", async (change) => {
    const now = Date.now();
    const { gw, predicate, cfg } = await fixture((c, fx) => { c.revokedGrants = join(fx.dir, "revoked.json"); });
    const originalFsync = fs.fsyncSync;
    let synced = false;
    vi.spyOn(fs, "fsyncSync").mockImplementation((fd) => {
      originalFsync(fd);
      synced = true;
      if (change === "expiry") { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now + 5000); }
      else writeFileSync(cfg.revokedGrants!, JSON.stringify([gw.grantDigest]));
    });
    syncBuiltinESMExports();
    const result = await call(gw, approve(binding(), new Date(now + 2000).toISOString()));
    expect(synced).toBe(true);
    expect(result.isError).toBe(true);
    const p = predicate(result);
    expect(p.execution.status).toBe("withheld");
    expect(p.approval!.consumedAt).toEqual(expect.any(String));
    expect(p.approval!.status).toBe(change === "expiry" ? "denied" : "approved");
    expect(readdirSync(cfg.approvals!.usedDir)).toHaveLength(1);
    expect(refunds()).toHaveLength(0);
  });

  it.each(["approval", "grant", "revocation"])("rechecks %s after final signature verification takes time", async (expires) => {
    const now = Date.now();
    const { gw, predicate, cfg } = await fixture((c, fx) => {
      if (expires === "revocation") c.revokedGrants = join(fx.dir, "revoked.json");
      if (expires !== "grant") return;
      const path = join(fx.dir, "grant.json");
      const envelope = JSON.parse(readFileSync(path, "utf8")) as Envelope;
      const payload = JSON.parse(Buffer.from(envelope.payload, "base64").toString());
      payload.expiresAt = new Date(now + 2000).toISOString();
      writeFileSync(path, JSON.stringify(dsseSign(envelope.payloadType, payload, loadPrivateKey(join(fx.dir, "keys/principal.key")))));
    });
    const originalFsync = fs.fsyncSync;
    const originalVerify = crypto.verify;
    let claimed = false;
    let advanced = false;
    vi.spyOn(fs, "fsyncSync").mockImplementation((fd) => { originalFsync(fd); claimed = true; });
    vi.spyOn(crypto, "verify").mockImplementation((...parameters: any[]) => {
      const result = (originalVerify as (...values: any[]) => boolean)(...parameters);
      if (claimed && !advanced) {
        advanced = true;
        if (expires === "revocation") writeFileSync(cfg.revokedGrants!, JSON.stringify([gw.grantDigest]));
        else {
          vi.useFakeTimers({ toFake: ["Date"] });
          vi.setSystemTime(now + 5000);
        }
      }
      return result;
    });
    syncBuiltinESMExports();
    const result = await call(gw, approve(binding(), new Date(now + (expires === "approval" ? 2000 : 60_000)).toISOString()));
    expect(advanced).toBe(true);
    expect(result.isError).toBe(true);
    const p = predicate(result);
    expect(p.execution.status).toBe("withheld");
    expect(p.approval!.status).toBe(expires === "approval" ? "denied" : "approved");
    if (expires === "approval") expect(p.approval!.checkedAt).toBe(new Date(now + 5000).toISOString());
    else expect(p.execution).toMatchObject({ reason: expect.stringMatching(expires === "revocation" ? /revoked/ : /expired/) });
    expect(p.approval!.consumedAt).toBe(p.approval!.checkedAt);
    expect(readdirSync(cfg.approvals!.usedDir)).toHaveLength(1);
    expect(refunds()).toHaveLength(0);
  });

  it("snapshots arguments and approval while fact gathering is awaited", async () => {
    const { gw, predicate } = await fixture();
    const a = args();
    const envelope = approve();
    lookup = () => { a.amount = 9999; envelope.payload = "mutated"; envelope.signatures.length = 0; };
    const original = structuredClone(envelope);
    const result = await call(gw, envelope, a);
    expect(result.isError).toBeFalsy();
    expect(refunds()[0]!.body).toEqual(args());
    expect(predicate(result).approval!.envelope).toEqual(original);
    expect(predicate(result).request.args).toEqual(args());
  });

  it("supports custom field mappings and exact rules ahead of a wildcard", async () => {
    const fields = { amount: "minor_units", currency: "unit", beneficiary: "payee" };
    const { gw, predicate } = await fixture((c) => { c.approvals!.tools = [{ tool: "*", minApprovers: 2 }, { tool: "stripe.refund", minApprovers: 1, fields }]; });
    const a = { minor_units: 123, unit: "GBP", payee: "cust_123", customer_id: "cust_123" };
    const result = await gw.handleCall({ name: "stripe.refund", arguments: a, _meta: { [APPROVAL_META_KEY]: approve({ ...binding(a), fields }) } });
    expect(result.isError).toBeFalsy();
    expect(predicate(result).approval).toMatchObject({ fields, requiredApprovers: 1 });
    const wrongTool = await gw.handleCall({ name: "customer.lookup", arguments: a, _meta: { [APPROVAL_META_KEY]: approve({ ...binding(a), fields }) } });
    expect(wrongTool.isError).toBe(true);
    expect(seen.filter((s) => s.method === "GET")).toHaveLength(1);
  });

  it("does not copy malformed approval input or appended untrusted signatures into private evidence", async () => {
    const secret = "approval-signature-private-canary";
    const { fx, gw, predicate } = await fixture((c) => { c.precommit = ["stripe.refund"]; c.capture = { "*": { args: { mode: "digest" }, result: { mode: "digest" }, facts: { mode: "digest" } } }; });
    const a = { ...args(), private_note: secret };
    const original = approve(binding(a));
    const invalidPayload = JSON.parse(Buffer.from(original.payload, "base64").toString());
    invalidPayload[secret] = secret;
    const malformed = await call(gw, dsseSign(APPROVAL_TYPE, invalidPayload, key), a);
    const denied = predicate(malformed);
    expect(denied.approval).not.toHaveProperty("envelope");
    // The reason can quote the statement, so a private rule withholds it.
    expect(isCommitment(denied.approval!.reason)).toBe(true);
    expect(JSON.stringify(denied)).not.toContain(secret);

    const padded = Buffer.from(secret.padEnd(64, "x")).toString("base64");
    const appended = { ...original, signatures: [...original.signatures, { keyid: secret, sig: padded }, { keyid: key.keyid, sig: padded }] };
    const approved = await call(gw, appended, a);
    expect(approved.isError).toBeFalsy();
    const p = predicate(approved);
    // The receipt commits to the envelope with only the verified signatures, and the precommit carries the same commitment.
    const { salts } = JSON.parse(readFileSync(join(fx.receiptsDir, "salts", `${String(approved._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as { salts: Record<string, string> };
    expect(isCommitment(p.approval!.envelope)).toBe(true);
    expect(checkCommitment(p.approval!.envelope as unknown as Commitment, original, salts[pathKey(["approval", "envelope"])]!)).toBe(true);
    expect(JSON.stringify(p)).not.toContain(secret);
    const authorization = decode(p.authorization as ReceiptBundle).predicate;
    expect(authorization.approval!.envelope).toEqual(p.approval!.envelope);
    expect(JSON.stringify(authorization)).not.toContain(secret);
  });
});
