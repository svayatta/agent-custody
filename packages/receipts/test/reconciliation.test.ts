import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { digestOf, generateKeyPair, publicKeyToPem } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { createIssuer } from "../src/issue.ts";
import type { AuthorizationPredicate, ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { publicKeyFromPem as browserKey, verifyBundle as browserVerify } from "../../../site/verifier/verify-web.ts";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const failed = (r: { checks: { name: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.name);
const response = (status: string, extra: Record<string, unknown> = {}) => ({ content: [{ type: "text", text: JSON.stringify({ refund: { status }, ...extra }) }], isError: false });

async function fixture(options: { crash?: boolean; encrypted?: boolean; private?: boolean; status?: "pending" | "unknown"; observe?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "custody-reconcile-"));
  dirs.push(dir);
  const gateway = generateKeyPair(), principal = generateKeyPair();
  const key = options.encrypted ? randomBytes(32) : undefined;
  const issuer = createIssuer(gateway, join(dir, "receipts"), join(dir, "log.jsonl"), {
    ...(options.private || options.encrypted ? { capture: { rules: { "stripe.refund": { args: { mode: key ? "encrypted" : "digest" }, result: { mode: key ? "encrypted" : "digest" } } }, key } } : {}),
  });
  const receiptId = randomUUID(), operationId = randomUUID();
  const lookup = { tool: "stripe.refund.get", args: { key: digestOf(operationId) }, statusPath: "refund.status", identityPath: "idempotencyKey", confirmed: ["succeeded"], failed: ["failed", "canceled"] };
  const args = { amount: 700, reason: "request-secret-canary" };
  const operation = { id: operationId, idempotencyKey: digestOf(operationId), lookupDigest: digestOf(lookup), status: "submitted" as const, budget: { id: "refunds", currency: "USD", period: "2026-01-01" }, originalReceiptId: receiptId, provenance: "observed" as const };
  const auth: AuthorizationPredicate = {
    receiptId, timestamp: "2026-01-01T12:00:00.000Z", issuer: { kind: "gateway", keyid: gateway.keyid, version: "test" },
    principal: { id: "owner", keyid: principal.keyid, provenance: "attested" }, agent: { id: "bot", provenance: "attested" },
    delegation: { envelope: createDelegation(principal, { version: "0.1", principal: "owner", agent: "bot", scopes: ["stripe.refund"], issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-02T00:00:00.000Z" }), provenance: "attested" },
    tool: { name: "stripe.refund", provenance: "observed" }, request: { args, argsDigest: digestOf(args), provenance: "claimed" }, facts: {},
    policy: { decision: options.observe ? "deny" : "allow", ...(options.observe ? { enforced: false } : {}), reasons: ["refunds"], errors: [], policyDigest: digestOf("policy"), provenance: "observed" }, operation,
  };
  const authorization = await issuer.authorize(auth);
  const firstResult = response("pending");
  const base: ReceiptPredicate = {
    ...auth, session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" }, authorization,
    operation: { ...operation, status: options.status ?? "pending" }, execution: { status: "executed", result: firstResult, resultDigest: digestOf(firstResult), provenance: "observed" },
  };
  const original = options.crash ? authorization : await issuer.issue(base);
  const providerResult = response("succeeded", { idempotencyKey: operation.idempotencyKey, secret: "provider-secret-canary" });
  const predicate: ReceiptPredicate = {
    ...base, receiptId: randomUUID(), timestamp: "2026-01-03T12:00:00.000Z", authorization: undefined,
    request: { args: lookup.args, argsDigest: digestOf(lookup.args), provenance: "claimed" }, facts: {},
    operation: { ...operation, status: "confirmed" }, reconciliation: { original, lookup },
    execution: { status: "executed", result: providerResult, resultDigest: digestOf(providerResult), provenance: "observed" },
  };
  const bundle = await issuer.issue(predicate);
  const opts = { issuerKeys: [gateway], principalKeys: [principal], logFile: join(dir, "log.jsonl") };
  const browserOpts = { issuerKeys: [await browserKey(publicKeyToPem(gateway.publicKey))], principalKeys: [await browserKey(publicKeyToPem(principal.publicKey))] };
  const check = async (b: ReceiptBundle, expected = true) => {
    const cli = verifyBundle(b, opts), web = await browserVerify(b, browserOpts);
    expect(failed(web)).toEqual(failed(cli));
    expect(cli.ok, JSON.stringify(failed(cli))).toBe(expected);
    return cli;
  };
  const record = (status: string, extra: Record<string, unknown> = {}) => response(status, { idempotencyKey: operation.idempotencyKey, ...extra });
  const changed = async (edit: (p: ReceiptPredicate) => void) => {
    const p = structuredClone(predicate);
    p.receiptId = randomUUID();
    edit(p);
    return issuer.issue(p);
  };
  return { dir, operationId, issuer, key, opts, browserOpts, bundle, predicate, original, check, changed, record };
}

describe("financial outcome reconciliation evidence", () => {
  for (const status of ["pending", "unknown"] as const) {
    it(`verifies ${status} to confirmed, self-contained after the grant expired`, async () => {
      const f = await fixture({ status });
      rmSync(join(f.dir, "receipts"), { recursive: true });
      await f.check(f.bundle);
      expect(decode(f.bundle).predicate.execution.status).toBe("executed");
      expect(decode(f.bundle).predicate.operation?.status).toBe("confirmed");
    });
  }

  it("closes a submitted authorization when a crash prevented the original receipt", async () => {
    const f = await fixture({ crash: true });
    await f.check(f.bundle);
    expect(verifyBundle(f.bundle, f.opts).checks.some((c) => c.name === "reconciliation original authorization operation is submitted")).toBe(true);
  });

  it("records failed settlement as a successful provider read", async () => {
    const f = await fixture();
    const b = await f.changed((p) => {
      p.operation!.status = "failed";
      p.execution = { status: "executed", result: f.record("failed"), resultDigest: digestOf(f.record("failed")), provenance: "observed" };
    });
    await f.check(b);
  });

  it("rejects a forged status, remapped pending response, altered lookup identity, and invalid digest", async () => {
    const f = await fixture();
    for (const edit of [
      (p: ReceiptPredicate) => { p.operation!.status = "failed"; },
      (p: ReceiptPredicate) => { p.reconciliation!.lookup.confirmed = ["pending"]; p.execution = { status: "executed", result: f.record("pending"), resultDigest: digestOf(f.record("pending")), provenance: "observed" }; },
      (p: ReceiptPredicate) => { p.reconciliation!.lookup.args.key = "0".repeat(64); p.request.args = p.reconciliation!.lookup.args; p.request.argsDigest = digestOf(p.request.args); },
      (p: ReceiptPredicate) => { if ("resultDigest" in p.execution) p.execution.resultDigest = "0".repeat(64); },
      (p: ReceiptPredicate) => { p.operation!.id = randomUUID(); },
      (p: ReceiptPredicate) => { p.operation!.budget.period = "2026-01-02"; },
    ]) await f.check(await f.changed(edit), false);
  });

  it("verifies a withheld retry that names the original receipt, and refuses a retry that claims to have executed", async () => {
    const f = await fixture();
    const retry = (p: ReceiptPredicate) => { delete p.reconciliation; p.execution = { status: "withheld", reason: "existing operation", provenance: "observed" }; };
    await f.check(await f.changed(retry));
    const executed = await f.changed((p) => { retry(p); p.execution = { status: "executed", result: f.record("succeeded"), resultDigest: digestOf(f.record("succeeded")), provenance: "observed" }; });
    expect(failed(await f.check(executed, false))).toContain("operation names this original receipt");
  });

  it("links the original and the reconciliation when the agent's operation id is withheld from both", async () => {
    const f = await fixture({ private: true });
    const original = JSON.parse(Buffer.from(f.original.envelope.payload, "base64").toString()).predicate;
    expect(original.operation).not.toHaveProperty("id");
    expect(JSON.stringify(original) + JSON.stringify(decode(f.bundle).predicate)).not.toContain(f.operationId);
    expect(decode(f.bundle).predicate.operation).not.toHaveProperty("id");
    await f.check(f.bundle);
  });

  it("rejects pending or erroneous provider reads, malformed originals, and nested reconciliations", async () => {
    const f = await fixture();
    for (const edit of [
      (p: ReceiptPredicate) => { p.execution = { status: "executed", result: f.record("pending"), resultDigest: digestOf(f.record("pending")), provenance: "observed" }; },
      (p: ReceiptPredicate) => { const r = { ...f.record("succeeded"), isError: true }; p.execution = { status: "executed", result: r, resultDigest: digestOf(r), provenance: "observed" }; },
      (p: ReceiptPredicate) => { p.reconciliation!.original.envelope.signatures[0]!.sig = Buffer.alloc(64).toString("base64"); },
      (p: ReceiptPredicate) => { p.reconciliation!.original.inclusion.hashes = ["0".repeat(64)]; },
      (p: ReceiptPredicate) => { p.reconciliation!.original = f.bundle; },
    ]) await f.check(await f.changed(edit), false);
  });

  for (const encrypted of [false, true]) {
    it(`applies ${encrypted ? "encrypted" : "digest"} capture to provider results without leaking original request data`, async () => {
      const f = await fixture({ private: true, encrypted });
      await f.check(f.bundle);
      const p = decode(f.bundle).predicate;
      const original = JSON.parse(Buffer.from(p.reconciliation!.original.envelope.payload, "base64").toString());
      const auth = original.predicate.authorization;
      const text = JSON.stringify(p) + JSON.stringify(original) + (auth ? Buffer.from(auth.envelope.payload, "base64").toString() : "") + readFileSync(join(f.dir, "log.jsonl"), "utf8");
      expect(text).not.toContain("request-secret-canary");
      expect(text).not.toContain("provider-secret-canary");
      const r = verifyBundle(f.bundle, { ...f.opts, captureKey: f.key });
      expect(r.ok, JSON.stringify(failed(r))).toBe(true);
      expect(r.checks.find((c) => c.name === "reconciliation provider status")?.detail).toContain(encrypted ? "no independent provider signature" : "provider result withheld");
    });
  }
});
