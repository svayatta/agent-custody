import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { APPROVAL_TYPE, createApproval, type ApprovalRecord } from "../src/approval.ts";
import { privateView } from "../src/capture.ts";
import { digestOf, dsseCountersign, dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { createIssuer } from "../src/issue.ts";
import { buildStatement, RECEIPT_TYPE, type ReceiptBundle, type ReceiptPredicate } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";

const fx = buildFixture(mkdtempSync(join(tmpdir(), "approval-verifier-")));
const issuerKey = loadPrivateKey(join(fx.dir, "keys", "gateway.key"));
const human = generateKeyPair(), secondHuman = generateKeyPair();
const humanFile = writeKeyPair(human, join(fx.dir, "keys"), "human");
const issuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile);
const at = new Date().toISOString();
const args = { amount: 1000, currency: "GBP", recipient: "acct_42", reason: "private customer note" };
const fields = { beneficiary: "recipient" };
const binding = { principal: "user_456", agent: "support-agent", tool: "stripe.refund", args, fields };
const approval = dsseCountersign(createApproval(human, { ...binding, issuedAt: at, expiresAt: new Date(Date.parse(at) + 3600_000).toISOString() }), secondHuman);
const record: ApprovalRecord = { envelope: approval, fields, requiredApprovers: 2, status: "approved", approverKeyids: [human.keyid, secondHuman.keyid], checkedAt: at, consumedAt: at, provenance: "observed" };
const base: ReceiptPredicate = {
  receiptId: "e2e4c960-fde7-4a66-a7b8-e05006af3c8a", timestamp: at,
  issuer: { kind: "gateway", keyid: issuerKey.keyid, version: "test" },
  principal: { id: "user_456", keyid: loadPublicKey(fx.principalPub).keyid, provenance: "attested" },
  agent: { id: "support-agent", provenance: "attested" },
  delegation: { envelope: JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")), provenance: "attested" },
  session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" },
  tool: { name: "stripe.refund", provenance: "observed" },
  request: { args, argsDigest: digestOf(args), provenance: "claimed" }, facts: {},
  policy: { decision: "allow", reasons: [], errors: [], policyDigest: "test", provenance: "observed" },
  approval: record,
  execution: { status: "executed", result: { refundId: "re_1" }, resultDigest: digestOf({ refundId: "re_1" }), provenance: "observed" },
};
const opts = { issuerKeys: [issuerKey], principalKeys: [loadPublicKey(fx.principalPub)], approvalKeys: [human, secondHuman] };
const failing = (bundle: ReceiptBundle, options = opts) => verifyBundle(bundle, options).checks.filter((c) => !c.ok).map((c) => c.name);
let bundle: ReceiptBundle;
beforeAll(async () => { bundle = await issuer.issue(structuredClone(base)); });

describe("independent approval verification", () => {
  it("checks two trusted signatures and a custom beneficiary mapping", () => {
    expect(failing(bundle)).toEqual([]);
    expect(failing(bundle, { ...opts, approvalKeys: [] })).toContain("approval signatures (human keys)");
    expect(failing(bundle, { ...opts, approvalKeys: [human] })).toContain("approval signatures (human keys)");
  });

  it.each(["amount", "currency", "recipient", "reason"])("rejects a re-signed changed %s even after recomputing the request digest", async (field) => {
    const p = structuredClone(base);
    p.request.args[field] = field === "amount" ? 1001 : "changed";
    p.request.argsDigest = digestOf(p.request.args);
    expect(failing(await issuer.issue(p))).toContain("approval payload binding");
  });

  it.each(["executed", "failed", "error"])("requires consumption for an attempted forward recorded as %s", async (status) => {
    const p = structuredClone(base);
    delete p.approval!.consumedAt;
    p.execution = status === "error" ? { status, error: "response lost", provenance: "observed" } : { ...(base.execution as Extract<ReceiptPredicate["execution"], { status: "executed" | "failed" }>), status: status as "executed" | "failed" };
    expect(failing(await issuer.issue(p))).toContain("approval consistent with execution");
  });

  it("does not accept duplicate signer ids as a second human", async () => {
    const p = structuredClone(base);
    p.approval!.envelope!.signatures = [approval.signatures[0]!, approval.signatures[0]!];
    p.approval!.approverKeyids = [human.keyid, human.keyid];
    expect(failing(await issuer.issue(p))).toContain("approval signatures (human keys)");
  });

  it("requires a signed approval valid when forwarded, not only when the call began", async () => {
    const p = structuredClone(base);
    p.approval!.consumedAt = new Date(Date.parse(at) + 7200_000).toISOString();
    expect(failing(await issuer.issue(p))).toContain("approval valid at forward time");
  });

  it("also checks the recorded check time against the signed validity window", async () => {
    const p = structuredClone(base);
    p.approval!.checkedAt = new Date(Date.parse(at) - 60_000).toISOString();
    expect(failing(await issuer.issue(p))).toContain("approval valid at forward time");
  });

  it("authenticates refusals with missing or invalid approvals", async () => {
    const p = structuredClone(base);
    p.approval = { requiredApprovers: 2, checkedAt: at, status: "denied", reason: "missing approval", approverKeyids: [], provenance: "observed" };
    p.policy!.decision = "deny";
    p.execution = { status: "denied", reason: "missing approval", provenance: "observed" };
    expect(failing(await issuer.issue(p), { ...opts, approvalKeys: [] })).toEqual([]);
  });

  it("rejects malformed status values before equality-based enforcement checks", async () => {
    for (const target of ["execution", "approval"] as const) {
      const p = structuredClone(base);
      (p[target] as unknown as { status: unknown }).status = [target === "execution" ? "executed" : "approved"];
      expect(failing(await issuer.issue(p))).toContain("structural parts in clear");
    }
  });

  it("rejects signed malformed approval statements", async () => {
    const p = structuredClone(base);
    const value = JSON.parse(Buffer.from(approval.payload, "base64").toString("utf8"));
    value.amount = 1.5;
    p.approval!.envelope = dsseCountersign(dsseSign(APPROVAL_TYPE, value, human), secondHuman);
    expect(failing(await issuer.issue(p))).toContain("approval signatures (human keys)");
  });

  it("checks the same approval in the precommit and the receipt", async () => {
    const p = structuredClone(base);
    const { execution, session, model, ...head } = p;
    p.authorization = await issuer.authorize(head);
    p.approval!.envelope = dsseCountersign(createApproval(human, { ...binding, issuedAt: at, expiresAt: new Date(Date.parse(at) + 3600_000).toISOString() }), secondHuman);
    expect(failing(await issuer.issue(p))).toContain("authorization carries this approval");
  });

  it.each(["status", "checkedAt", "approverKeyids"])("rejects a precommit with an invalid approval %s even when the final record is valid", async (field) => {
    const p = structuredClone(base);
    const { execution, session, model, ...head } = structuredClone(p);
    if (field === "status") head.approval!.status = "denied";
    if (field === "checkedAt") head.approval!.checkedAt = new Date(Date.parse(at) - 60_000).toISOString();
    if (field === "approverKeyids") head.approval!.approverKeyids = [human.keyid, human.keyid];
    p.authorization = await issuer.authorize(head);
    expect(failing(await issuer.issue(p))).toContain("authorization approval was valid");
  });

  it("keeps authenticated approvals clear but requires disclosed or decrypted private args for binding", async () => {
    const key = Buffer.alloc(32, 7);
    const rules = { "stripe.refund": { args: { mode: "encrypted" as const, clear: ["amount", "currency", "recipient"] } } };
    const privateIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules, key } });
    const p = structuredClone(base);
    const { execution, session, model, ...head } = p;
    p.authorization = await privateIssuer.authorize(head);
    const privateBundle = await privateIssuer.issue(p);
    const visible = JSON.parse(Buffer.from(privateBundle.envelope.payload, "base64").toString()).predicate as ReceiptPredicate;
    expect(visible.approval).toEqual(record);
    expect(visible.capture!.withheld.some((w) => w[0] === "approval")).toBe(false);
    expect(failing(privateBundle)).toEqual(["approval payload binding"]);
    expect(verifyBundle(privateBundle, { ...opts, captureKey: key }).checks.filter((c) => !c.ok)).toEqual([]);
  });

  it("never allows capture to hide an approval's status or signatures", () => {
    const p = structuredClone(base);
    const view = privateView(p, { args: { mode: "digest" } });
    const st = buildStatement({ ...view.predicate, capture: { mode: "digest", withheld: [["approval"]] } });
    const malformed = { ...bundle, envelope: dsseSign(RECEIPT_TYPE, st, issuerKey) };
    expect(failing(malformed)).toContain("structural parts in clear");
  });

  it("accepts repeatable --approval-key flags in the offline CLI", async () => {
    const p = structuredClone(base);
    const oneHuman = createApproval(human, { ...binding, issuedAt: at, expiresAt: new Date(Date.parse(at) + 3600_000).toISOString() });
    p.approval = { ...record, envelope: oneHuman, requiredApprovers: 1, approverKeyids: [human.keyid] };
    await issuer.issue(p);
    const cli = spawnSync(process.execPath, ["--import", "tsx", join(import.meta.dirname, "../src/cli.ts"), "verify", join(fx.receiptsDir, `${p.receiptId}.json`), "--issuer-key", join(fx.dir, "keys/gateway.pub"), "--principal-key", fx.principalPub, "--approval-key", humanFile.pubFile, "--approval-key", humanFile.pubFile, "--json"], { encoding: "utf8", timeout: 30_000 });
    expect(cli.status, cli.stderr || cli.stdout).toBe(0);
    expect(JSON.parse(cli.stdout).ok).toBe(true);
  });
});
