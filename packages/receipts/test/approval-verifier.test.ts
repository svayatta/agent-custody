import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { APPROVAL_TYPE, createApproval, type ApprovalRecord } from "../src/approval.ts";
import { isCommitment, privateView, withhold } from "../src/capture.ts";
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

  it("withholds the approval envelope under a private rule, and checks it again with the capture key", async () => {
    const key = Buffer.alloc(32, 7);
    const rules = { "stripe.refund": { args: { mode: "encrypted" as const, clear: ["amount", "currency", "recipient"] } } };
    const privateIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules, key } });
    const p = structuredClone(base);
    const { execution, session, model, ...head } = p;
    p.authorization = await privateIssuer.authorize(head);
    const privateBundle = await privateIssuer.issue(p);
    const visible = JSON.parse(Buffer.from(privateBundle.envelope.payload, "base64").toString()).predicate as ReceiptPredicate;
    // The gateway's own observations stay in clear. The envelope, which the agent supplied, is one commitment.
    const { envelope, ...observed } = record;
    expect(visible.approval).toEqual({ ...observed, envelope: expect.objectContaining({ $custody: "encrypted" }) });
    expect(visible.capture!.withheld).toContainEqual(["approval", "envelope"]);
    expect(visible.capture!.withheld.some((w) => w[0] === "approval" && w.length === 1)).toBe(false);
    const authorized = JSON.parse(Buffer.from((visible.authorization!.envelope).payload, "base64").toString()).predicate as ReceiptPredicate;
    expect(authorized.approval!.envelope).toEqual(visible.approval!.envelope);
    // Without the key, the checks pass as committed. With it, they run on the decrypted envelope and arguments.
    expect(failing(privateBundle)).toEqual([]);
    const keyed = verifyBundle(privateBundle, { ...opts, captureKey: key });
    expect(keyed.checks.filter((c) => !c.ok)).toEqual([]);
    expect(keyed.checks.find((c) => c.name === "approval payload binding")?.detail).toMatch(/principal, agent, tool, full arguments/);
    expect(keyed.checks.find((c) => c.name === "authorization approval was valid")?.detail).toMatch(/must record an approved statement/);
    // A decrypted envelope for other arguments still fails the binding.
    const other = structuredClone(base);
    other.request.args.recipient = "acct_43";
    other.request.argsDigest = digestOf(other.request.args);
    expect(verifyBundle(await privateIssuer.issue(other), { ...opts, captureKey: key }).checks.filter((c) => !c.ok).map((c) => c.name)).toContain("approval payload binding");
  });

  it("keeps the action fields and the unsalted argument digest out of a digest-mode receipt", async () => {
    const privateIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules: { "stripe.refund": { args: { mode: "digest" as const } } } } });
    const p = structuredClone(base);
    p.request.args.recipient = "IBAN-GB29-SECRET";
    p.request.argsDigest = digestOf(p.request.args);
    p.approval!.envelope = dsseCountersign(createApproval(human, { ...binding, args: p.request.args, issuedAt: at, expiresAt: new Date(Date.parse(at) + 3600_000).toISOString() }), secondHuman);
    const text = Buffer.from((await privateIssuer.issue(p)).envelope.payload, "base64").toString();
    // The envelope payload is base64 inside the statement: look at it decoded, as a reader of the receipt would.
    const shown = (JSON.parse(text).predicate as ReceiptPredicate).approval!.envelope?.payload;
    const decoded = shown ? Buffer.from(shown, "base64").toString() : "";
    for (const view of [text, decoded]) {
      expect(view).not.toContain("IBAN-GB29-SECRET");
      expect(view).not.toContain(digestOf(p.request.args));
    }
    // The signed approval payload carries both. It is the reason to withhold the envelope.
    expect(Buffer.from(p.approval!.envelope!.payload, "base64").toString()).toContain(digestOf(p.request.args));
    expect(Buffer.from(p.approval!.envelope!.payload, "base64").toString()).toContain("IBAN-GB29-SECRET");
  });

  it("withholds the refusal reason of an approval under a private rule", async () => {
    const privateIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules: { "stripe.refund": { args: { mode: "digest" as const } } } } });
    const p = structuredClone(base);
    p.approval = { requiredApprovers: 2, checkedAt: at, status: "denied", reason: "approval amount does not match this call", approverKeyids: [], provenance: "observed" };
    p.policy!.decision = "deny";
    p.execution = { status: "denied", reason: "approval rejected", provenance: "observed" };
    const privateBundle = await privateIssuer.issue(p);
    const visible = JSON.parse(Buffer.from(privateBundle.envelope.payload, "base64").toString()).predicate as ReceiptPredicate;
    expect(visible.approval!.reason).toEqual(expect.objectContaining({ $custody: "withheld" }));
    expect(failing(privateBundle, { ...opts, approvalKeys: [] })).toEqual([]);
  });

  it.each([["in clear", undefined], ["under a private args rule", { "stripe.refund": { args: { mode: "digest" as const } } }]])("passes a refusal that holds a valid approval without approval keys, %s", async (_name, rules) => {
    const refusingIssuer = rules ? createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules } }) : issuer;
    for (const execution of [
      { status: "denied" as const, reason: "policy denied the action", provenance: "observed" as const },
      { status: "withheld" as const, reason: "the grant was revoked after the approval was consumed", provenance: "observed" as const },
    ]) {
      const p = structuredClone(base);
      p.policy!.decision = execution.status === "denied" ? "deny" : "allow";
      p.execution = execution;
      expect(failing(await refusingIssuer.issue(p), { ...opts, approvalKeys: [] })).toEqual([]);
    }
    // The same record on a forwarded call needs the keys. Under a private rule the envelope is a commitment: nothing to check.
    const forwardedFailing = failing(await refusingIssuer.issue(structuredClone(base)), { ...opts, approvalKeys: [] });
    if (rules) expect(forwardedFailing).toEqual([]);
    else expect(forwardedFailing).toContain("approval signatures (human keys)");
  });

  it("passes the approval binding as committed when the arguments are withheld, as the args digest does", async () => {
    const privateIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules: { "stripe.refund": { args: { mode: "digest" as const } } } } });
    const p = structuredClone(base);
    p.approval!.envelope = dsseCountersign(createApproval(human, { ...binding, issuedAt: at, expiresAt: new Date(Date.parse(at) + 3600_000).toISOString() }), secondHuman);
    expect(failing(await privateIssuer.issue(p))).toEqual([]);
  });

  it("keeps an approved envelope in clear beside arguments in clear, and fails one that is withheld there", async () => {
    // args whole in clear, result private: the binding must still run
    const rules = { "stripe.refund": { args: { mode: "clear" as const }, result: { mode: "digest" as const } } };
    const clearArgsIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules } });
    const honest = await clearArgsIssuer.issue(structuredClone(base));
    const visible = JSON.parse(Buffer.from(honest.envelope.payload, "base64").toString()).predicate as ReceiptPredicate;
    expect(visible.approval!.envelope).toEqual(approval);
    expect(visible.capture!.withheld.some((w) => w[0] === "approval")).toBe(false);
    expect(verifyBundle(honest, opts).checks.find((c) => c.name === "approval payload binding")?.ok).toBe(true);
    // a crafted issuer withholds the envelope to skip the binding check
    const crafted = structuredClone(visible);
    crafted.approval!.envelope = withhold(approval).commitment as never;
    crafted.capture!.withheld.push(["approval", "envelope"]);
    const skipped = await issuer.issue(crafted);
    expect(failing(skipped)).toContain("approval signatures (human keys)");
    // the same receipt with the arguments withheld too is the private receipt, which passes as committed
    const privateIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules: { "stripe.refund": { args: { mode: "digest" as const } } } } });
    expect(failing(await privateIssuer.issue(structuredClone(base)))).toEqual([]);
  });

  it("fails a precommit that withholds the envelope beside arguments in clear, even when the receipt carries the same commitment", async () => {
    const commitment = withhold(approval).commitment;
    const note = { mode: "digest" as const, withheld: [["approval", "envelope"]] };
    const p = structuredClone(base);
    const { execution, session, model, ...head } = p;
    const sealedApproval = { ...record, envelope: commitment as never };
    p.authorization = await issuer.authorize({ ...head, approval: sealedApproval, capture: note });
    p.approval = sealedApproval;
    p.capture = note;
    const names = failing(await issuer.issue(p));
    expect(names).toContain("authorization approval was valid");
    expect(names).not.toContain("authorization carries this approval");
  });

  it("keeps an envelope in clear when the authorization showed it and the approval was then refused at forward time", async () => {
    const rules = { "stripe.refund": { args: { mode: "clear" as const }, result: { mode: "digest" as const } } };
    const clearArgsIssuer = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules } });
    const p = structuredClone(base);
    const { execution, session, model, ...head } = p;
    p.authorization = await clearArgsIssuer.authorize(head);
    p.approval = { ...record, status: "denied", reason: "approval has expired", approverKeyids: [] };
    p.execution = { status: "withheld", reason: "approval rejected before the call was forwarded: approval has expired", provenance: "observed" };
    const refused = await clearArgsIssuer.issue(p);
    const visible = JSON.parse(Buffer.from(refused.envelope.payload, "base64").toString()).predicate as ReceiptPredicate;
    expect(visible.approval!.envelope).toEqual(approval);
    expect(isCommitment(visible.approval!.reason)).toBe(true);
    expect(failing(refused, { ...opts, approvalKeys: [] })).toEqual([]);
  });

  it("keeps an envelope in clear when a private args rule withholds nothing for this call, and withholds it for a masked tool name", async () => {
    const listed = createIssuer(issuerKey, fx.receiptsDir, fx.logFile, { capture: { rules: { "stripe.refund": { args: { mode: "digest" as const, clear: Object.keys(args) } } } } });
    const bundle = await listed.issue(structuredClone(base));
    const visible = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()).predicate as ReceiptPredicate;
    expect(visible.capture?.withheld.some((w) => w[0] === "request" && w[1] === "args")).toBeFalsy();
    expect(visible.approval!.envelope).toEqual(approval);
    expect(verifyBundle(bundle, opts).checks.find((c) => c.name === "approval payload binding")?.ok).toBe(true);
    // the tool name is masked as text the agent chose, and the envelope signs that real name
    const masked = JSON.parse(Buffer.from((await listed.issue(structuredClone(base), { unknownTool: true })).envelope.payload, "base64").toString()).predicate as ReceiptPredicate;
    expect(masked.tool.name).toBe("(unknown tool)");
    expect(isCommitment(masked.approval!.envelope)).toBe(true);
  });

  it("does not require human keys for the precommit of a call that was withheld after the approval was consumed", async () => {
    const p = structuredClone(base);
    const { execution, session, model, ...head } = p;
    p.authorization = await issuer.authorize(head);
    p.execution = { status: "withheld", reason: "the delegation grant was revoked before the call was forwarded", provenance: "observed" };
    expect(failing(await issuer.issue(p), { ...opts, approvalKeys: [] })).toEqual([]);
    // the same record on a forwarded call needs the keys
    const forwardedPrecommit = structuredClone(base);
    forwardedPrecommit.authorization = p.authorization;
    expect(failing(await issuer.issue(forwardedPrecommit), { ...opts, approvalKeys: [] })).toContain("authorization approval was valid");
  });

  it.each(["checkedAt", "consumedAt"] as const)("rejects an approval time without an offset: %s", async (field) => {
    // Date.parse reads such a time as local time, so the window checks would depend on the verifier's time zone.
    for (const time of [at.replace("Z", ""), at.replace("T", " "), at.slice(0, 16)]) {
      const p = structuredClone(base);
      p.approval![field] = time;
      expect(failing(await issuer.issue(p))).toContain("structural parts in clear");
    }
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
