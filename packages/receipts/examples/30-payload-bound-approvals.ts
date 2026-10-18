// Aspect: payload-bound human approvals. Source: src/approval.ts, src/gateway.ts, src/verify.ts
// Run:    node examples/30-payload-bound-approvals.ts
//
// Two approvers sign the exact refund, independently of the agent's delegation. Changed amounts, recipients,
// and extra arguments cannot borrow that approval. The gateway burns the id before forwarding and refuses
// its replay. Refused calls remain verifiable evidence of refusal; they do not authorize the bad approval.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { APPROVAL_META_KEY, createApproval, verifyApproval } from "../src/approval.ts";
import { loadConfig } from "../src/config.ts";
import { dsseCountersign, generateKeyPair, loadPublicKey, writeKeyPair, type Envelope } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("30-payload-bound-approvals"));
const first = generateKeyPair();
const second = generateKeyPair();
const firstFiles = writeKeyPair(first, join(fx.dir, "keys"), "approver");
const secondFiles = writeKeyPair(second, join(fx.dir, "keys"), "second-approver");
const approvalKeys = [loadPublicKey(firstFiles.pubFile), loadPublicKey(secondFiles.pubFile)];
const fields = { beneficiary: "customer_id" };
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.approvals = {
  trustedKeys: [firstFiles.pubFile, secondFiles.pubFile],
  usedDir: "approvals-used",
  tools: [{ tool: "stripe.refund", minApprovers: 2, fields }],
};
cfg.precommit = ["stripe.refund"];
writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
const keys = {
  issuerKeys: [loadPublicKey(fx.gatewayPub)],
  principalKeys: [loadPublicKey(fx.principalPub)],
  upstreamKeys: [loadPublicKey(fx.upstreamPub)],
  approvalKeys,
  logFile: fx.logFile,
};
const args = { customer_id: "cust_123", amount: 2500, currency: "GBP", note: "refund for order 42" };
const binding = { principal: "user_456", agent: "support-agent", tool: "stripe.refund", args, fields };
const now = Date.now();
const oneSignature = createApproval(first, { ...binding, issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 300_000).toISOString() });
const approved = dsseCountersign(oneSignature, second);
const expired = dsseCountersign(createApproval(first, {
  ...binding, issuedAt: new Date(now - 120_000).toISOString(), expiresAt: new Date(now - 60_000).toISOString(),
}), second);
const gateway = await createGateway(loadConfig(fx.configFile));

const call = async (callArgs: Record<string, unknown>, envelope?: Envelope) => {
  const result = await gateway.handleCall({
    name: "stripe.refund", arguments: callArgs,
    ...(envelope ? { _meta: { [APPROVAL_META_KEY]: envelope } } : {}),
  });
  const id = String(result._meta?.[RECEIPT_META_KEY]);
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
  const predicate = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
  const verified = verifyBundle(bundle, keys);
  assert.equal(verified.ok, true, JSON.stringify(verified.checks.filter((check) => !check.ok)));
  return { result, bundle, predicate };
};

try {
  step(1, "the gateway requires two trusted signatures for a refund; customer_id is the beneficiary");
  console.log("   approved: GBP 2500 minor units for cust_123, plus the complete arguments including the note");
  assert.equal(verifyApproval(approved, approvalKeys, binding, { minApprovers: 2 }).ok, true);

  step(2, "missing approval and one signature are refused before the refund can run");
  for (const [label, envelope] of [["missing", undefined], ["one signer", oneSignature]] as const) {
    const { predicate } = await call(args, envelope);
    assert.equal(predicate.execution.status, "denied");
    console.log(`   ${label}: ${predicate.execution.status}; refusal receipt verifies`);
  }

  step(3, "the same signed envelope cannot approve a changed amount, beneficiary, or extra argument");
  for (const [label, changed] of [
    ["amount", { ...args, amount: 5000 }],
    ["beneficiary", { ...args, customer_id: "cust_999" }],
    ["extra argument", { ...args, expedite: true }],
  ] as const) {
    const { predicate } = await call(changed, approved);
    assert.equal(predicate.execution.status, "denied");
    console.log(`   changed ${label}: ${predicate.execution.status}; refusal receipt verifies`);
  }

  step(4, "an expired approval is refused even though both signatures are valid");
  const stale = await call(args, expired);
  assert.equal(stale.predicate.execution.status, "denied");
  console.log(`   ${stale.predicate.execution.status}; refusal receipt verifies`);

  step(5, "the exact approved action passes the grant, approval, and Cedar gates and is pre-committed");
  const executed = await call(args, approved);
  assert.equal(executed.predicate.execution.status, "executed");
  assert.equal(executed.predicate.approval?.approverKeyids.length, 2);
  assert.ok(executed.predicate.approval?.consumedAt);
  assert.ok(executed.predicate.authorization);
  console.log(`   ${executed.predicate.execution.status}; two approvers, consumed id, authorization and receipt verify`);
  assert.equal(verifyBundle(executed.bundle, { ...keys, approvalKeys: [] }).ok, false);
  console.log("   without separately trusted human keys, the execution does not verify");

  step(6, "replaying that approval does not forward a second refund");
  const replay = await call(args, approved);
  assert.ok(replay.predicate.execution.status === "denied" || replay.predicate.execution.status === "withheld");
  assert.match((replay.result.content[0] as { text: string }).text, /already|used/i);
  console.log(`   ${replay.predicate.execution.status}; signed refusal receipt verifies`);
} finally {
  await gateway.close();
}
console.log("\nOK");
