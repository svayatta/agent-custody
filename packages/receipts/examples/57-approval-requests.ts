// Aspect: human in the loop over signed approvals. Source: src/approval-requests.ts, src/gateway.ts, src/cli.ts
// Run:    node examples/57-approval-requests.ts
//
// The agent sends a refund that needs a person's approval, with no approval attached. The gateway refuses it and
// leaves a request. The approver lists the requests, reads the exact arguments, and signs with their own key from the
// command line. The agent sends the same call again and it is forwarded, once. Changing the amount is a new request.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { APPROVAL_REQUEST_META_KEY } from "../src/approval-requests.ts";
import { loadConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import type { ReceiptBundle } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("57-approval-requests"));
const approver = writeKeyPair(generateKeyPair(), join(fx.dir, "keys"), "approver");
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.approvals = { trustedKeys: [approver.pubFile], usedDir: "approvals-used", maxLifetimeSeconds: 900, requests: { dir: "approval-requests" }, tools: [{ tool: "stripe.refund" }] };
writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
const gateway = await createGateway(loadConfig(fx.configFile));
const refund = (amount: number) => gateway.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount, currency: "GBP" } });
const text = (r: { content?: unknown }) => (r.content as { text: string }[])[0]!.text;
const approvals = (...a: string[]) => {
  const r = spawnSync(process.execPath, [join(import.meta.dirname, "../src/cli.ts"), "approvals", ...a, "--config", fx.configFile], { encoding: "utf8", timeout: 30_000 });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
};

try {
  step(1, "the agent asks for a £25.00 refund with no approval: refused, and a request is left for a person");
  const first = await refund(2500);
  const { requestId } = first._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string };
  console.log(`   ${text(first)}`);
  assert.equal(first.isError, true);

  step(2, "the approver lists what is waiting and reads the exact arguments they are asked to sign");
  console.log(`   ${approvals("list")}`);
  const shown = JSON.parse(approvals("show", requestId)) as { arguments: unknown };
  console.log(`   arguments: ${JSON.stringify(shown.arguments)}`);

  step(3, "they sign it with their own key, for five minutes; the key never leaves their machine");
  console.log(`   ${approvals("approve", requestId, "--key", approver.keyFile, "--expires", "5m")}`);

  step(4, "the agent sends the same call again: forwarded once, and the receipt carries the approval");
  const second = await refund(2500);
  assert.equal(second.isError, undefined, text(second));
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(second._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  const verified = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], approvalKeys: [loadPublicKey(approver.pubFile)], logFile: fx.logFile });
  assert.equal(verified.ok, true, JSON.stringify(verified.checks.filter((c) => !c.ok)));
  console.log(`   forwarded; receipt ${String(second._meta?.[RECEIPT_META_KEY])} verifies, with the approver's key`);

  step(5, "the same call a third time, and the same refund for £25.01: both refused, each waiting for a person again");
  const third = await refund(2500);
  const changed = await refund(2501);
  console.log(`   third:   ${text(third)}`);
  console.log(`   changed: ${text(changed)}`);
  assert.equal(third.isError, true);
  assert.equal(changed.isError, true);
  assert.notEqual((changed._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string }).requestId, requestId);

} finally {
  await gateway.close();
}
console.log("\nOK");
