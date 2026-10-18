// Aspect: tightening a policy against observed history. Source: src/simulate.ts, src/cli.ts
// Run:    node examples/28-policy-simulation.ts
//
// Observe three refunds, stop the gateway, and replay their signed receipts against a lower limit. The replay
// needs no upstream: the customer facts and the delegation come from each receipt, as they were at call time.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { loadConfig } from "../src/config.ts";
import { policyDigest } from "../src/policy.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import type { SimulationReport } from "../src/simulate.ts";
import { buildFixture, POLICY } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("28-policy-simulation"));
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.mode = "observe";
writeFileSync(fx.configFile, JSON.stringify(cfg));

step(1, "observe three refunds under the original 100000 limit");
const gateway = await createGateway(loadConfig(fx.configFile));
const ids: string[] = [];
try {
  for (const amount of [2500, 7500, 5000000]) {
    const result = await gateway.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount } });
    if (result.isError) throw new Error("observe mode should forward this in-scope call");
    const id = String(result._meta?.[RECEIPT_META_KEY]);
    ids.push(id);
    console.log(`   amount ${amount}: executed, receipt ${id}`);
  }
} finally {
  await gateway.close();
}

step(2, "stop the gateway and propose a 5000 limit; replay only the recorded evidence");
const proposed = `permit(principal, action == Action::"stripe.refund", resource)
when {
  context.args.amount <= 5000 &&
  context.facts.customer.verified == true &&
  context.grant.principal == "user_456" &&
  context.grant.scopes.contains("stripe.refund")
};
`;
const policyFile = join(fx.dir, "proposed.cedar");
const reportFile = join(fx.dir, "simulation.json");
writeFileSync(policyFile, proposed);
const cli = spawnSync(process.execPath, [
  resolve(import.meta.dirname, "..", "src", "cli.ts"), "policy", "simulate",
  "--policy", policyFile, "--receipts", fx.receiptsDir,
  "--issuer-key", fx.gatewayPub, "--principal-key", fx.principalPub,
  "--out", reportFile,
], { encoding: "utf8" });
if (cli.status !== 0) throw new Error(cli.stderr || cli.stdout);
console.log(cli.stdout.trim());

step(3, "only the 7500 refund changes: the 5000000 refund was already a recorded deny in observe mode");
const report = JSON.parse(readFileSync(reportFile, "utf8")) as SimulationReport;
if (!report.complete || report.evaluated !== 3 || report.unchanged !== 2 || report.changes.length !== 1 || report.changes[0]?.receiptId !== ids[1]) throw new Error("unexpected replay decisions");
if (report.policyDigest !== policyDigest(proposed) || report.policyDigest === policyDigest(POLICY) || !report.previousPolicyDigests.includes(policyDigest(POLICY))) throw new Error("simulation must pin the proposed and original policy digests");
console.log(`   run ${report.runId}: proposed policy ${report.policyDigest}`);
console.log(`   saved ${reportFile}`);
console.log("\nOK");
