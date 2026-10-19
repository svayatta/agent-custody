// Aspect: recovery after a support agent acts on a wrong plan; this version is scripted and offline.
// Live Codex version: node examples/codex-recovery/run.ts run (see codex-recovery/README.md).
// Run: node examples/08-support-recovery.ts (after `bun run build` at the repository root).
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digestOf } from "@agent-custody/receipts";
import { call, correct, CUSTOMER, inspect, openGateway, prepare, recover, saveJson, SPACE } from "./codex-recovery/scenario.ts";

const dir = join(mkdtempSync(join(tmpdir(), "support-recovery-")), "case");
console.log("1. CRM import records the wrong plan. This run uses scripted calls, not a model.");
await prepare(dir);
const agent = await openGateway(dir, "agent");
try {
  await call(agent, "memory.read", { subject: CUSTOMER });
  await call(agent, "memory.write", { subject: CUSTOMER, predicate: "discount_percent", value: 20, space: SPACE });
  await call(agent, "memory.write", { subject: CUSTOMER, predicate: "support_tier", value: "priority", space: SPACE });
  await call(agent, "billing.credit", { customer_id: CUSTOMER, incident_id: "INC-42", amount: 2500 });
} finally { await agent.close(); }
console.log("2. Operator corrects the plan and retires the support grant.");
await correct(dir);
const plan = await inspect(dir);
assert.equal(plan.retractFacts.length, 2);
assert.equal(plan.reverseCredits.length, 1);
assert.equal(plan.exposed, true);
saveJson(join(dir, "recovery-plan.json"), plan);
console.log("3. Demo operator explicitly approves the plan; recovery uses its own grant.");
const report = await recover(dir, digestOf(plan));
assert.equal(report.ok, true);
assert.equal(report.billing.credits[0]?.status, "reversed");
assert.equal(report.current.length, 3);
console.log(`4. ${report.receiptsVerified} receipts verify. Current plan is free, discount is 0, support is standard; simulated credit reversed.`);
console.log("\nOK");
