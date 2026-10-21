// Real MCP subprocesses and the same recovery path as the live demo; never calls a model or the network.
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { digestOf } from "@agent-custody/receipts";
import { call, correct, CUSTOMER, inspect, openGateway, prepare, recover, resultValue, saveJson, SPACE, verifiedReceipts, verifyRecovery } from "../examples/codex-recovery/scenario.ts";
import { readBilling } from "../examples/codex-recovery/billing.ts";

async function fixture(exposed = true) {
  const dir = join(mkdtempSync(join(tmpdir(), "codex-recovery-test-")), "case");
  await prepare(dir);
  const agent = await openGateway(dir, "agent");
  try {
    if (exposed) await call(agent, "memory.read", { subject: CUSTOMER });
    await call(agent, "memory.write", { subject: CUSTOMER, predicate: "discount_percent", value: 20, space: SPACE });
    const args = { customer_id: CUSTOMER, incident_id: "INC-42", amount: 2500 };
    const one = resultValue<{ credit: { id: string } }>(await call(agent, "billing.credit", args));
    const two = resultValue<{ credit: { id: string } }>(await call(agent, "billing.credit", args));
    expect(two.credit.id).toBe(one.credit.id);
    const forbidden = await agent.handleCall({ name: "memory.retract", arguments: { factId: "anything", reason: "hide the evidence" } });
    expect(forbidden.isError).toBe(true);
    const overwrite = await agent.handleCall({ name: "memory.write", arguments: { subject: CUSTOMER, predicate: "plan", value: "free", space: SPACE } });
    expect(overwrite.isError).toBe(true);
  } finally { await agent.close(); }
  await correct(dir);
  return dir;
}

describe("support recovery demo", () => {
  it("requires approval, retires the support grant, compensates once, and verifies actual store state against receipts", async () => {
    const dir = await fixture();
    await expect(openGateway(dir, "agent")).rejects.toThrow("revoked");
    const plan = await inspect(dir);
    expect(plan.retractFacts.map(f => f.predicate)).toEqual(["discount_percent"]);
    expect(plan.reverseCredits).toHaveLength(1);
    expect(plan.exposed).toBe(true);
    saveJson(join(dir, "recovery-plan.json"), plan);
    await expect(recover(dir, "wrong")).rejects.toThrow("Approval");
    expect(readBilling(dir).credits[0]?.status).toBe("active");
    const report = await recover(dir, digestOf(plan));
    expect(report.ok).toBe(true);
    expect(report.current.map(f => [f.predicate, f.value])).toEqual([["plan", "free"], ["discount_percent", 0]]);
    expect(report.billing.credits).toHaveLength(1);
    expect(report.billing.credits[0]?.status).toBe("reversed");
    const receipts = verifiedReceipts(dir);
    expect(receipts.filter(r => r.tool.name === "billing.reverseCredit" && r.execution.status === "executed")).toHaveLength(1);
    expect(receipts.some(r => r.execution.status === "denied")).toBe(true);
    // Altering the mutable billing file cannot masquerade as verified recovery.
    const state = readBilling(dir);
    state.credits[0]!.amount = 1;
    saveJson(join(dir, "billing.json"), state);
    await expect(inspect(dir)).rejects.toThrow("differs from its receipt");
  });

  it("lists the corrective writes again after a partial recovery, and verify refuses until they exist", async () => {
    const dir = await fixture();
    const first = await inspect(dir);
    expect(first.writeFacts).toEqual([{ predicate: "discount_percent", value: 0 }]);
    // The operator retracts the wrong fact and reverses the credit; the process stops before the corrective write.
    const operator = await openGateway(dir, "operator");
    try {
      await call(operator, "memory.retract", { factId: first.retractFacts[0]!.factId, reason: "partial recovery" });
      await call(operator, "billing.reverseCredit", { credit_id: first.reverseCredits[0]!.id, reason: "partial recovery" });
    } finally { await operator.close(); }
    const refreshed = await inspect(dir);
    expect(refreshed.retractFacts).toEqual([]);
    expect(refreshed.writeFacts).toEqual(first.writeFacts);
    await expect(verifyRecovery(dir)).rejects.toThrow("Recovery incomplete");
    saveJson(join(dir, "recovery-plan.json"), refreshed);
    const report = await recover(dir, digestOf(refreshed));
    expect(report.current.map(f => [f.predicate, f.value])).toEqual([["plan", "free"], ["discount_percent", 0]]);
  });

  it("rejects a stale approval and altered receipt before making recovery calls", async () => {
    const dir = await fixture();
    const plan = await inspect(dir);
    saveJson(join(dir, "recovery-plan.json"), plan);
    const operator = await openGateway(dir, "operator");
    try { await call(operator, "billing.account", { customer_id: CUSTOMER }); }
    finally { await operator.close(); }
    await expect(recover(dir, digestOf(plan))).rejects.toThrow("State changed");
    expect(readBilling(dir).credits[0]?.status).toBe("active");
    const file = readdirSync(join(dir, "receipts")).find(f => f.endsWith(".json") && !f.endsWith(".authorization.json"))!;
    const path = join(dir, "receipts", file);
    const bundle = JSON.parse(readFileSync(path, "utf8"));
    const statement = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString());
    statement.predicate.agent.id = "forged";
    bundle.envelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    writeFileSync(path, JSON.stringify(bundle));
    await expect(inspect(dir)).rejects.toThrow("failed verification");
  });

  it("does not invent a dependency when billing happened without an observed memory read", async () => {
    const dir = await fixture(false);
    await expect(inspect(dir)).rejects.toThrow("no observed dependency");
    expect(readBilling(dir).credits[0]?.status).toBe("active");
  });

  it("reports no agent activity honestly instead of manufacturing an affected action", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "codex-no-action-")), "case");
    await prepare(dir);
    await correct(dir);
    const plan = await inspect(dir);
    expect(plan.agentCalls).toBe(0);
    expect(plan.exposed).toBe(false);
    expect(plan.retractFacts).toEqual([]);
    expect(plan.reverseCredits).toEqual([]);
    expect(plan.notes.join(" ")).toContain("does not demonstrate an agent workflow");
    // A forged validity window must not hide a fact while leaving the signatures unchanged.
    const ledger = join(dir, "ledger.jsonl");
    const events = readFileSync(ledger, "utf8").trim().split("\n").map(line => JSON.parse(line));
    const corrected = events.find(e => e.kind === "assert" && e.fact.value === "free");
    corrected.fact.validTo = corrected.fact.validFrom;
    writeFileSync(ledger, events.map(e => JSON.stringify(e)).join("\n") + "\n");
    await expect(inspect(dir)).rejects.toThrow("validTo");
  });
});
