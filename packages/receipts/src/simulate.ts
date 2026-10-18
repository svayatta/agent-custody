// Offline policy replay. The recorded inputs stay fixed; no tool or fact provider is called.
import { randomUUID } from "node:crypto";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { isCommitment, pathText, restorePaths, under } from "./capture.ts";
import { decodeDelegation, DELEGATION_TYPE, delegationValidAt } from "./delegation.ts";
import { evaluate, policyDigest, type PolicyDecision } from "./policy.ts";
import type { ReceiptPredicate } from "./receipt.ts";
import { structuralProblem } from "./verify.ts";

export interface SimulationChange {
  receiptId: string;
  tool: string;
  /** The recorded Cedar decision, including observe-mode and provenance information. */
  previous: NonNullable<ReceiptPredicate["policy"]>;
  proposed: PolicyDecision;
}

export interface SimulationSkip {
  receiptId: string;
  tool: string;
  reason: string;
}

export interface SimulationGroup {
  tool: string;
  /** The proposed policy's determining policy ids and evaluation errors. */
  reason: string;
  receiptIds: string[];
}

export interface SimulationReport {
  runId: string;
  timestamp: string;
  policyDigest: string;
  previousPolicyDigests: string[];
  total: number;
  evaluated: number;
  unchanged: number;
  complete: boolean;
  changes: SimulationChange[];
  skipped: SimulationSkip[];
  /** Changed decisions, grouped by tool and the proposed reason. */
  groups: SimulationGroup[];
}

const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
const order = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

/** A gateway can deny before Cedar runs. Such a denial cannot be changed by replacing Cedar text. */
function gateProblem(p: ReceiptPredicate): string | null {
  if (p.issuer.kind !== "gateway") return null;
  // A failed gatherFacts never assigns its partial result to the receipt. With private errors, no facts, and no
  // determining policy ids, an evaluation error and missing lookup inputs are indistinguishable. Observe mode may
  // even have executed this call, so execution status cannot establish whether Cedar ran.
  if (p.policy?.decision === "deny" && isCommitment(p.policy.errors) && Object.keys(p.facts).length === 0 && p.policy.reasons.length === 0) {
    return "original failure details are withheld; cannot establish complete Cedar inputs";
  }
  // The decision is the baseline. A grant revoked after Cedar ran can withhold execution, but does not invalidate
  // the recorded policy inputs or turn that allow into an early gate denial.
  const messages = Array.isArray(p.policy?.errors) ? p.policy.errors : [];
  const gate = messages.find((s) => /^delegation grant /s.test(s)
    || /^tool ".*" is not in the delegation scopes$/s.test(s)
    || /^fact argument ".*" needs call argument ".*", which is missing$/s.test(s)
    || /^fact ".*" lookup via .* failed:/s.test(s));
  return gate ? `non-policy gate: ${gate}` : null;
}

/**
 * Compare a proposed Cedar policy with recorded policy decisions, using each receipt's original arguments, fact
 * values, agent, and (for gateways) grant context. Observe-mode decisions are the baseline even when the call ran.
 * Receipts are not signature-verified here; verify their bundles separately when their authenticity matters.
 * Missing inputs and non-Cedar gate failures are reported as skipped, never guessed or fetched again.
 */
export function simulatePolicy(policyText: string, receipts: ReceiptPredicate[]): SimulationReport {
  const parsed = cedar.checkParsePolicySet({ staticPolicies: policyText });
  if (parsed.type === "failure") throw new Error(`invalid Cedar policy: ${parsed.errors.map((e) => e.message).join("; ")}`);
  const report: SimulationReport = {
    runId: randomUUID(),
    timestamp: new Date().toISOString(),
    policyDigest: policyDigest(policyText),
    previousPolicyDigests: [],
    total: receipts.length,
    evaluated: 0,
    unchanged: 0,
    complete: true,
    changes: [],
    skipped: [],
    groups: [],
  };
  const digests = new Set<string>();
  for (const original of receipts) {
    const receiptId = typeof original?.receiptId === "string" ? original.receiptId : "(unknown receipt)";
    const tool = typeof original?.tool?.name === "string" ? original.tool.name : "(unknown tool)";
    const skip = (reason: string) => { report.skipped.push({ receiptId, tool, reason }); };
    const broken = structuralProblem(original);
    if (broken) { skip(`malformed receipt: ${broken}`); continue; }
    if (original.policy === null) { skip("no recorded policy decision (record-only receipt)"); continue; }
    const previous = original.policy;
    if (typeof previous.policyDigest !== "string" || !previous.policyDigest || !strings(previous.reasons)
      || (!strings(previous.errors) && !(isCommitment(previous.errors) && original.capture?.withheld.some((p) => p.length === 2 && p[0] === "policy" && p[1] === "errors")))
      || (previous.enforced !== undefined && typeof previous.enforced !== "boolean")) {
      skip("malformed receipt: recorded policy metadata is invalid"); continue;
    }
    digests.add(previous.policyDigest);
    if (!receiptId || !tool || typeof original.agent.id !== "string" || !original.agent.id
      || !Number.isFinite(Date.parse(original.timestamp)) || !["sdk", "gateway"].includes(original.issuer.kind)) {
      skip("malformed receipt: receipt id, tool, agent, timestamp, or issuer is invalid"); continue;
    }
    const restored = restorePaths(original, original.capture);
    if (restored.problems.length) {
      skip(`malformed capture: ${restored.problems.map((p) => p.error).join("; ")}`); continue;
    }
    const missing = restored.missing.filter((p) => under(p, ["request", "args"]) || (p[0] === "facts" && p[2] === "value"));
    if (missing.length) { skip(`required policy inputs are withheld: ${missing.map(pathText).join(", ")}`); continue; }
    const p = restored.predicate;
    if (tool === "(unknown tool)" && p.issuer.kind === "gateway" && p.capture) {
      skip("the original tool name is unavailable under the capture rule"); continue;
    }
    if (Object.values(p.facts).some((f) => !Object.hasOwn(f, "value") || f.value === undefined)) {
      skip("malformed receipt: a recorded fact has no value"); continue;
    }
    const gate = gateProblem(p);
    if (gate) { skip(gate); continue; }
    const context: Record<string, unknown> = {
      args: p.request.args,
      facts: Object.fromEntries(Object.entries(p.facts).map(([name, fact]) => [name, fact.value])),
    };
    if (p.issuer.kind === "gateway") {
      const envelope = p.delegation?.envelope;
      const grant = envelope?.payloadType === DELEGATION_TYPE ? decodeDelegation(envelope) : null;
      if (!grant || grant.agent !== p.agent.id || grant.principal !== p.principal.id) {
        skip("the recorded delegation context is missing, malformed, or does not name this agent and principal"); continue;
      }
      if (!grant.scopes.includes(tool)) { skip("the tool is outside the recorded delegation scopes"); continue; }
      if (!delegationValidAt(grant, p.timestamp)) { skip("the recorded delegation was outside its validity window at receipt time"); continue; }
      context.grant = { principal: grant.principal, scopes: grant.scopes };
    }
    let proposed: PolicyDecision;
    try {
      proposed = evaluate(policyText, { agentId: p.agent.id, tool, context });
    } catch (e) {
      // An evaluator exception is a deny, just as at the gateway; it must never become an allow in a replay.
      proposed = { decision: "deny", reasons: [], errors: [e instanceof Error ? e.message : String(e)], policyDigest: report.policyDigest };
    }
    report.evaluated++;
    if (proposed.decision === previous.decision) report.unchanged++;
    else report.changes.push({ receiptId, tool, previous, proposed });
  }
  report.previousPolicyDigests = [...digests].sort(order);
  report.complete = report.skipped.length === 0;
  const groups = new Map<string, SimulationGroup>();
  for (const change of report.changes) {
    const reason = [...new Set([...change.proposed.reasons, ...change.proposed.errors])].sort(order).join("; ") || "no permit policy matched";
    const key = JSON.stringify([change.tool, reason]);
    const group = groups.get(key) ?? { tool: change.tool, reason, receiptIds: [] };
    group.receiptIds.push(change.receiptId);
    groups.set(key, group);
  }
  report.groups = [...groups.values()].sort((a, b) => order(a.tool, b.tool) || order(a.reason, b.reason));
  for (const group of report.groups) group.receiptIds.sort(order);
  return report;
}

export function formatSimulation(report: SimulationReport): string {
  const changes = new Map(report.changes.map((c) => [JSON.stringify([c.tool, c.receiptId]), c]));
  const lines = [
    `Policy simulation ${report.runId}`,
    `Timestamp: ${report.timestamp}`,
    `Proposed policy: ${report.policyDigest}`,
    `Previous policies: ${report.previousPolicyDigests.join(", ") || "none"}`,
    `Receipts: ${report.total}; evaluated: ${report.evaluated}; unchanged: ${report.unchanged}; changed: ${report.changes.length}; skipped: ${report.skipped.length}`,
  ];
  for (const group of report.groups) {
    lines.push("", `${group.tool}: ${group.reason}`);
    for (const receiptId of group.receiptIds) {
      const change = changes.get(JSON.stringify([group.tool, receiptId]))!;
      lines.push(`  ${receiptId}: ${change.previous.decision} -> ${change.proposed.decision}`);
    }
  }
  for (const skipped of report.skipped) lines.push(`SKIPPED ${skipped.receiptId} (${skipped.tool}): ${skipped.reason}`);
  lines.push("", report.complete ? "RESULT: COMPLETE" : "RESULT: INCOMPLETE");
  return lines.join("\n");
}
