// Shared by the live Codex demo and an offline integration test. Not a public package API.
import { mkdirSync, readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { createDelegation, createGateway, digestOf, generateKeyPair, grantDigest, loadConfig, loadPublicKey, verifyBundle, writeKeyPair, writeRevokedGrants, type Envelope, type Gateway, type ReceiptBundle, type ReceiptPredicate } from "@agent-custody/receipts";
import { Ledger, blastRadius, loadReceipts } from "../../src/index.ts";
import { readBilling } from "./billing.ts";

export const CUSTOMER = "cust_123";
export const SPACE = "team:support";
export const REASON = "Operator correction: CRM sync bug; the actual plan is free";
export const BENEFITS = { discount_percent: 0, support_tier: "standard" };
export const readJson = <T>(file: string): T => JSON.parse(readFileSync(file, "utf8"));
export const saveJson = (file: string, value: unknown) => writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
export interface Manifest { rootFactId: string; createdAt: string }
export const manifest = (dir: string) => readJson<Manifest>(join(dir, "manifest.json"));
export const openGateway = (dir: string, role: "agent" | "operator") => createGateway(loadConfig(join(dir, `${role}.json`)));

export function resultValue<T>(result: { content: unknown[]; isError?: boolean }): T {
  if (result.isError) throw new Error(JSON.stringify(result.content));
  return JSON.parse((result.content[0] as { text: string }).text);
}
export async function call(gw: Gateway, name: string, args: Record<string, unknown>) {
  const result = await gw.handleCall({ name, arguments: args });
  resultValue(result); // Do not silently proceed after a denied/failed recovery operation.
  return result;
}

export async function prepare(dir: string): Promise<Manifest> {
  mkdirSync(dir, { recursive: false, mode: 0o700 });
  mkdirSync(join(dir, "agent-workspace"));
  writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
  writeKeyPair(generateKeyPair(), join(dir, "keys"), "memory");
  writeKeyPair(generateKeyPair(), join(dir, "keys"), "billing");
  const principal = generateKeyPair();
  writeKeyPair(principal, join(dir, "keys"), "principal");
  saveJson(join(dir, "billing.json"), { customer_id: CUSTOMER, currency: "GBP", credits: [] });
  // Deliberately wrong source data; the model is not told about the sync bug.
  saveJson(join(dir, "crm.json"), { customer_id: CUSTOMER, plan: "enterprise" });
  writeFileSync(join(dir, "policy.cedar"), `
permit(principal == Agent::"recovery-operator", action, resource);
permit(principal == Agent::"codex-support", action == Action::"memory.read", resource)
when { context.args.subject == "cust_123" };
permit(principal == Agent::"codex-support", action == Action::"memory.write", resource)
when { context.args.subject == "cust_123" && context.args.space == "team:support" &&
  ["discount_percent", "support_tier"].contains(context.args.predicate) && !(context.args has supersedes) };
permit(principal == Agent::"codex-support", action == Action::"billing.account", resource)
when { context.args.customer_id == "cust_123" };
permit(principal == Agent::"codex-support", action == Action::"billing.credit", resource)
when { context.args.customer_id == "cust_123" && context.args.incident_id == "INC-42" && context.args.amount > 0 && context.args.amount <= 2500 };
`);
  const common = {
    identity: { keyFile: "keys/gateway.key" },
    upstreams: [
      { name: "memory", command: process.execPath, args: [resolve(import.meta.dirname, "../../src/cli.ts"), "serve", "--ledger", join(dir, "ledger.jsonl"), "--key", join(dir, "keys/memory.key")] },
      { name: "billing", command: process.execPath, args: [join(import.meta.dirname, "billing.ts"), "--dir", dir] },
    ],
    trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl",
    precommit: ["billing.credit", "billing.reverseCredit"], revokedGrants: "revoked.json",
  };
  const now = Date.now();
  for (const role of ["agent", "operator"] as const) {
    const scopes = role === "agent" ? ["memory.read", "memory.write", "billing.account", "billing.credit"] : ["memory.read", "memory.write", "memory.retract", "billing.account", "billing.reverseCredit"];
    const grant = createDelegation(principal, { version: "0.1", principal: "demo-operator", agent: role === "agent" ? "codex-support" : "recovery-operator", scopes, issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 24 * 3600_000).toISOString() });
    saveJson(join(dir, `${role}-grant.json`), grant);
    saveJson(join(dir, `${role}.json`), { ...common, grantFile: `${role}-grant.json` });
  }
  const gw = await openGateway(dir, "operator");
  try {
    const crm = readJson<{ plan: string }>(join(dir, "crm.json"));
    const written = resultValue<{ fact: { factId: string } }>(await call(gw, "memory.write", { subject: CUSTOMER, predicate: "plan", value: crm.plan, space: SPACE }));
    const m = { rootFactId: written.fact.factId, createdAt: new Date().toISOString() };
    saveJson(join(dir, "manifest.json"), m);
    return m;
  } finally { await gw.close(); }
}

/** Verify the evidence before deriving any report or recovery action from it. */
export function verifiedReceipts(dir: string): ReceiptPredicate[] {
  const keys = {
    issuerKeys: [loadPublicKey(join(dir, "keys/gateway.pub"))],
    principalKeys: [loadPublicKey(join(dir, "keys/principal.pub"))],
    upstreamKeys: [loadPublicKey(join(dir, "keys/memory.pub")), loadPublicKey(join(dir, "keys/billing.pub"))],
    logFile: join(dir, "log.jsonl"),
  };
  return readdirSync(join(dir, "receipts")).filter(f => f.endsWith(".json") && !f.endsWith(".authorization.json")).map(f => {
    const check = verifyBundle(readJson<ReceiptBundle>(join(dir, "receipts", f)), keys);
    if (!check.ok || !check.statement) throw new Error(`Receipt ${f} failed verification: ${check.checks.filter(c => !c.ok).map(c => c.name).join(", ")}`);
    return check.statement.predicate;
  }).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

/** Check the mutable demo stores against signed tool results, not just the signatures in isolation. */
async function checkStores(dir: string, receipts: ReceiptPredicate[]) {
  const byId = new Map(receipts.map(r => [r.receiptId, r]));
  const executed = (id: string | null | undefined, tool: string) => {
    const r = id ? byId.get(id) : undefined;
    if (!r || r.tool.name !== tool || r.execution.status !== "executed") throw new Error(`Store has no executed ${tool} receipt: ${id}`);
    return resultValue<Record<string, any>>(r.execution.result as { content: unknown[] });
  };
  const ledger = new Ledger(join(dir, "ledger.jsonl"));
  const facts = await ledger.facts();
  const factIds = new Set(facts.map(f => f.factId));
  const retractions = new Set<string>();
  for (const f of facts) {
    const written = executed(f.source.receiptId, "memory.write").fact;
    // This demo uses retractions, never supersession; validTo must match the original signed write too.
    for (const field of ["factId", "subject", "predicate", "value", "space", "actor", "source", "validFrom", "validTo", "confidence", "provenance"] as const) {
      if (digestOf(f[field]) !== digestOf(written[field])) throw new Error(`Ledger differs from its signed write: ${f.factId} ${field}`);
    }
    for (const e of await ledger.history(f.factId)) {
      if (e.kind === "retract") {
        const recorded = executed(e.source.receiptId, "memory.retract");
        for (const field of ["eventId", "factId", "actor", "reason", "txTime", "source"] as const) {
          if (digestOf(e[field]) !== digestOf(recorded[field])) throw new Error("Retraction differs from its receipt");
        }
        retractions.add(e.eventId);
      }
    }
  }
  const billing = readBilling(dir);
  for (const r of receipts.filter(r => r.execution.status === "executed")) {
    if (r.tool.name === "memory.write") {
      const f = executed(r.receiptId, "memory.write").fact;
      if (!factIds.has(f.factId)) throw new Error("A receipted fact is missing from the ledger");
    }
    if (r.tool.name === "memory.retract" && !retractions.has(executed(r.receiptId, "memory.retract").eventId)) throw new Error("A receipted retraction is missing from the ledger");
    if (r.tool.name === "billing.credit") {
      const c = executed(r.receiptId, "billing.credit").credit;
      if (!billing.credits.some(x => x.id === c.id)) throw new Error("A receipted credit is missing from billing");
    }
  }
  for (const credit of billing.credits) {
    const original = executed(credit.receiptId, "billing.credit").credit;
    if (original.id !== credit.id || original.amount !== credit.amount) throw new Error("Billing credit differs from its receipt");
    if (credit.status === "reversed") {
      const reversal = executed(credit.reversalReceiptId, "billing.reverseCredit").credit;
      if (reversal.id !== credit.id || reversal.status !== "reversed" || reversal.amount !== credit.amount) throw new Error("Billing reversal differs from its receipt");
    }
  }
}

export async function correct(dir: string) {
  // This command is the operator introducing an external correction, not a model discovering the truth.
  const { rootFactId } = manifest(dir);
  await checkStores(dir, verifiedReceipts(dir));
  const gw = await openGateway(dir, "operator");
  try {
    // Retire the support grant before the operator changes state. It cannot add more work during recovery.
    writeRevokedGrants(join(dir, "revoked.json"), [grantDigest(readJson<Envelope>(join(dir, "agent-grant.json")))]);
    saveJson(join(dir, "crm.json"), { customer_id: CUSTOMER, plan: "free" });
    const ledger = new Ledger(join(dir, "ledger.jsonl"));
    if (!(await ledger.history(rootFactId)).some(e => e.kind === "retract")) await call(gw, "memory.retract", { factId: rootFactId, reason: REASON });
    if (!(await ledger.asOf()).some(f => f.predicate === "plan" && f.value === "free")) await call(gw, "memory.write", { subject: CUSTOMER, predicate: "plan", value: "free", space: SPACE });
    saveJson(join(dir, "correction.json"), { reason: REASON, plan: "free" });
  } finally { await gw.close(); }
}

export interface RecoveryPlan {
  rootFactId: string;
  snapshot: string;
  retractFacts: { factId: string; predicate: string; value: unknown }[];
  reverseCredits: { id: string; amount: number; receiptId: string }[];
  writeFacts: { predicate: string; value: unknown }[];
  agentCalls: number;
  exposed: boolean;
  notes: string[];
}

export async function inspect(dir: string): Promise<RecoveryPlan> {
  if (!existsSync(join(dir, "correction.json"))) throw new Error("Run correct first to introduce the operator's correction");
  const receipts = verifiedReceipts(dir);
  await checkStores(dir, receipts);
  const { rootFactId } = manifest(dir);
  const ledger = new Ledger(join(dir, "ledger.jsonl"));
  const b = await blastRadius(ledger, loadReceipts(join(dir, "receipts")), rootFactId);
  if (!b.retraction) throw new Error("The original plan has not been retracted");
  if (b.withheld.length) throw new Error("Incomplete blast radius: consumed fact ids are withheld");
  const current = await ledger.asOf();
  const billing = readBilling(dir);
  const affected = new Set(b.receipts.map(r => r.receiptId));
  const agent = receipts.filter(r => r.agent.id === "codex-support");
  const retractFacts = b.stillBelieved.filter(f => f.actor === "codex-support" && f.subject === CUSTOMER && f.space === SPACE)
    .filter(f => Object.hasOwn(BENEFITS, f.predicate) && f.value !== BENEFITS[f.predicate as keyof typeof BENEFITS])
    .map(f => ({ factId: f.factId, predicate: f.predicate, value: f.value }));
  const reverseCredits = billing.credits.filter(c => c.status === "active" && affected.has(c.receiptId)).map(({ id, amount, receiptId }) => ({ id, amount, receiptId }));
  // Do not silently call an untraced side effect "unaffected". This small demo cannot decide its recovery.
  const untraced = billing.credits.filter(c => c.status === "active" && !affected.has(c.receiptId));
  if (untraced.length) throw new Error("Active credit has no observed dependency on the plan; review it manually before recovery");
  const writeFacts = [...new Set(retractFacts.map(f => f.predicate))].filter(predicate => !current.some(f => f.predicate === predicate && f.value === BENEFITS[predicate as keyof typeof BENEFITS]))
    .map(predicate => ({ predicate, value: BENEFITS[predicate as keyof typeof BENEFITS] }));
  return {
    rootFactId,
    snapshot: digestOf({ facts: current.map(f => [f.factId, f.value]).sort(), billing, receipts: receipts.map(r => r.receiptId).sort() }),
    retractFacts, reverseCredits, writeFacts, agentCalls: agent.length,
    exposed: agent.some(r => Array.isArray(r.consumed?.factIds) && r.consumed.factIds.includes(rootFactId)),
    notes: ["Possible dependencies: observed exposure, not proven reasoning or causation.", "A verified receipt authenticates recorded evidence; it does not establish the truth of the customer plan.", ...(agent.length ? [] : ["The agent made no gateway calls; this run does not demonstrate an agent workflow."])],
  };
}

export async function recover(dir: string, approval: string) {
  const stored = readJson<RecoveryPlan>(join(dir, "recovery-plan.json"));
  if (digestOf(stored) !== approval) throw new Error("Approval must equal the digest of the saved recovery plan");
  const fresh = await inspect(dir);
  if (digestOf(fresh) !== approval) throw new Error("State changed since review; inspect and approve a fresh plan");
  const gw = await openGateway(dir, "operator");
  const reason = `${REASON}; approved recovery plan ${approval}`;
  try {
    for (const f of stored.retractFacts) await call(gw, "memory.retract", { factId: f.factId, reason });
    for (const f of stored.writeFacts) await call(gw, "memory.write", { subject: CUSTOMER, predicate: f.predicate, value: f.value, space: SPACE });
    for (const credit of stored.reverseCredits) await call(gw, "billing.reverseCredit", { credit_id: credit.id, reason });
    saveJson(join(dir, "approval.json"), { planDigest: approval, approvedAt: new Date().toISOString(), actor: "demo-operator" });
  } finally { await gw.close(); }
  return verifyRecovery(dir);
}

export async function verifyRecovery(dir: string) {
  const receipts = verifiedReceipts(dir);
  const plan = await inspect(dir);
  const current = await new Ledger(join(dir, "ledger.jsonl")).asOf();
  const corrected = current.some(f => f.subject === CUSTOMER && f.predicate === "plan" && f.value === "free");
  const remainingWrong = current.filter(f => f.subject === CUSTOMER && Object.hasOwn(BENEFITS, f.predicate) && f.value !== BENEFITS[f.predicate as keyof typeof BENEFITS]);
  const ok = corrected && !remainingWrong.length && !plan.retractFacts.length && !plan.reverseCredits.length && readBilling(dir).credits.every(c => c.status === "reversed");
  const report = { ok, receiptsVerified: receipts.length, current: current.map(({ factId, predicate, value }) => ({ factId, predicate, value })), billing: readBilling(dir), agentCalls: plan.agentCalls, exposed: plan.exposed };
  if (!ok) throw new Error("Recovery incomplete: stale beliefs or active credits remain");
  return report;
}
