// Explain one action. A security owner types a receipt id and gets the questions answered in the order they ask
// them: who acted, who authorized it, what was allowed, what the agent saw, what it did, why, what the evidence is,
// whether it verifies, what depended on it, and what needs reversing. The receipt answers the first eight on its own;
// the ledger answers the last two, because it knows which beliefs the call wrote and what was built on them since.
// The action pack is the same thing as one signed artefact, with every receipt it cites inside it.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { digestOf, dsseSign, dsseVerify, verifyBundle, type Envelope, type KeyPair, type PublicKeyRef, type ReceiptBundle, type ReceiptStatement, type VerifyOptions, type VerifyResult } from "@agent-custody/receipts";
import { blastRadius, loadReceipts, type ReceiptSummary } from "./blast.ts";
import type { Fact, Ledger } from "./ledger.ts";

export const ACTION_PACK_TYPE = "https://agent-custody.dev/action-pack/v0.1";

export interface ActionPack {
  version: "0.1";
  generatedAt: string;
  receiptId: string;
  /** the receipt itself, as issued */
  receipt: ReceiptBundle;
  /** the beliefs the agent had been shown before this call, as the ledger knows them; ids the ledger never held are listed apart */
  consumed: { facts: Fact[]; unknown: string[] };
  /** beliefs written in this call: every fact whose source receipt is this one */
  written: Fact[];
  /** what each written belief is today */
  status: Record<string, "believed" | "retracted" | "forgotten" | "superseded">;
  /** everything downstream of the written beliefs: later calls that consumed them and beliefs derived, transitively */
  downstream: { receipts: ReceiptSummary[]; derivedFacts: Fact[]; stillBelieved: Fact[] };
  /** every receipt cited by the downstream walk, by id, as the full bundle */
  receipts: Record<string, ReceiptBundle>;
  missingReceipts: string[];
}

export const decodeStatement = (b: ReceiptBundle): ReceiptStatement => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

function loadBundle(receiptsDir: string, receiptId: string): ReceiptBundle {
  return JSON.parse(readFileSync(join(receiptsDir, `${receiptId}.json`), "utf8")) as ReceiptBundle;
}

/**
 * Builds the pack. Without a ledger the receipt is explained on its own and the belief questions are answered as
 * unknown rather than as nothing, so a reader can tell "nothing depended on it" from "nobody looked".
 */
export async function buildActionPack(receiptsDir: string, receiptId: string, ledger?: Ledger): Promise<ActionPack> {
  const receipt = loadBundle(receiptsDir, receiptId);
  const p = decodeStatement(receipt).predicate;
  // under a capture rule the ids are a commitment in the receipt: nothing to look up, and the explanation says so
  const consumedIds = Array.isArray(p.consumed?.factIds) ? p.consumed.factIds : [];
  const consumed: ActionPack["consumed"] = { facts: [], unknown: [] };
  const written: Fact[] = [];
  const status: ActionPack["status"] = {};
  const downstream: ActionPack["downstream"] = { receipts: [], derivedFacts: [], stillBelieved: [] };
  const receipts: Record<string, ReceiptBundle> = {};
  const missingReceipts: string[] = [];
  if (ledger) {
    for (const id of consumedIds) {
      const f = await ledger.get(id);
      if (f) consumed.facts.push(f);
      else consumed.unknown.push(id);
    }
    for (const f of await ledger.facts()) if (f.source.receiptId === receiptId) written.push(f);
    const summaries = loadReceipts(receiptsDir);
    const seenReceipts = new Map<string, ReceiptSummary>();
    const seenFacts = new Map<string, Fact>();
    const believed = new Set<string>();
    for (const f of written) {
      const history = await ledger.history(f.factId);
      status[f.factId] = history.some((e) => e.kind === "forget") ? "forgotten" : history.some((e) => e.kind === "retract") ? "retracted" : f.validTo !== null ? "superseded" : "believed";
      const b = await blastRadius(ledger, summaries, f.factId);
      for (const r of b.receipts) seenReceipts.set(r.receiptId, r);
      for (const d of b.derivedFacts) seenFacts.set(d.factId, d);
      for (const s of b.stillBelieved) believed.add(s.factId);
    }
    downstream.receipts = [...seenReceipts.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    downstream.derivedFacts = [...seenFacts.values()];
    downstream.stillBelieved = downstream.derivedFacts.filter((f) => believed.has(f.factId));
    const wanted = new Set<string>([...downstream.receipts.map((r) => r.receiptId), ...downstream.derivedFacts.map((f) => f.source.receiptId).filter((x): x is string => !!x)]);
    for (const id of [...wanted].sort()) {
      try {
        receipts[id] = loadBundle(receiptsDir, id);
      } catch {
        missingReceipts.push(id);
      }
    }
  } else {
    consumed.unknown.push(...consumedIds);
  }
  return { version: "0.1", generatedAt: new Date().toISOString(), receiptId, receipt, consumed, written, status, downstream, receipts, missingReceipts };
}

export function signActionPack(pack: ActionPack, key: KeyPair): Envelope {
  const statement = { _type: "https://in-toto.io/Statement/v1", subject: [{ name: `action-pack:${pack.receiptId}`, digest: { sha256: digestOf(pack) } }], predicateType: ACTION_PACK_TYPE, predicate: pack };
  return dsseSign("application/vnd.in-toto+json", statement, key);
}

export interface ActionPackCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface ActionPackVerification {
  ok: boolean;
  checks: ActionPackCheck[];
  pack: ActionPack | null;
  /** the receipt's own verification, when issuer keys were given */
  receipt: VerifyResult | null;
}

export type ReceiptKeys = Pick<VerifyOptions, "issuerKeys" | "principalKeys" | "logKeys" | "upstreamKeys" | "providerSecrets">;

/** The pack's signature and digest, the receipt inside it against the gateway's keys, every downstream receipt likewise, and that the written beliefs really cite this receipt. */
export function verifyActionPack(envelope: Envelope, packKeys: PublicKeyRef[], keys?: ReceiptKeys): ActionPackVerification {
  const checks: ActionPackCheck[] = [];
  const add = (name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    return ok;
  };
  const v = dsseVerify(envelope, packKeys);
  if (!v.ok) {
    add("pack signature", false, v.error);
    return { ok: false, checks, pack: null, receipt: null };
  }
  add("pack signature", true, `keyid ${v.keyid.slice(0, 12)}`);
  const st = v.payload as { predicateType?: string; subject?: { digest?: { sha256?: string } }[]; predicate?: ActionPack };
  if (!add("pack type", st.predicateType === ACTION_PACK_TYPE && !!st.predicate)) return { ok: false, checks, pack: null, receipt: null };
  const pack = st.predicate!;
  add("pack digest", st.subject?.[0]?.digest?.sha256 === digestOf(pack));
  let receiptResult: VerifyResult | null = null;
  const p = decodeStatement(pack.receipt).predicate;
  add("receipt is the one the pack names", p.receiptId === pack.receiptId);
  if (keys) {
    const opts: VerifyOptions = { issuerKeys: keys.issuerKeys, principalKeys: keys.principalKeys ?? [], ...(keys.logKeys ? { logKeys: keys.logKeys } : {}), ...(keys.upstreamKeys ? { upstreamKeys: keys.upstreamKeys } : {}), ...(keys.providerSecrets ? { providerSecrets: keys.providerSecrets } : {}) };
    receiptResult = verifyBundle(pack.receipt, opts);
    add("receipt verifies", receiptResult.ok, receiptResult.ok ? `${receiptResult.checks.length} checks` : receiptResult.checks.filter((c) => !c.ok).map((c) => c.name).join(", "));
    for (const [id, bundle] of Object.entries(pack.receipts)) {
      const r = verifyBundle(bundle, opts);
      add(`downstream receipt ${id.slice(0, 8)} verifies`, r.ok && r.statement?.predicate.receiptId === id, r.ok ? undefined : r.checks.filter((c) => !c.ok).map((c) => c.name).join(", "));
    }
  } else {
    add("receipts checked against the gateway's keys", false, "no issuer key given; pass --issuer-key to check the receipts inside the pack");
  }
  add("written beliefs cite this receipt", pack.written.every((f) => f.source.receiptId === pack.receiptId));
  add("no downstream receipts missing", pack.missingReceipts.length === 0, pack.missingReceipts.length ? `${pack.missingReceipts.length} cited receipt(s) absent` : undefined);
  return { ok: checks.every((c) => c.ok), checks, pack, receipt: receiptResult };
}

const decodeDelegation = (env: Envelope): { principal?: string; agent?: string; scopes?: string[]; issuedAt?: string; expiresAt?: string } | null => {
  try {
    return JSON.parse(Buffer.from(env.payload, "base64").toString());
  } catch {
    return null;
  }
};

const factLine = (f: Fact) => `${f.subject} ${f.predicate}${f.forgotten ? " (erased)" : ` = ${JSON.stringify(f.value)}`} [${f.factId.slice(0, 8)}]`;

/** The ten questions, answered from the pack; `verification` is the receipt's own check list when keys were given. */
export function formatExplain(pack: ActionPack, verification: VerifyResult | null, withLedger: boolean): string {
  const p = decodeStatement(pack.receipt).predicate;
  const lines: string[] = [];
  const row = (q: string, a: string) => lines.push(`${q.padEnd(28)} ${a}`);
  const more = (a: string) => lines.push(`${"".padEnd(28)} ${a}`);
  row("WHO", `${p.agent.id} (${p.agent.provenance}${p.issuer.kind === "sdk" ? ", self-reported by its own process" : ", named in a signed grant"})`);
  const d = p.delegation ? decodeDelegation(p.delegation.envelope) : null;
  if (p.principal.provenance === "attested") row("WHO AUTHORIZED IT", `${p.principal.id}, grant signed by key ${p.principal.keyid.slice(0, 12)}${d ? `, valid ${d.issuedAt} to ${d.expiresAt}` : ""}`);
  else row("WHO AUTHORIZED IT", `${p.principal.id ?? "nobody named"} (claimed; no signed grant)`);
  row("WHAT WAS ALLOWED", d?.scopes ? `tools ${d.scopes.join(", ")}` : "no grant in this receipt");
  // under a capture rule a message is a commitment in the receipt; the explanation says so rather than printing it
  const text = (v: unknown): string => (typeof v === "string" ? v : "(withheld under the capture rule)");
  const errors: string[] = Array.isArray(p.policy?.errors) ? p.policy.errors : p.policy?.errors ? [text(p.policy.errors)] : [];
  if (p.policy) more(`policy ${p.policy.policyDigest.slice(0, 12)} decided ${p.policy.decision}${p.policy.reasons.length ? ` by ${p.policy.reasons.join(", ")}` : ""}${errors.length ? `; errors: ${errors.join("; ")}` : ""}`);
  const facts = Object.entries(p.facts);
  row("WHAT THE AGENT SAW", facts.length ? facts.map(([k, f]) => `${k} = ${JSON.stringify(f.value)} (fetched by the gateway via ${f.tool})`).join("; ") : "no facts fetched for this call");
  const shown = Array.isArray(p.consumed?.factIds) ? p.consumed.factIds : [];
  if (p.consumed && !Array.isArray(p.consumed.factIds)) more("the beliefs shown before this call are withheld under the capture rule");
  else if (!withLedger) more(shown.length ? `${shown.length} belief(s) shown before this call; open with a ledger to see them` : "no beliefs shown before this call");
  else if (shown.length === 0) more("no beliefs shown before this call");
  else {
    more(`${shown.length} belief(s) shown before this call:`);
    for (const f of pack.consumed.facts) more(`  ${factLine(f)}`);
    for (const id of pack.consumed.unknown) more(`  ${id.slice(0, 8)} (not in this ledger)`);
  }
  row("WHAT IT DID", `${p.tool.name} ${JSON.stringify(p.request.args)} -> ${p.execution.status}${p.execution.status === "denied" ? `: ${text(p.execution.reason)}` : p.execution.status === "withheld" ? `: ${text(p.execution.reason)}` : p.execution.status === "error" ? `: ${text(p.execution.error)}` : ""}`);
  row("WHY", p.policy ? (p.policy.decision === "allow" ? `the policy permitted it${p.policy.reasons.length ? ` (${p.policy.reasons.join(", ")})` : ""}` : p.policy.enforced === false ? `the policy would have refused it, and was in observe mode, so the call went through: ${[...p.policy.reasons, ...errors].join("; ") || "no permit matched"}` : `the policy refused it: ${[...p.policy.reasons, ...errors].join("; ") || "no permit matched"}`) : "no policy was evaluated");
  const th = pack.receipt.treeHead.signatures[0]?.keyid ?? "?";
  row("WHAT EVIDENCE", `receipt ${p.receiptId}, leaf ${pack.receipt.inclusion.leafIndex} of a log whose head is signed by ${th.slice(0, 12)}`);
  if (p.authorization) more(`authorization committed as leaf ${p.authorization.inclusion.leafIndex}, before the call was forwarded`);
  if ((p.execution.status === "executed" || p.execution.status === "failed") && p.execution.upstream) more("the upstream's own signature over the result is embedded");
  row("CAN I VERIFY IT", verification ? (verification.ok ? `VERIFIED, ${verification.checks.length} checks` : `NOT VERIFIED: ${verification.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")}`) : "not checked here; pass the gateway's and principal's public keys");
  if (!withLedger) {
    row("DID ANYTHING DEPEND ON THIS", "unknown without a ledger");
    row("WHAT NEEDS REVERSAL", "unknown without a ledger");
  } else {
    const w = pack.written;
    if (w.length === 0) row("DID ANYTHING DEPEND ON THIS", "this call wrote no beliefs; nothing in the ledger descends from it");
    else {
      row("DID ANYTHING DEPEND ON THIS", `${w.length} belief(s) written in this call, ${pack.downstream.receipts.length} later call(s) made after seeing them, ${pack.downstream.derivedFacts.length} belief(s) derived`);
      for (const f of w) more(`  wrote ${factLine(f)}: ${pack.status[f.factId]}`);
      for (const r of pack.downstream.receipts) more(`  then ${r.timestamp} ${r.tool} ${r.status} (receipt ${r.receiptId.slice(0, 8)})`);
    }
    const open = [...w.filter((f) => pack.status[f.factId] === "believed"), ...pack.downstream.stillBelieved];
    if (open.length === 0) row("WHAT NEEDS REVERSAL", w.length === 0 ? "nothing" : "nothing still believed; every belief from this call and after it is retracted, forgotten, or superseded");
    else {
      row("WHAT NEEDS REVERSAL", `${open.length} belief(s) still believed${pack.downstream.receipts.length ? `, and ${pack.downstream.receipts.length} later call(s) to review` : ""}`);
      for (const f of open) more(`  ${factLine(f)} (space ${f.space})`);
    }
  }
  return lines.join("\n");
}
