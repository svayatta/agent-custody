// Blast radius: given a fact, everything that relied on it. The receipts say which facts the agent had been shown
// before each call; the ledger says which facts were written in which call. Walking both, forward, gives every
// downstream action and every derived belief, transitively, and the retraction that undoes the belief if there is one.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { restorePaths, type CaptureNote } from "@agent-custody/receipts";
import type { Fact, Ledger, RetractEvent } from "./ledger.ts";

/** The parts of a receipt this query needs. Decoded from a bundle's statement; nothing here is verified, so verify first. */
export interface ReceiptSummary {
  receiptId: string;
  timestamp: string;
  tool: string;
  status: string;
  /** fact ids the agent had been shown before this call, from the receipt's consumed field; empty when none, or when they are withheld */
  consumed: string[];
  /** true when the receipt withholds the consumed ids under a capture rule and no key brought them back: the call may depend on any fact, and the query cannot tell */
  consumedWithheld: boolean;
}

/** Reads every bundle in a receipts directory. Order is by timestamp. With the capture key, withheld consumed ids are decrypted; otherwise a receipt that withholds them is marked, not treated as having consumed nothing. */
export function loadReceipts(dir: string, opts: { captureKey?: Buffer } = {}): ReceiptSummary[] {
  const out: ReceiptSummary[] = [];
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const bundle = JSON.parse(readFileSync(join(dir, f), "utf8")) as { envelope?: { payload?: string } };
    if (!bundle.envelope?.payload) continue;
    const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as { predicate?: any };
    const p = st.predicate;
    if (!p?.receiptId) continue;
    let ids: unknown = p.consumed?.factIds;
    let consumedWithheld = false;
    if (p.consumed && !Array.isArray(ids)) {
      const back = opts.captureKey ? restorePaths(p, p.capture as CaptureNote | undefined, undefined, opts.captureKey).predicate as { consumed?: { factIds?: unknown } } : null;
      if (Array.isArray(back?.consumed?.factIds)) ids = back!.consumed!.factIds;
      else consumedWithheld = true;
    }
    out.push({ receiptId: p.receiptId, timestamp: p.timestamp, tool: p.tool?.name ?? "?", status: p.execution?.status ?? "?", consumed: Array.isArray(ids) ? ids.filter((id): id is string => typeof id === "string") : [], consumedWithheld });
  }
  return out.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export interface BlastRadius {
  fact: Fact | null;
  /** every receipt for a call made after the agent had been shown this fact or one derived from it */
  receipts: ReceiptSummary[];
  /** every fact written in one of those calls, transitively */
  derivedFacts: Fact[];
  /** the retraction of the root fact, when it has been undone */
  retraction: RetractEvent | null;
  /** derived facts that are still believed; the ones a cleanup has to decide about */
  stillBelieved: Fact[];
  /** receipts made since the ledger learned the fact (its assert's transaction time) whose consumed ids are withheld: each may depend on it, and the sets above are incomplete while any is listed */
  withheld: ReceiptSummary[];
}

export async function blastRadius(ledger: Ledger, receipts: ReceiptSummary[], factId: string): Promise<BlastRadius> {
  const all = await ledger.facts();
  const byId = new Map(all.map((f) => [f.factId, f]));
  const believed = new Set((await ledger.asOf()).map((f) => f.factId));
  const seen = new Set<string>([factId]);
  const hit = new Map<string, ReceiptSummary>();
  const derived = new Map<string, Fact>();
  let grew = true;
  while (grew) {
    grew = false;
    for (const r of receipts) {
      if (hit.has(r.receiptId) || !r.consumed.some((id) => seen.has(id))) continue;
      hit.set(r.receiptId, r);
      grew = true;
    }
    for (const f of all) {
      if (f.factId === factId || derived.has(f.factId) || !f.source.receiptId || !hit.has(f.source.receiptId)) continue;
      derived.set(f.factId, f);
      seen.add(f.factId);
      grew = true;
    }
  }
  const history = await ledger.history(factId);
  const retraction = (history.find((e) => e.kind === "retract") as RetractEvent | undefined) ?? null;
  const derivedFacts = [...derived.values()];
  const fact = byId.get(factId) ?? null;
  // What the query cannot see: a call whose consumed ids are withheld, made once the ledger knew the fact, may have
  // relied on it. The bound is the assert's transaction time, never validFrom: a fact valid from tomorrow is readable
  // today (memory.read with validAt), so a call today may already have consumed it. Unknown, no bound at all.
  const known = history.find((e) => e.kind === "assert")?.txTime;
  const withheld = receipts.filter((r) => r.consumedWithheld && !hit.has(r.receiptId) && (!known || r.timestamp >= known));
  return { fact, receipts: [...hit.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp)), derivedFacts, retraction, stillBelieved: derivedFacts.filter((f) => believed.has(f.factId)), withheld };
}

export function formatBlastRadius(b: BlastRadius, factId: string): string {
  const lines: string[] = [];
  lines.push(b.fact ? `fact ${factId}: ${b.fact.subject} ${b.fact.predicate} = ${JSON.stringify(b.fact.value)} (space ${b.fact.space}, by ${b.fact.actor}, ${b.fact.provenance})` : `fact ${factId}: not in this ledger`);
  lines.push(b.retraction ? `retracted at ${b.retraction.txTime} by ${b.retraction.actor}: ${b.retraction.reason}` : "not retracted");
  lines.push(`${b.receipts.length} call(s) made after the agent was shown it:`);
  for (const r of b.receipts) lines.push(`  ${r.timestamp}  ${r.tool.padEnd(18)} ${r.status.padEnd(9)} receipt ${r.receiptId.slice(0, 8)}`);
  lines.push(`${b.derivedFacts.length} belief(s) written in those calls, ${b.stillBelieved.length} still believed:`);
  for (const f of b.derivedFacts) lines.push(`  ${f.subject} ${f.predicate} = ${JSON.stringify(f.value)}  fact ${f.factId.slice(0, 8)}  ${b.stillBelieved.includes(f) ? "STILL BELIEVED" : "no longer believed"}`);
  if (b.withheld.length) {
    lines.push(`INCOMPLETE: ${b.withheld.length} call(s) made since the ledger learned the fact withhold what the agent had been shown under a capture rule; each may depend on it, and so may beliefs written in them. Give the capture key to see.`);
    for (const r of b.withheld) lines.push(`  ${r.timestamp}  ${r.tool.padEnd(18)} ${r.status.padEnd(9)} receipt ${r.receiptId.slice(0, 8)}  consumed ids withheld`);
  }
  return lines.join("\n");
}
