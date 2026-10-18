// The custody pack: everything about one fact as a single artefact a reviewer can verify. Its history with the
// receipt that produced each event, its blast radius with every downstream receipt, its forget certificate and what
// the stores answered, all inside one signed statement. Hand it to counsel, an auditor, or the person who asked for
// the deletion; they need the signing key and the gateway's key, and nothing from you.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { digestOf, dsseSign, dsseVerify, verifyBundle, type Envelope, type KeyPair, type PublicKeyRef, type ReceiptBundle } from "@agent-custody/receipts";
import { blastRadius, loadReceipts, type BlastRadius } from "./blast.ts";
import type { Fact, Ledger, LedgerEvent } from "./ledger.ts";

export const PACK_TYPE = "https://agent-custody.dev/custody-pack/v0.1";

export interface CustodyPack {
  version: "0.1";
  generatedAt: string;
  factId: string;
  fact: Fact | null;
  /** every event that touched the fact, oldest first */
  history: LedgerEvent[];
  /** every receipt referenced by the history or the blast radius, by id, as the full verifiable bundle */
  receipts: Record<string, ReceiptBundle>;
  /** receipt ids the history or blast radius cited but no bundle was found for */
  missingReceipts: string[];
  blast: BlastRadius;
  /** the forget event and what the forget receipt recorded, when the fact was forgotten */
  forget: { event: LedgerEvent; receiptId: string | null; verification: Record<string, string> | null; removedFrom: string[] | null } | null;
  /** hold and release events, in order */
  holds: LedgerEvent[];
}

function loadBundles(dir: string): Map<string, ReceiptBundle> {
  const out = new Map<string, ReceiptBundle>();
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    try {
      const bundle = JSON.parse(readFileSync(join(dir, f), "utf8")) as ReceiptBundle;
      const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as { predicate?: { receiptId?: string } };
      if (st.predicate?.receiptId) out.set(st.predicate.receiptId, bundle);
    } catch {
      // not a bundle; skip
    }
  }
  return out;
}

function receiptResult(bundle: ReceiptBundle): unknown {
  try {
    const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as { predicate?: { execution?: { result?: { content?: { type: string; text?: string }[] } } } };
    const text = st.predicate?.execution?.result?.content?.find((c) => c.type === "text")?.text;
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  } catch {
    return null; // a damaged bundle; the receipt check reports it
  }
}

export async function buildPack(ledger: Ledger, receiptsDir: string, factId: string, opts: { captureKey?: Buffer } = {}): Promise<CustodyPack> {
  const bundles = loadBundles(receiptsDir);
  const history = await ledger.history(factId);
  const blast = await blastRadius(ledger, loadReceipts(receiptsDir, opts), factId);
  const wanted = new Set<string>();
  for (const e of history) {
    const src = e.kind === "assert" ? e.fact.source.receiptId : e.source.receiptId;
    if (src) wanted.add(src);
  }
  for (const r of blast.receipts) wanted.add(r.receiptId);
  for (const f of blast.derivedFacts) if (f.source.receiptId) wanted.add(f.source.receiptId);
  const receipts: Record<string, ReceiptBundle> = {};
  const missingReceipts: string[] = [];
  for (const id of [...wanted].sort()) {
    const b = bundles.get(id);
    if (b) receipts[id] = b;
    else missingReceipts.push(id);
  }
  const forgetEvent = history.find((e) => e.kind === "forget");
  let forget: CustodyPack["forget"] = null;
  if (forgetEvent && forgetEvent.kind === "forget") {
    const rid = forgetEvent.source.receiptId;
    const result = rid && receipts[rid] ? (receiptResult(receipts[rid]) as { verification?: Record<string, string>; removedFrom?: string[] } | null) : null;
    forget = { event: forgetEvent, receiptId: rid, verification: result?.verification ?? null, removedFrom: result?.removedFrom ?? null };
  }
  return {
    version: "0.1",
    generatedAt: new Date().toISOString(),
    factId,
    fact: blast.fact,
    history,
    receipts,
    missingReceipts,
    blast,
    forget,
    holds: history.filter((e) => e.kind === "hold" || e.kind === "release"),
  };
}

export function signPack(pack: CustodyPack, key: KeyPair): Envelope {
  const statement = { _type: "https://in-toto.io/Statement/v1", subject: [{ name: `custody-pack:${pack.factId}`, digest: { sha256: digestOf(pack) } }], predicateType: PACK_TYPE, predicate: pack };
  return dsseSign("application/vnd.in-toto+json", statement, key);
}

export interface PackCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface PackVerification {
  ok: boolean;
  checks: PackCheck[];
  pack: CustodyPack | null;
}

/**
 * Verifies the pack's own signature and digest, then every receipt inside it against the gateway's keys when given,
 * that every event's source receipt is present, and that the forget receipt's result names this fact.
 */
export function verifyPack(envelope: Envelope, packKeys: PublicKeyRef[], receiptKeys?: { issuerKeys: PublicKeyRef[]; principalKeys?: PublicKeyRef[]; logKeys?: PublicKeyRef[]; upstreamKeys?: PublicKeyRef[] }): PackVerification {
  const checks: PackCheck[] = [];
  const add = (name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    return ok;
  };
  const v = dsseVerify(envelope, packKeys);
  if (!v.ok) {
    add("pack signature", false, v.error);
    return { ok: false, checks, pack: null };
  }
  add("pack signature", true, `keyid ${v.keyid.slice(0, 12)}`);
  const st = v.payload as { predicateType?: string; subject?: { digest?: { sha256?: string } }[]; predicate?: CustodyPack };
  if (!add("pack type", st.predicateType === PACK_TYPE && !!st.predicate)) return { ok: false, checks, pack: null };
  const pack = st.predicate!;
  add("pack digest", st.subject?.[0]?.digest?.sha256 === digestOf(pack));
  add("no receipts missing", pack.missingReceipts.length === 0, pack.missingReceipts.length ? `${pack.missingReceipts.length} cited receipt(s) absent` : undefined);
  for (const e of pack.history) {
    const src = e.kind === "assert" ? e.fact.source.receiptId : e.source.receiptId;
    if (src) add(`${e.kind} event cites a receipt in the pack`, src in pack.receipts, src.slice(0, 8));
  }
  if (receiptKeys) {
    for (const [id, bundle] of Object.entries(pack.receipts)) {
      const r = verifyBundle(bundle, { issuerKeys: receiptKeys.issuerKeys, principalKeys: receiptKeys.principalKeys ?? [], ...(receiptKeys.logKeys ? { logKeys: receiptKeys.logKeys } : {}), ...(receiptKeys.upstreamKeys ? { upstreamKeys: receiptKeys.upstreamKeys } : {}) });
      add(`receipt ${id.slice(0, 8)} verifies`, r.ok, r.ok ? undefined : r.checks.filter((c) => !c.ok).map((c) => c.name).join(", "));
      if (r.ok && r.statement && r.statement.predicate.receiptId !== id) add(`receipt ${id.slice(0, 8)} is the receipt it claims to be`, false);
    }
  } else {
    add("receipts checked against the gateway's keys", false, "no issuer key given; pass --issuer-key to check the receipts inside the pack");
  }
  if (pack.forget) {
    const bundle = pack.forget.receiptId ? pack.receipts[pack.forget.receiptId] : undefined;
    const result = bundle ? (receiptResult(bundle) as { factId?: string; erasedFromLedger?: boolean } | null) : null;
    add("forget receipt names this fact and records the erasure", !!result && result.factId === pack.factId && result.erasedFromLedger === true, bundle ? undefined : "forget receipt not in the pack");
  }
  return { ok: checks.every((c) => c.ok), checks, pack };
}

export function formatPack(p: CustodyPack): string {
  const lines: string[] = [];
  lines.push(p.fact ? `fact ${p.factId}: ${p.fact.subject} ${p.fact.predicate}${p.fact.forgotten ? " = (erased)" : ` = ${JSON.stringify(p.fact.value)}`} (space ${p.fact.space}, by ${p.fact.actor}, ${p.fact.provenance})` : `fact ${p.factId}: not in this ledger`);
  lines.push(`history: ${p.history.map((e) => e.kind).join(" → ")}`);
  lines.push(`receipts in pack: ${Object.keys(p.receipts).length}${p.missingReceipts.length ? `, missing ${p.missingReceipts.length}` : ""}`);
  if (p.holds.length) lines.push(`holds: ${p.holds.map((e) => (e.kind === "hold" || e.kind === "release" ? `${e.kind} by ${e.actor} (${e.reason})` : e.kind)).join("; ")}`);
  if (p.forget) lines.push(`forgotten at ${p.forget.event.txTime} by ${(p.forget.event as { actor: string }).actor}; receipt ${p.forget.receiptId?.slice(0, 8) ?? "none"}; stores: ${p.forget.verification ? Object.entries(p.forget.verification).map(([k, v]) => `${k}=${v}`).join(", ") : "none"}`);
  lines.push(`blast radius: ${p.blast.receipts.length} later call(s), ${p.blast.derivedFacts.length} derived belief(s), ${p.blast.stillBelieved.length} still believed${p.blast.withheld?.length ? `; INCOMPLETE: ${p.blast.withheld.length} later call(s) withhold what the agent had been shown under a capture rule and may depend on it` : ""}`);
  return lines.join("\n");
}
