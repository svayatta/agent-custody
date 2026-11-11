/**
 * A reader for another project's agent records: Perathos session logs (`perathos.receipt/v1`), checked against the
 * verification rules of their published spec (docs/specs/RECEIPT_V1.md in perathos-protocol/perathos). Written from
 * that spec alone, so a Perathos log and an agent-custody receipt can be checked with one tool, each for what it proves.
 *
 * A Perathos log is recorded by hooks inside the agent's host and sealed by checkpoints signed with a key held there.
 * A valid log shows that the key holder sealed this sequence and nothing up to the last checkpoint changed since. It
 * does not show that an enforcement point outside the agent saw each call, which is what an agent-custody receipt
 * attests, so the report says which kind of evidence it is. RFC 3161 anchors are not checked here.
 */
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { canonicalize, sha256Hex } from "./crypto.ts";

export const PERATHOS_RECEIPT_V1 = "perathos.receipt/v1";
const KINDS = new Set(["pre", "post", "checkpoint"]);
const ZERO = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
// the spec's only form: fixed width, UTC, microseconds, so string order is time order
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface PerathosCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface PerathosReport {
  ok: boolean;
  checks: PerathosCheck[];
  warnings: string[];
  session: string | null;
  agent: string | null;
  receipts: number;
  toolCalls: number;
  checkpoints: number;
  signers: string[];
  /** the seq of the last checkpoint; receipts after it are an unsealed tail, which is not an error */
  sealedThrough: number;
  unsealedTail: number;
  /** pre receipts whose guard decided deny: calls that never ran */
  denied: number;
  signerFailures: number;
  firstTs: string | null;
  lastTs: string | null;
  provenance: string;
}

export interface PerathosOptions {
  /** Ed25519 public keys as 64 hex characters; when given, every checkpoint signer must be one of them */
  trustedKeys?: string[];
  /** accept a log with no checkpoint or an unsigned one, as a warning */
  allowUnsigned?: boolean;
  /** the head witness (`<session_id>.head.json`): the latest checkpoint's seq and receipt_hash */
  head?: { seq: number; receipt_hash: string };
}

type Receipt = Record<string, unknown>;

/** The receipt_hash the spec defines: SHA-256 of the canonical JSON of every field but receipt_hash and signature. */
export function perathosReceiptHash(r: Receipt): string {
  const body: Receipt = {};
  for (const [k, v] of Object.entries(r)) if (k !== "receipt_hash" && k !== "signature") body[k] = v;
  return sha256Hex(canonicalize(body));
}

function ed25519Key(hex: string): KeyObject {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}

function signatureOk(r: Receipt): string | null {
  const signer = r.signer;
  const s = r.signature as Record<string, unknown> | undefined;
  if (typeof signer !== "string" || !HEX64.test(signer)) return "no signer key";
  if (!s || typeof s !== "object") return "no signature";
  if (s.algorithm !== "ed25519") return `algorithm ${String(s.algorithm)}`;
  if (s.verify_key !== signer) return "verify_key is not the signer";
  if (typeof s.signature !== "string" || !/^[0-9a-f]{128}$/.test(s.signature)) return "signature is not 64 bytes of hex";
  if (typeof r.receipt_hash !== "string" || !HEX64.test(r.receipt_hash)) return "no receipt_hash";
  try {
    return verify(null, Buffer.from(r.receipt_hash, "hex"), ed25519Key(signer), Buffer.from(s.signature, "hex")) ? null : "signature does not verify";
  } catch {
    return "the signer is not an Ed25519 public key";
  }
}

/** The head witness file, `{ "seq", "receipt_hash" }`, checked for shape. */
export function perathosHead(text: string): { seq: number; receipt_hash: string } {
  const h = JSON.parse(text) as Record<string, unknown>;
  if (!h || typeof h !== "object" || !Number.isInteger(h.seq) || (h.seq as number) < 1 || typeof h.receipt_hash !== "string" || !HEX64.test(h.receipt_hash)) throw new Error('the head witness must be { "seq": <integer from 1>, "receipt_hash": <64 hex> }');
  return { seq: h.seq as number, receipt_hash: h.receipt_hash };
}

/** Check a Perathos session log (JSON Lines) against rules 1 to 9 of the v1 spec. */
export function verifyPerathosLog(text: string, opts: PerathosOptions = {}): PerathosReport {
  const checks: PerathosCheck[] = [];
  const warnings: string[] = [];
  const add = (name: string, problems: string[]) => checks.push({ name, ok: problems.length === 0, ...(problems.length ? { detail: problems.slice(0, 3).join("; ") + (problems.length > 3 ? `; and ${problems.length - 3} more` : "") } : {}) });

  const receipts: Receipt[] = [];
  const parse: string[] = [];
  text.split("\n").forEach((line, i) => {
    if (!line.trim()) return;
    try {
      const v = JSON.parse(line) as unknown;
      if (v && typeof v === "object" && !Array.isArray(v)) receipts.push(v as Receipt);
      else parse.push(`line ${i + 1} is not an object`);
    } catch {
      parse.push(`line ${i + 1} is not JSON`);
    }
  });
  add("every line is a JSON object", parse.length ? parse : receipts.length ? [] : ["the log is empty"]);

  const format: string[] = [], seq: string[] = [], chain: string[] = [], hashes: string[] = [], order: string[] = [], sigs: string[] = [], unsigned: string[] = [];
  const signers = new Set<string>();
  const checkpoints: Receipt[] = [];
  const sealed: Receipt[] = [];
  let signerFailures = 0;
  receipts.forEach((r, i) => {
    const at = `seq ${String(r.seq ?? i + 1)}`;
    if (r.v !== PERATHOS_RECEIPT_V1 || !KINDS.has(String(r.kind))) format.push(`${at}: v ${String(r.v)}, kind ${String(r.kind)}`);
    if (r.seq !== i + 1) seq.push(`line ${i + 1} has seq ${String(r.seq)}`);
    const prev = i === 0 ? ZERO : receipts[i - 1]!.receipt_hash;
    if (r.prev_hash !== prev) chain.push(`${at}: prev_hash does not match the receipt before`);
    if (r.receipt_hash !== perathosReceiptHash(r)) hashes.push(`${at}: receipt_hash does not recompute`);
    if (r.session_id !== receipts[0]!.session_id) order.push(`${at}: session ${String(r.session_id)}`);
    if (typeof r.ts !== "string" || !TS.test(r.ts)) order.push(`${at}: ts ${JSON.stringify(r.ts)} is not YYYY-MM-DDTHH:MM:SS.mmmmmmZ`);
    else if (i > 0 && typeof receipts[i - 1]!.ts === "string" && TS.test(receipts[i - 1]!.ts as string) && r.ts < (receipts[i - 1]!.ts as string)) order.push(`${at}: time goes back`);
    if (r.kind !== "checkpoint") return;
    checkpoints.push(r);
    if (r.signature === undefined && r.signer === undefined) {
      unsigned.push(`${at}${typeof r.signer_error === "string" ? `: the recorder's signer failed when it was sealed (${r.signer_error})` : ""}`);
      if (typeof r.signer_error === "string") signerFailures++;
      return;
    }
    const problem = signatureOk(r);
    if (problem) sigs.push(`${at}: ${problem}`);
    else {
      signers.add(r.signer as string);
      sealed.push(r);
    }
  });
  add("format is perathos.receipt/v1 with a known kind", format);
  add("seq is 1, 2, 3, ... in file order", seq);
  add("prev_hash chains each receipt to the one before", chain);
  add("receipt_hash recomputes", hashes);
  add("one session, and time never goes back", order);
  add("checkpoint signatures verify", sigs);
  const sealing = checkpoints.length ? unsigned : ["no checkpoint seals the log", ...unsigned];
  if (opts.allowUnsigned) {
    warnings.push(...sealing);
    add("every checkpoint is signed (unsigned allowed)", []);
  } else add("every checkpoint is signed", sealing);
  if (opts.trustedKeys) {
    const trusted = new Set(opts.trustedKeys.map((k) => k.toLowerCase()));
    add("every signer is a trusted key", [...signers].filter((k) => !trusted.has(k)).map((k) => `untrusted signer ${k.slice(0, 12)}`));
  } else {
    // without a pinned key, a second key could seal receipts appended after the recorder's last checkpoint
    add("one key seals the session (no --key given)", signers.size > 1 ? [`${signers.size} keys sealed this session: ${[...signers].map((k) => k.slice(0, 12)).join(", ")}; pin the recorder's key with --key`] : []);
    warnings.push("no key pinned: a VALID result shows the log is consistent with itself, not who sealed it; pin the recorder's key with --key");
  }
  if (opts.head) {
    const h = opts.head;
    const found = checkpoints.some((c) => c.seq === h.seq && c.receipt_hash === h.receipt_hash);
    add("the head witness's checkpoint is in the log", found ? [] : [`no checkpoint at seq ${h.seq} with that receipt_hash: the log was cut or replaced`]);
  }

  // only a checkpoint whose signature verified seals what comes before it
  const last = sealed.at(-1);
  const sealedThrough = typeof last?.seq === "number" ? last.seq : 0;
  const agent = typeof receipts[0]?.agent === "string" ? (receipts[0].agent as string) : null;
  return {
    ok: checks.every((c) => c.ok),
    checks,
    warnings,
    session: typeof receipts[0]?.session_id === "string" ? (receipts[0].session_id as string) : null,
    agent,
    receipts: receipts.length,
    toolCalls: receipts.filter((r) => r.kind === "pre").length,
    checkpoints: checkpoints.length,
    signers: [...signers],
    sealedThrough,
    unsealedTail: Math.max(0, receipts.length - sealedThrough),
    denied: receipts.filter((r) => r.kind === "pre" && (r.guard as Record<string, unknown> | undefined)?.decision === "deny").length,
    signerFailures,
    firstTs: typeof receipts[0]?.ts === "string" ? (receipts[0].ts as string) : null,
    lastTs: typeof receipts.at(-1)?.ts === "string" ? (receipts.at(-1)!.ts as string) : null,
    provenance: `perathos.receipt/v1, recorded by hooks inside the agent's host (${agent ?? "unknown"}); the checkpoint key is held on that host, so a valid log shows that the key holder sealed this sequence, not that an enforcement point outside the agent saw each call; times are the host's clock, and RFC 3161 anchors were not checked`,
  };
}

/** The report as text, in the style of `verify`. */
export function formatPerathosReport(r: PerathosReport): string {
  const lines = r.checks.map((c) => `${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  for (const w of r.warnings) lines.push(`WARN  ${w}`);
  lines.push("", `RESULT: ${r.ok ? "VALID" : "INVALID"}`, "");
  lines.push(`session         ${r.session ?? "-"}`);
  lines.push(`receipts        ${r.receipts} (${r.toolCalls} tool calls, ${r.checkpoints} checkpoints)`);
  lines.push(`sealed          through seq ${r.sealedThrough}${r.unsealedTail ? `, ${r.unsealedTail} receipt(s) after it unsealed` : ""}`);
  lines.push(`signers         ${r.signers.length ? r.signers.map((k) => k.slice(0, 12)).join(", ") : "-"}`);
  lines.push(`time            ${r.firstTs ?? "-"} to ${r.lastTs ?? "-"} (host clock)`);
  if (r.denied) lines.push(`denied          ${r.denied} call(s) stopped by the guard`);
  lines.push("", `PROVENANCE: ${r.provenance}`);
  return lines.join("\n");
}
