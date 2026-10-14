// Private evidence: what a receipt records of a call, field by field. The signature and the digests are over the
// whole call as it happened; what the receipt file carries in clear is a choice, made per tool in the config. A field
// that is withheld leaves a commitment in its place, sha256 over a random salt and the canonical value, so a reviewer
// who is later shown the value can check it belongs. An encrypted field carries the value as well, under a key the
// customer holds (AES-256-GCM); whoever has the key reveals it and recomputes every digest; whoever does not sees
// that a field existed, that it was committed to, and nothing else. The verifier accepts both: a receipt with
// withheld fields passes with the note that the digest was committed, not recomputed, and passes in full once the
// fields are disclosed or the key is given.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { canonicalize, sha256Hex } from "./crypto.ts";

export type CaptureMode = "clear" | "digest" | "encrypted";
/** One side of a call: the arguments, the result, or the facts. */
export interface CaptureSide {
  /** clear: everything in the receipt (the default); digest: withheld fields leave a commitment; encrypted: withheld fields leave a commitment and the value under the customer's key */
  mode: CaptureMode;
  /** top-level fields kept in clear in digest or encrypted mode, e.g. the amount and the customer id of a refund */
  clear?: string[];
}
export interface CaptureRule {
  args?: CaptureSide;
  result?: CaptureSide;
  facts?: CaptureSide;
}
/** by tool name, or "*" for every tool without a rule of its own */
export type CaptureConfig = Record<string, CaptureRule>;
/** On the receipt beside a captured part: how it was captured and which fields are withheld ("*" when the whole value is). */
export interface CaptureNote {
  mode: "digest" | "encrypted";
  withheld: string[];
}

export interface Withheld {
  $custody: "withheld";
  /** sha256 over salt || canonical JSON of the value */
  sha256: string;
  salt: string;
}
export interface Encrypted {
  $custody: "encrypted";
  alg: "A256GCM";
  /** sha256 of the key, so a reviewer knows which key reveals it */
  keyid: string;
  iv: string;
  ciphertext: string;
  tag: string;
  sha256: string;
  salt: string;
}
export type Commitment = Withheld | Encrypted;

/** The result's bookkeeping fields stay in clear whatever the rule says: the error flag, and the metadata that carries an upstream's signature. */
const ALWAYS_CLEAR_IN_RESULT = ["isError", "_meta"];

/** A 32-byte key from hex (64 chars) or base64 (44 chars), as an environment variable holds it. */
export function captureKeyFrom(text: string): Buffer {
  const t = text.trim();
  const key = /^[0-9a-fA-F]{64}$/.test(t) ? Buffer.from(t, "hex") : Buffer.from(t, "base64");
  if (key.length !== 32) throw new Error("capture key: expected 32 bytes as 64 hex characters or base64");
  return key;
}
export function captureKeyId(key: Buffer): string {
  return sha256Hex(key);
}
export function isCommitment(v: unknown): v is Commitment {
  return !!v && typeof v === "object" && !Array.isArray(v) && ((v as { $custody?: unknown }).$custody === "withheld" || (v as { $custody?: unknown }).$custody === "encrypted");
}
function commit(value: unknown, salt: Buffer): string {
  return sha256Hex(Buffer.concat([salt, Buffer.from(canonicalize(value), "utf8")]));
}

/** Replaces a value with its commitment, carrying the value encrypted when a key is given. */
export function withhold(value: unknown, key?: Buffer): Commitment {
  const salt = randomBytes(16);
  const sha256 = commit(value, salt);
  if (!key) return { $custody: "withheld", sha256, salt: salt.toString("hex") };
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(canonicalize(value), "utf8"), cipher.final()]);
  return { $custody: "encrypted", alg: "A256GCM", keyid: captureKeyId(key), iv: iv.toString("base64"), ciphertext: ciphertext.toString("base64"), tag: cipher.getAuthTag().toString("base64"), sha256, salt: salt.toString("hex") };
}

/** True when `value` is what the commitment was made over. */
export function checkCommitment(c: Commitment, value: unknown): boolean {
  return commit(value, Buffer.from(c.salt, "hex")) === c.sha256;
}

/** The value behind an encrypted commitment, under the key that made it; checked against the commitment too. */
export function reveal(c: Commitment, key: Buffer): unknown {
  if (c.$custody !== "encrypted") throw new Error("this field was withheld without its value; only the party that disclosed it can supply it");
  if (c.keyid !== captureKeyId(key)) throw new Error(`this field was encrypted under key ${c.keyid.slice(0, 12)}…, not the one given`);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(c.iv, "base64"));
  decipher.setAuthTag(Buffer.from(c.tag, "base64"));
  const text = Buffer.concat([decipher.update(Buffer.from(c.ciphertext, "base64")), decipher.final()]).toString("utf8");
  const value = JSON.parse(text) as unknown;
  if (!checkCommitment(c, value)) throw new Error("the decrypted value does not match its commitment");
  return value;
}

export function ruleFor(capture: CaptureConfig | undefined, tool: string): CaptureRule | undefined {
  return capture?.[tool] ?? capture?.["*"];
}

/**
 * The view of a value a receipt carries under a side's rule. A plain object is captured field by field, the listed
 * ones in clear and the rest withheld; anything else is withheld whole ("*"). Mode clear returns the value itself
 * and no note.
 */
export function captureValue(value: unknown, side: CaptureSide | undefined, key?: Buffer, alwaysClear: string[] = []): { view: unknown; note?: CaptureNote } {
  if (!side || side.mode === "clear") return { view: value };
  if (side.mode === "encrypted" && !key) throw new Error("capture mode encrypted needs captureKeyEnv");
  const k = side.mode === "encrypted" ? key : undefined;
  const mode = side.mode;
  if (!value || typeof value !== "object" || Array.isArray(value)) return { view: withhold(value, k), note: { mode, withheld: ["*"] } };
  const keep = new Set([...(side.clear ?? []), ...alwaysClear]);
  const view: Record<string, unknown> = {};
  const withheld: string[] = [];
  for (const [name, v] of Object.entries(value as Record<string, unknown>)) {
    if (keep.has(name)) view[name] = v;
    else {
      view[name] = withhold(v, k);
      withheld.push(name);
    }
  }
  return withheld.length ? { view, note: { mode, withheld } } : { view: value };
}
export const captureArgs = (args: Record<string, unknown>, side: CaptureSide | undefined, key?: Buffer) => captureValue(args, side, key) as { view: Record<string, unknown>; note?: CaptureNote };
export const captureResult = (result: unknown, side: CaptureSide | undefined, key?: Buffer) => captureValue(result, side, key, ALWAYS_CLEAR_IN_RESULT);

/** The commitments in a view, by field; `{ "*": c }` when the whole value is one. */
export function commitmentsIn(view: unknown): Record<string, Commitment> {
  if (isCommitment(view)) return { "*": view };
  if (!view || typeof view !== "object" || Array.isArray(view)) return {};
  return Object.fromEntries(Object.entries(view as Record<string, unknown>).filter(([, v]) => isCommitment(v))) as Record<string, Commitment>;
}

export type Restored = { value: unknown; how: "clear" | "disclosed" | "decrypted" };

/**
 * The full value behind a view: the view itself when nothing is withheld; the disclosed value when one is given and
 * every commitment in the view matches it; the decrypted value when the key is given and every withheld field is
 * encrypted under it. Null when the value cannot be had. Throws when a disclosure or a key contradicts a commitment.
 */
export function restore(view: unknown, disclosed?: unknown, key?: Buffer): Restored | null {
  const cs = commitmentsIn(view);
  const names = Object.keys(cs);
  if (names.length === 0) return { value: view, how: "clear" };
  if (disclosed !== undefined) {
    if ("*" in cs) {
      if (!checkCommitment(cs["*"]!, disclosed)) throw new Error("the disclosed value does not match the receipt's commitment");
      return { value: disclosed, how: "disclosed" };
    }
    const d = disclosed as Record<string, unknown>;
    if (!d || typeof d !== "object") throw new Error("the disclosure must be an object with the withheld fields");
    for (const name of names) if (!checkCommitment(cs[name]!, d[name])) throw new Error(`disclosed field "${name}" does not match the receipt's commitment`);
    return { value: { ...(view as Record<string, unknown>), ...Object.fromEntries(names.map((n) => [n, d[n]])) }, how: "disclosed" };
  }
  // the key reveals only what was encrypted under it; another key is not an error, the values simply stay withheld
  if (key && names.every((n) => cs[n]!.$custody === "encrypted" && (cs[n] as Encrypted).keyid === captureKeyId(key))) {
    if ("*" in cs) return { value: reveal(cs["*"]!, key), how: "decrypted" };
    return { value: { ...(view as Record<string, unknown>), ...Object.fromEntries(names.map((n) => [n, reveal(cs[n]!, key)])) }, how: "decrypted" };
  }
  return null;
}
