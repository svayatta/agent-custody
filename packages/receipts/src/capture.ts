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
/**
 * On the receipt beside a captured part: how it was captured and which fields are withheld. A value that was not a
 * plain object is withheld whole, and `whole: true` says so; a field literally named "*" is just a field. The note is
 * inside the signed statement, and a verifier trusts it, not the shape of the data: a field the note names must be a
 * commitment, and commitment-shaped data the note does not name is ordinary data, in the digest like anything else.
 */
export interface CaptureNote {
  mode: "digest" | "encrypted";
  withheld: string[];
  whole?: true;
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
  if (!value || typeof value !== "object" || Array.isArray(value)) return { view: withhold(value, k), note: { mode, withheld: ["*"], whole: true } };
  const keep = new Set([...(side.clear ?? []), ...alwaysClear]);
  // a null-prototype object, so a field named __proto__ is recorded rather than setting the prototype (as canonicalize does)
  const view: Record<string, unknown> = Object.create(null);
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

/**
 * The commitments a capture note declares, read from the view: the whole value, or the named fields. Throws when the
 * note names a field that is not a commitment in the view, which no honest issuer produces: a verifier must not skip
 * a digest on the strength of a note the data does not bear out.
 */
export function commitmentsIn(view: unknown, note: CaptureNote): { whole: Commitment } | { fields: Record<string, Commitment> } {
  if (note.whole) {
    if (!isCommitment(view)) throw new Error("the capture note says the value is withheld whole, but the receipt carries no commitment");
    return { whole: view };
  }
  if (!view || typeof view !== "object" || Array.isArray(view)) throw new Error("the capture note names withheld fields, but the receipt carries no object");
  const fields: Record<string, Commitment> = Object.create(null);
  for (const name of note.withheld) {
    const v = (view as Record<string, unknown>)[name];
    if (!isCommitment(v)) throw new Error(`the capture note says field "${name}" is withheld, but the receipt carries no commitment for it`);
    fields[name] = v;
  }
  return { fields };
}

export type Restored = { value: unknown; how: "clear" | "disclosed" | "decrypted" };

/** A copy with a null prototype, so a field named __proto__ stays a field through the spread. */
const plain = (o: Record<string, unknown>, over: Record<string, unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = Object.create(null);
  for (const [k, v] of Object.entries(o)) out[k] = v;
  for (const [k, v] of Object.entries(over)) out[k] = v;
  return out;
};

/**
 * The full value behind a view, under its capture note: the view itself when there is no note; the disclosed value
 * when one is given and every declared commitment matches it; the decrypted value when the key is given and every
 * withheld field is encrypted under it. Null when the value cannot be had. Throws when the note does not match the
 * data, or a disclosure or a key contradicts a commitment.
 */
export function restore(view: unknown, note: CaptureNote | undefined, disclosed?: unknown, key?: Buffer): Restored | null {
  if (!note) return { value: view, how: "clear" };
  const cs = commitmentsIn(view, note);
  if ("whole" in cs) {
    if (disclosed !== undefined) {
      if (!checkCommitment(cs.whole, disclosed)) throw new Error("the disclosed value does not match the receipt's commitment");
      return { value: disclosed, how: "disclosed" };
    }
    if (key && cs.whole.$custody === "encrypted" && cs.whole.keyid === captureKeyId(key)) return { value: reveal(cs.whole, key), how: "decrypted" };
    return null;
  }
  const names = Object.keys(cs.fields);
  if (disclosed !== undefined) {
    const d = disclosed as Record<string, unknown>;
    if (!d || typeof d !== "object" || Array.isArray(d)) throw new Error("the disclosure must be an object with the withheld fields");
    for (const name of names) if (!checkCommitment(cs.fields[name]!, d[name])) throw new Error(`disclosed field "${name}" does not match the receipt's commitment`);
    return { value: plain(view as Record<string, unknown>, Object.fromEntries(names.map((n) => [n, d[n]]))), how: "disclosed" };
  }
  // the key reveals only what was encrypted under it; another key is not an error, the values simply stay withheld
  if (key && names.every((n) => cs.fields[n]!.$custody === "encrypted" && (cs.fields[n] as Encrypted).keyid === captureKeyId(key))) {
    return { value: plain(view as Record<string, unknown>, Object.fromEntries(names.map((n) => [n, reveal(cs.fields[n]!, key)]))), how: "decrypted" };
  }
  return null;
}
