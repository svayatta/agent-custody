// Private evidence: what a receipt records of a call, decided in one place. The signature and the digests are over
// the whole call as it happened; what the receipt file carries in clear is a choice, made per tool in the config, and
// applied by the issuer to the whole statement just before it is signed (`privateView`). A fixed list of structural
// paths stays in clear: ids, key ids, timestamps, the tool name, the grant, the digests and their salts, the decision
// and the ids of the policies behind it, the status, the provenance fields, and the note itself. Every other value
// under a private rule leaves a commitment in its place, sha256 over a random salt and the canonical value, so a
// reviewer who is later shown the value can check it belongs; an encrypted commitment carries the value as well,
// under a key the customer holds (AES-256-GCM). A field or path added to the receipt later starts withheld, never in
// clear. The signed note lists the withheld paths; a verifier trusts the note, not the shape of the data.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { canonicalize, digestOf, sha256Hex } from "./crypto.ts";
import type { AuthorizationPredicate } from "./receipt.ts";

export type CaptureMode = "clear" | "digest" | "encrypted";
/** One side of a call: the arguments, the result, or the facts. */
export interface CaptureSide {
  /** clear: the side in the receipt as it was; digest: withheld fields leave a commitment; encrypted: withheld fields leave a commitment and the value under the customer's key */
  mode: CaptureMode;
  /** top-level fields kept in clear in digest or encrypted mode, e.g. the amount and the customer id of a refund */
  clear?: string[];
}
/**
 * A tool's rule. Once any side is private, the rule is private: a side it does not set is withheld whole, field by
 * field, and so is every other value in the receipt that is not structural (policy errors, an error message, a denial
 * reason, the result's metadata, a provider's delivery body). A side set to mode clear stays in clear.
 */
export interface CaptureRule {
  args?: CaptureSide;
  result?: CaptureSide;
  facts?: CaptureSide;
}
/** by tool name, or "*" for every tool without a rule of its own */
export type CaptureConfig = Record<string, CaptureRule>;
/** A path into the predicate, one segment per key: `["request", "args", "reason"]`. Segments are keys, so a field named "." or "*" is just a field. */
export type Path = string[];
/**
 * On the receipt, inside the signed statement: how the call was captured and which paths are withheld. The verifier
 * trusts the note, not the shape of the data: a path the note names must hold a commitment, and commitment-shaped data
 * at a path the note does not name is ordinary data, in the digest like anything else.
 */
export interface CaptureNote {
  mode: "digest" | "encrypted";
  withheld: Path[];
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
  if (c.$custody !== "encrypted") throw new Error("this value was withheld without its value; only the party that holds it can supply it");
  if (c.keyid !== captureKeyId(key)) throw new Error(`this value was encrypted under key ${c.keyid.slice(0, 12)}…, not the one given`);
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

/** The one mode a rule withholds in: encrypted when any side is, else digest; clear when no side is private. */
export function ruleMode(rule: CaptureRule | undefined): CaptureMode {
  const modes = [rule?.args, rule?.result, rule?.facts].map((s) => s?.mode ?? "clear");
  if (modes.includes("encrypted")) return "encrypted";
  if (modes.includes("digest")) return "digest";
  return "clear";
}

/**
 * How a side is captured: null when it is in clear whole (set to clear, or every side clear); else the fields kept in
 * clear and whether its commitments carry the value encrypted. A side the rule does not set is withheld whole, field
 * by field, in the rule's mode.
 */
function sideOf(rule: CaptureRule | undefined, side: "args" | "result" | "facts", key: Buffer | undefined): { clear: Set<string>; key: Buffer | undefined } | null {
  const mode = ruleMode(rule);
  if (mode === "clear") return null;
  const s = rule?.[side];
  if (s?.mode === "clear") return null;
  return { clear: new Set(s?.clear ?? []), key: (s?.mode ?? mode) === "encrypted" ? key : undefined };
}

// ---- paths ----

export const pathKey = (p: Path) => JSON.stringify(p);
export const pathText = (p: Path) => p.map((s) => (/^[A-Za-z0-9_-]+$/.test(s) ? s : JSON.stringify(s))).join(".");
export const under = (p: Path, prefix: Path) => prefix.length <= p.length && prefix.every((s, i) => p[i] === s);
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** The value at a path, by own properties only; undefined when the path leaves the data. */
export function getAt(root: unknown, path: Path): unknown {
  let v: unknown = root;
  for (const s of path) {
    if (!isObject(v) || !own(v, s)) return undefined;
    v = v[s];
  }
  return v;
}

/** A copy with a null prototype, so a field named __proto__ stays a field. */
const plain = (o: Record<string, unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = Object.create(null);
  for (const [k, v] of Object.entries(o)) out[k] = v;
  return out;
};

/** A copy of `root` with `value` at `path`, every object on the way copied (null-prototype), the rest shared. Creates objects for missing segments. */
export function setAt<T>(root: T, path: Path, value: unknown): T {
  if (path.length === 0) return value as T;
  const [head, ...rest] = path as [string, ...string[]];
  const o = isObject(root) ? plain(root) : (Object.create(null) as Record<string, unknown>);
  o[head] = setAt(own(o, head) ? o[head] : undefined, rest, value);
  return o as T;
}

// ---- the choke point ----

/** The structural top-level parts of a statement: ids, keys, times, the grant, the names. Never withheld. */
const CLEAR_TOP = new Set(["receiptId", "timestamp", "issuer", "principal", "agent", "delegation", "session", "model", "tool", "consumed", "authorization", "capture"]);
/** Inside the parts that carry values: what stays in clear beside them. */
const CLEAR_IN = {
  request: new Set(["argsDigest", "argsSalt", "provenance"]),
  fact: new Set(["tool", "resultDigest", "resultSalt", "provenance"]),
  policy: new Set(["decision", "reasons", "policyDigest", "enforced", "provenance"]),
  execution: new Set(["status", "resultDigest", "resultSalt", "provenance"]),
  upstream: new Set(["provider", "signature", "bind", "envelope"]),
};
/** The result's error flag is its status, so it stays in clear; its metadata carries whatever an upstream put there, so it never does. */
const RESULT_ALWAYS_CLEAR = new Set(["isError"]);
const RESULT_NEVER_CLEAR = new Set(["_meta"]);

/** What the producer knows about this call that the view needs: which fact arguments copy a call argument that is in clear, and the full lookup results behind the fact digests. */
export interface CaptureContext {
  /** per fact name: the lookup arguments that may stay in clear under a private args rule (constants, or copies of call arguments the rule keeps in clear) */
  clearFactArgs?: Record<string, string[]>;
  /** per fact name: the lookup's full result, so its digest can be salted */
  factResults?: Record<string, unknown>;
}

/**
 * The statement a receipt carries under a tool's rule: the predicate with every non-structural value withheld as the
 * rule says, the three digests salted, and the note of what is withheld at `capture`. Under a clear rule, the
 * predicate itself. Applied by the issuer to every statement it signs, the authorization included.
 */
export function privateView<P extends AuthorizationPredicate>(predicate: P, rule: CaptureRule | undefined, key?: Buffer, ctx: CaptureContext = {}): P {
  const mode = ruleMode(rule);
  if (mode === "clear") return predicate;
  if (mode === "encrypted" && !key) throw new Error("capture mode encrypted needs captureKeyEnv");
  /** every value outside the three sides is withheld in the rule's mode: encrypted when any side is */
  const k = mode === "encrypted" ? key : undefined;
  const withheld: Path[] = [];
  let out: Record<string, unknown> = plain(predicate as unknown as Record<string, unknown>);
  const hide = (path: Path, value: unknown, withKey: Buffer | undefined) => {
    // nothing and null carry nothing, so they stay as they are
    if (value === undefined || value === null) return;
    out = setAt(out, path, withhold(value, withKey));
    withheld.push(path);
  };
  /** a side captured field by field: the listed fields kept, the rest withheld; a value that is not a plain object withheld whole */
  const object = (path: Path, value: unknown, side: { clear: Set<string>; key: Buffer | undefined }, always = new Set<string>(), never = new Set<string>()) => {
    if (!isObject(value)) return hide(path, value, side.key);
    for (const [f, v] of Object.entries(value)) if (never.has(f) || !(side.clear.has(f) || always.has(f))) hide([...path, f], v, side.key);
  };
  const salted = (value: unknown) => {
    const salt = randomBytes(16).toString("hex");
    return { digest: digestOf(value, salt), salt };
  };
  const argsSide = sideOf(rule, "args", key);
  const resultSide = sideOf(rule, "result", key);
  const factsSide = sideOf(rule, "facts", key);
  for (const [key_, value] of Object.entries(predicate as unknown as Record<string, unknown>)) {
    if (CLEAR_TOP.has(key_)) continue;
    if (key_ === "request" && isObject(value)) {
      for (const [f, v] of Object.entries(value)) {
        if (f === "args") {
          if (argsSide) object(["request", "args"], v, argsSide);
        } else if (!CLEAR_IN.request.has(f)) hide(["request", f], v, k);
      }
      if (own(value, "args")) {
        const s = salted(value.args);
        out = setAt(out, ["request", "argsDigest"], s.digest);
        out = setAt(out, ["request", "argsSalt"], s.salt);
      }
    } else if (key_ === "facts" && isObject(value)) {
      for (const [name, fact] of Object.entries(value)) {
        if (!isObject(fact)) {
          hide(["facts", name], fact, k);
          continue;
        }
        for (const [f, v] of Object.entries(fact)) {
          if (f === "value") {
            if (factsSide) object(["facts", name, "value"], v, factsSide);
          } else if (f === "args") {
            if (argsSide) object(["facts", name, "args"], v, { clear: new Set(ctx.clearFactArgs?.[name] ?? []), key: argsSide.key });
          } else if (!CLEAR_IN.fact.has(f)) hide(["facts", name, f], v, k);
        }
        const full = ctx.factResults?.[name];
        if (full !== undefined) {
          const s = salted(full);
          out = setAt(out, ["facts", name, "resultDigest"], s.digest);
          out = setAt(out, ["facts", name, "resultSalt"], s.salt);
        }
      }
    } else if (key_ === "policy" && isObject(value)) {
      for (const [f, v] of Object.entries(value)) {
        // an empty error list is structural (there were none); a non-empty one carries the evaluator's messages
        if (f === "errors" && Array.isArray(v) && v.length === 0) continue;
        if (!CLEAR_IN.policy.has(f)) hide(["policy", f], v, k);
      }
    } else if (key_ === "execution" && isObject(value)) {
      for (const [f, v] of Object.entries(value)) {
        if (f === "result") {
          if (resultSide) object(["execution", "result"], v, resultSide, RESULT_ALWAYS_CLEAR, RESULT_NEVER_CLEAR);
        } else if (f === "upstream" && isObject(v)) {
          // a provider's delivery is the result in another form: its body goes with the result; the signatures stay
          for (const [uf, uv] of Object.entries(v)) {
            if (uf === "rawBody") {
              if (resultSide) hide(["execution", "upstream", "rawBody"], uv, resultSide.key);
            } else if (!CLEAR_IN.upstream.has(uf)) hide(["execution", "upstream", uf], uv, k);
          }
        } else if (!CLEAR_IN.execution.has(f)) hide(["execution", f], v, k);
      }
      if (own(value, "result")) {
        const s = salted(value.result);
        out = setAt(out, ["execution", "resultDigest"], s.digest);
        out = setAt(out, ["execution", "resultSalt"], s.salt);
      }
    } else hide([key_], value, k);
  }
  if (withheld.length) out.capture = { mode, withheld } satisfies CaptureNote;
  return out as unknown as P;
}

// ---- the way back ----

export type How = "disclosed" | "decrypted";

export interface Restoration<P> {
  /** the predicate with every restorable path put back */
  predicate: P;
  /** how each restored path came back, by `pathKey` */
  restored: Map<string, How>;
  /** the withheld paths whose value could not be had */
  missing: Path[];
  /** paths where the note, the data, a disclosure, or the key contradict each other; each a reason a check must fail */
  problems: { path: Path; error: string }[];
}

/**
 * The full statement behind a view, under its note: a path the note names must hold a commitment; the value at that
 * path in the disclosure, when there is one, must match the commitment; else the key reveals what was encrypted under
 * it; else the path stays withheld. A disclosure is a partial predicate, the real values at the withheld paths, as
 * `agent-custody reveal` writes it. Nothing here throws: the problems are reported, so a verifier fails the right check.
 */
export function restorePaths<P>(predicate: P, note: CaptureNote | undefined, disclosed?: unknown, key?: Buffer): Restoration<P> {
  const r: Restoration<P> = { predicate, restored: new Map(), missing: [], problems: [] };
  if (!note) return r;
  const keyid = key ? captureKeyId(key) : null;
  for (const path of note.withheld) {
    const c = getAt(predicate, path);
    if (!isCommitment(c)) {
      r.problems.push({ path, error: `the capture note says ${pathText(path)} is withheld, but the receipt carries no commitment for it` });
      continue;
    }
    const d = disclosed === undefined ? undefined : getAt(disclosed, path);
    if (d !== undefined) {
      if (!checkCommitment(c, d)) {
        r.problems.push({ path, error: `the disclosed ${pathText(path)} does not match the receipt's commitment` });
        continue;
      }
      r.predicate = setAt(r.predicate, path, d);
      r.restored.set(pathKey(path), "disclosed");
    } else if (key && c.$custody === "encrypted" && c.keyid === keyid) {
      try {
        r.predicate = setAt(r.predicate, path, reveal(c, key));
        r.restored.set(pathKey(path), "decrypted");
      } catch (e) {
        r.problems.push({ path, error: `${pathText(path)}: ${e instanceof Error ? e.message : String(e)}` });
      }
    } else r.missing.push(path);
  }
  return r;
}
