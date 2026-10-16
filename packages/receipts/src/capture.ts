// Private evidence: what a receipt records of a call, decided in one place. The signature and the digests are over
// the whole call as it happened; what the receipt file carries in clear is a choice, made per tool in the config, and
// applied by the issuer to the whole statement just before it is signed (`privateView`). A fixed list of structural
// paths stays in clear: ids, key ids, timestamps, the tool name, the grant, the digests, the decision
// and the ids of the policies behind it, the status, the provenance fields, and the note itself. Every other value
// under a private rule leaves a commitment in its place, sha256 over a random salt and the canonical value, so a
// reviewer who is later shown the value and the salt can check it belongs; an encrypted commitment carries both as
// well, under a key the customer holds (AES-256-GCM). The salt never appears in the receipt: without it a reviewer
// cannot confirm a guess of a withheld value against the commitment (issue #126), and the digests over withheld
// values are salted with material derived from the field salts, so nothing public confirms a guess against them
// either. A field or path added to the receipt later starts withheld, never in clear. The signed note lists the
// withheld paths; a verifier trusts the note, not the shape of the data.
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
  /** sha256 over salt || canonical JSON of the value; the salt is not in the receipt */
  sha256: string;
}
export interface Encrypted {
  $custody: "encrypted";
  alg: "A256GCM";
  /** sha256 of the key, so a reviewer knows which key reveals it */
  keyid: string;
  iv: string;
  /** AES-256-GCM over the canonical JSON of `{ salt, value }` */
  ciphertext: string;
  tag: string;
  sha256: string;
}
export type Commitment = Withheld | Encrypted;
/** What a disclosure carries at a withheld path: the value and the salt the commitment was made with. Without `value` it is unfinished (`reveal --include-salts` writes it so for the holder to fill in) and fails verification. */
export interface Disclosed {
  $custody: "disclosed";
  salt: string;
  value?: unknown;
}

/** A 32-byte key from hex (64 chars) or base64 (44 chars), as an environment variable holds it. */
export function captureKeyFrom(text: string): Buffer {
  const t = text.trim();
  // strict forms only: a base64 string with stray characters would decode silently to a different key
  if (!/^[0-9a-fA-F]{64}$/.test(t) && !/^[A-Za-z0-9+/]{43}=$/.test(t)) throw new Error("capture key: expected 32 bytes as 64 hex characters or 44 characters of base64");
  const key = t.length === 64 ? Buffer.from(t, "hex") : Buffer.from(t, "base64");
  if (key.length !== 32) throw new Error("capture key: expected 32 bytes as 64 hex characters or base64");
  return key;
}
export function captureKeyId(key: Buffer): string {
  return sha256Hex(key);
}
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const B64 = /^[A-Za-z0-9+/]+=*$/;
/** A well-formed commitment: the sha256 a verifier checks, and for an encrypted one the fields the key needs. A `$custody` tag alone is not one. */
export function isCommitment(v: unknown): v is Commitment {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const c = v as Record<string, unknown>;
  if (typeof c.sha256 !== "string" || !HEX64.test(c.sha256)) return false;
  if (c.$custody === "withheld") return true;
  if (c.$custody !== "encrypted") return false;
  // a 12-byte iv and a 16-byte tag, as AES-256-GCM is used here; a shorter tag would be accepted by the cipher and must not be
  return c.alg === "A256GCM" && typeof c.keyid === "string" && HEX64.test(c.keyid) && [c.iv, c.ciphertext, c.tag].every((f) => typeof f === "string" && (f as string).length > 0 && B64.test(f as string)) && (c.iv as string).length === 16 && (c.tag as string).length === 24;
}
/** What an encrypted commitment is bound to: the receipt and the path, so a ciphertext moved to another receipt or path does not decrypt. */
export function aadFor(receiptId: unknown, path: Path): string {
  return canonicalize({ receiptId: typeof receiptId === "string" ? receiptId : null, path });
}
/** A disclosed value as a disclosure carries it: the salt, and the value when the holder has filled it in. */
export function isDisclosed(v: unknown): v is Disclosed {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const d = v as Record<string, unknown>;
  return d.$custody === "disclosed" && typeof d.salt === "string" && HEX32.test(d.salt);
}
function commit(value: unknown, salt: string): string {
  return sha256Hex(Buffer.concat([Buffer.from(salt, "hex"), Buffer.from(canonicalize(value), "utf8")]));
}

/** Replaces a value with its commitment, carrying the value and the salt encrypted when a key is given (bound to `aad`, see `aadFor`); the salt is returned to the caller, never written into the receipt. */
export function withhold(value: unknown, key?: Buffer, aad?: string): { commitment: Commitment; salt: string } {
  const salt = randomBytes(16).toString("hex");
  const sha256 = commit(value, salt);
  if (!key) return { commitment: { $custody: "withheld", sha256 }, salt };
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(canonicalize({ salt, value }), "utf8"), cipher.final()]);
  return { commitment: { $custody: "encrypted", alg: "A256GCM", keyid: captureKeyId(key), iv: iv.toString("base64"), ciphertext: ciphertext.toString("base64"), tag: cipher.getAuthTag().toString("base64"), sha256 }, salt };
}

/** True when `value` under `salt` is what the commitment was made over. */
export function checkCommitment(c: Commitment, value: unknown, salt: string): boolean {
  return HEX32.test(salt) && commit(value, salt) === c.sha256;
}

/** The value and the salt behind an encrypted commitment, under the key that made it; checked against the commitment too. */
export function reveal(c: Commitment, key: Buffer, aad?: string): { value: unknown; salt: string } {
  if (c.$custody !== "encrypted") throw new Error("this value was withheld without its value; only the party that holds it can supply it, with its salt");
  if (c.keyid !== captureKeyId(key)) throw new Error(`this value was encrypted under key ${c.keyid.slice(0, 12)}…, not the one given`);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(c.iv, "base64"));
  if (aad) decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(c.tag, "base64"));
  const text = Buffer.concat([decipher.update(Buffer.from(c.ciphertext, "base64")), decipher.final()]).toString("utf8");
  const inner = JSON.parse(text) as { salt?: unknown; value?: unknown };
  if (!inner || typeof inner !== "object" || typeof inner.salt !== "string" || !("value" in inner)) throw new Error("the decrypted content is not a salt and a value");
  if (!checkCommitment(c, inner.value, inner.salt)) throw new Error("the decrypted value does not match its commitment");
  return { value: inner.value, salt: inner.salt };
}

/**
 * The salt of a digest over a part that holds withheld values: derived from the salts of those values, in note order,
 * so whoever can restore the values can recompute the digest and nobody else can confirm a guess against it. No salt
 * when nothing under the part is withheld: the values are public, and so may the digest be.
 */
export function digestSalt(salts: string[]): string | undefined {
  return salts.length ? sha256Hex(Buffer.from(salts.join(""), "hex")) : undefined;
}

/** The tool's rule, else the "*" rule: by own property, so a tool named `constructor` or `toString` does not find an inherited member and fall through to clear. */
export function ruleFor(capture: CaptureConfig | undefined, tool: string): CaptureRule | undefined {
  if (!capture) return undefined;
  if (Object.hasOwn(capture, tool)) return capture[tool];
  return Object.hasOwn(capture, "*") ? capture["*"] : undefined;
}
const ownOf = <T>(o: Record<string, T> | undefined, k: string): T | undefined => (o && Object.hasOwn(o, k) ? o[k] : undefined);

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
export const pathText = (p: Path) => p.map((s) => (/^[A-Za-z0-9_$-]+$/.test(s) ? s : JSON.stringify(s))).join(".");
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
const CLEAR_TOP = new Set(["receiptId", "timestamp", "issuer", "principal", "agent", "delegation", "tool", "authorization", "capture"]);
/** Inside the parts that carry values: what stays in clear beside them. */
const CLEAR_IN = {
  request: new Set(["argsDigest", "provenance"]),
  fact: new Set(["tool", "resultDigest", "provenance"]),
  policy: new Set(["decision", "reasons", "policyDigest", "enforced", "provenance"]),
  execution: new Set(["status", "resultDigest", "provenance"]),
  upstream: new Set(["provider"]),
  consumed: new Set(["provenance"]),
  /** the host's correlation ids are supplied by the agent's process or its call: values, withheld; the provenance stays */
  session: new Set(["provenance"]),
  model: new Set(["provenance"]),
};
/** The result's error flag is its status, so it stays in clear when it is the boolean flag and nothing else; its metadata carries whatever an upstream put there, so it never does. */
const RESULT_ALWAYS_CLEAR = new Set(["isError"]);
const RESULT_NEVER_CLEAR = new Set(["_meta"]);
/** the slot in a captured side's view that holds the commitment over every field not kept in clear */
export const REST = "$rest";

/** What the producer knows about this call that the view needs: which fact arguments copy a call argument that is in clear, and the full lookup results behind the fact digests. */
export interface CaptureContext {
  /** per fact name: the lookup arguments that may stay in clear under a private args rule (constants, or copies of call arguments the rule keeps in clear) */
  clearFactArgs?: Record<string, string[]>;
  /** per fact name: the lookup's full result, which the receipt's `resultDigest` then commits to; without it the digest the producer computed is withheld */
  factResults?: Record<string, unknown>;
  /** the tool name is not one any upstream offers, so it is text the agent chose: under a private rule the view shows "(unknown tool)" in its place, the rule having been selected by the real name */
  unknownTool?: boolean;
}

/** The view the issuer signs, and the salts behind its commitments by `pathKey`, which the issuer keeps and never signs. */
export interface PrivateView<P> {
  predicate: P;
  salts: Record<string, string>;
}

/** The parts an authorization and its receipt share; the receipt's view takes them from the authorization's, commitments and salts alike. */
const SHARED_WITH_AUTHORIZATION = ["request", "facts", "policy", "consumed"];

/**
 * The statement a receipt carries under a tool's rule: the predicate with every non-structural value withheld as the
 * rule says, the three digests salted from the field salts, and the note of what is withheld at `capture`. Under a
 * clear rule, the predicate itself and no salts. Applied by the issuer to every statement it signs, the authorization
 * included; given the authorization's view as `prior`, the receipt's view carries the same request, facts, and policy,
 * so that the receipt still names the authorization and nothing is withheld twice.
 */
export function privateView<P extends AuthorizationPredicate>(predicate: P, rule: CaptureRule | undefined, key?: Buffer, ctx: CaptureContext = {}, prior?: PrivateView<AuthorizationPredicate>): PrivateView<P> {
  const mode = ruleMode(rule);
  if (mode === "clear") return { predicate, salts: {} };
  if (mode === "encrypted" && !key) throw new Error("capture mode encrypted needs captureKeyEnv");
  /** every value outside the three sides is withheld in the rule's mode: encrypted when any side is */
  const k = mode === "encrypted" ? key : undefined;
  const withheld: Path[] = [];
  const salts: Record<string, string> = {};
  let out: Record<string, unknown> = plain(predicate as unknown as Record<string, unknown>);
  // the note is this view's to write: one that came in with the predicate names nothing here
  delete out.capture;
  if (ctx.unknownTool && isObject(out.tool)) out.tool = { ...out.tool, name: "(unknown tool)" };
  if (prior) {
    for (const part of SHARED_WITH_AUTHORIZATION) if (own(prior.predicate as unknown as Record<string, unknown>, part)) out[part] = (prior.predicate as unknown as Record<string, unknown>)[part];
    for (const w of prior.predicate.capture?.withheld ?? []) {
      withheld.push(w);
      const s = ownOf(prior.salts, pathKey(w));
      if (s) salts[pathKey(w)] = s;
    }
  }
  const receiptId = (predicate as unknown as { receiptId?: unknown }).receiptId;
  const hide = (path: Path, value: unknown, withKey: Buffer | undefined) => {
    // nothing carries nothing; a null does (that a value was null), and is withheld like any other
    if (value === undefined) return;
    const w = withhold(value, withKey, aadFor(receiptId, path));
    out = setAt(out, path, w.commitment);
    salts[pathKey(path)] = w.salt;
    withheld.push(path);
  };
  /** the digest of a part, salted from the salts of the withheld values under it */
  const digest = (value: unknown, prefix: Path) => digestOf(value, digestSalt(withheld.filter((w) => under(w, prefix)).map((w) => salts[pathKey(w)]!)));
  /**
   * A side captured under its rule: the listed fields are kept beside one commitment, at `$rest`, over an object of
   * every other field. Field by field would leave the field names in clear, in the view and in the signed note, and
   * names are chosen by the agent or the upstream like the values are. A value that is not a plain object is withheld
   * whole. `always` names a boolean status flag that stays in clear only when it is one; `never` names fields that are
   * withheld even when listed. A field literally named `$rest` is never clear: it is withheld with the rest and comes
   * back with it.
   */
  const object = (path: Path, value: unknown, side: { clear: Set<string>; key: Buffer | undefined }, always = new Set<string>(), never = new Set<string>()) => {
    if (!isObject(value)) return hide(path, value, side.key);
    const view: Record<string, unknown> = Object.create(null);
    const rest: Record<string, unknown> = Object.create(null);
    let any = false;
    for (const [f, v] of Object.entries(value)) {
      if (f !== REST && !never.has(f) && (side.clear.has(f) || (always.has(f) && typeof v === "boolean"))) view[f] = v;
      else {
        rest[f] = v;
        any = true;
      }
    }
    if (!any) return;
    out = setAt(out, path, view);
    hide([...path, REST], rest, side.key);
  };
  /** the lookup arguments of a fact, field by field: the names are the fact config's, not the call's */
  const fields = (path: Path, value: unknown, side: { clear: Set<string>; key: Buffer | undefined }) => {
    if (!isObject(value)) return hide(path, value, side.key);
    for (const [f, v] of Object.entries(value)) if (!side.clear.has(f)) hide([...path, f], v, side.key);
  };
  const argsSide = sideOf(rule, "args", key);
  const resultSide = sideOf(rule, "result", key);
  const factsSide = sideOf(rule, "facts", key);
  for (const [key_, value] of Object.entries(predicate as unknown as Record<string, unknown>)) {
    if (CLEAR_TOP.has(key_)) continue;
    if (prior && SHARED_WITH_AUTHORIZATION.includes(key_)) continue;
    // no policy was evaluated: structural, not a value
    if (key_ === "policy" && value === null) continue;
    if (key_ === "request" && isObject(value)) {
      for (const [f, v] of Object.entries(value)) {
        if (f === "args") {
          if (argsSide) object(["request", "args"], v, argsSide);
        } else if (!CLEAR_IN.request.has(f)) hide(["request", f], v, k);
      }
      if (own(value, "args")) out = setAt(out, ["request", "argsDigest"], digest(value.args, ["request", "args"]));
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
            if (argsSide) fields(["facts", name, "args"], v, { clear: new Set(ownOf(ctx.clearFactArgs, name) ?? []), key: argsSide.key });
          } else if (!CLEAR_IN.fact.has(f)) hide(["facts", name, f], v, k);
        }
        // The fact's digest is over the lookup's full result, of which the receipt shows only the selected value: the
        // rest (metadata, other content) is never public under a private rule, whatever the selected fields are. So
        // the digest becomes a commitment to the full result (disclosed or decrypted like any value, and checked at
        // `withheld facts.<name>.resultDigest`), or, when the producer did not give the full result, the digest
        // string itself is withheld: an unsalted digest over private data would confirm a guess.
        const full = ownOf(ctx.factResults, name);
        const digestPath = ["facts", name, "resultDigest"];
        if (full !== undefined) {
          const w = withhold(full, factsSide ? factsSide.key : k, aadFor(receiptId, digestPath));
          out = setAt(out, digestPath, w.commitment);
          salts[pathKey(digestPath)] = w.salt;
          withheld.push(digestPath);
        } else hide(digestPath, fact.resultDigest, k);
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
          // a result left in clear by the rule still carries its metadata, which an upstream wrote and which may repeat the arguments: withheld under any private rule
          else if (isObject(v) && own(v, "_meta")) hide(["execution", "result", "_meta"], v._meta, k);
        } else if (f === "upstream" && isObject(v)) {
          // Everything an upstream or a provider wrote in the evidence is withheld under any private rule: the delivery
          // body and the signed envelope (a signed payload may carry any claim), and the provider's signature and bind
          // too, since the signature is a MAC over the withheld body (whoever holds the secret would confirm a guess of
          // the body against it) and the bind is a string the upstream chose. Only the provider's name stays. The
          // verifier checks the delivery once the body, the signature, and the bind are back.
          for (const [uf, uv] of Object.entries(v)) {
            if (uf === "rawBody" || uf === "envelope" || uf === "signature" || uf === "bind") hide(["execution", "upstream", uf], uv, resultSide ? resultSide.key : k);
            else if (!CLEAR_IN.upstream.has(uf)) hide(["execution", "upstream", uf], uv, k);
          }
        } else if (!CLEAR_IN.execution.has(f)) hide(["execution", f], v, k);
      }
      if (own(value, "result")) out = setAt(out, ["execution", "resultDigest"], digest(value.result, ["execution", "result"]));
    } else if ((key_ === "session" || key_ === "model") && isObject(value)) {
      // correlation ids the host or the agent supplied: a value when there is one; none is structural
      for (const [f, v] of Object.entries(value)) {
        if (v === null) continue;
        if (!CLEAR_IN[key_].has(f)) hide([key_, f], v, k);
      }
    } else if (key_ === "consumed" && isObject(value)) {
      // the fact ids an upstream declared it served are upstream-chosen strings: withheld under a private rule, an empty list being structural
      for (const [f, v] of Object.entries(value)) {
        if (f === "factIds" && Array.isArray(v) && v.length === 0) continue;
        if (!CLEAR_IN.consumed.has(f)) hide(["consumed", f], v, k);
      }
    } else hide([key_], value, k);
  }
  if (withheld.length) out.capture = { mode, withheld } satisfies CaptureNote;
  return { predicate: out as unknown as P, salts };
}

// ---- the way back ----

export type How = "disclosed" | "decrypted";

export interface Restoration<P> {
  /** the predicate with every restorable path put back */
  predicate: P;
  /** how each restored path came back, by `pathKey` */
  restored: Map<string, How>;
  /** the salt of each restored path, by `pathKey`: what the digests over them are salted from */
  salts: Map<string, string>;
  /** the value of each restored path as it was committed, by `pathKey`; a `$rest` is folded into its parent in `predicate`, so this is where it stays whole */
  values: Map<string, unknown>;
  /** the withheld paths whose value could not be had */
  missing: Path[];
  /** paths where the note, the data, a disclosure, or the key contradict each other; each a reason a check must fail */
  problems: { path: Path; error: string }[];
}

/**
 * The full statement behind a view, under its note: a path the note names must hold a commitment; the disclosure, when
 * it carries that path as `{ $custody: "disclosed", salt, value }`, must match the commitment; else the key reveals
 * what was encrypted under it; else the path stays withheld. A disclosure is a partial predicate with those at the
 * withheld paths, as `agent-custody reveal` writes it. Nothing here throws: the problems are reported, so a verifier
 * fails the right check.
 */
export function restorePaths<P>(predicate: P, note: CaptureNote | undefined, disclosed?: unknown, key?: Buffer): Restoration<P> {
  const r: Restoration<P> = { predicate, restored: new Map(), salts: new Map(), values: new Map(), missing: [], problems: [] };
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
      if (!isDisclosed(d)) {
        r.problems.push({ path, error: `the disclosed ${pathText(path)} must be { "$custody": "disclosed", "salt", "value" }, as agent-custody reveal writes it; a value alone cannot be checked` });
        continue;
      }
      // a salt without its value is what reveal --include-salts writes for the holder to complete: handed over as it
      // is, it would let a reviewer confirm guesses, so an unfinished disclosure fails rather than passes as committed
      if (!("value" in d)) {
        r.problems.push({ path, error: `the disclosed ${pathText(path)} carries a salt but no value; fill in the value or remove the entry, since a salt alone lets a reviewer confirm guesses` });
        continue;
      }
      if (!checkCommitment(c, d.value, d.salt)) {
        r.problems.push({ path, error: `the disclosed ${pathText(path)} does not match the receipt's commitment` });
        continue;
      }
      r.predicate = setAt(r.predicate, path, d.value);
      r.restored.set(pathKey(path), "disclosed");
      r.salts.set(pathKey(path), d.salt);
      r.values.set(pathKey(path), d.value);
    } else if (key && c.$custody === "encrypted" && c.keyid === keyid) {
      try {
        const back = reveal(c, key, aadFor(getAt(predicate, ["receiptId"]), path));
        r.predicate = setAt(r.predicate, path, back.value);
        r.restored.set(pathKey(path), "decrypted");
        r.salts.set(pathKey(path), back.salt);
        r.values.set(pathKey(path), back.value);
      } catch (e) {
        r.problems.push({ path, error: `${pathText(path)}: ${e instanceof Error ? e.message : String(e)}` });
      }
    } else r.missing.push(path);
  }
  // a restored `$rest` is the rest of its parent: folded back in, so the parent is the object the digest was made over
  for (const path of note.withheld) {
    if (path[path.length - 1] !== REST || !r.restored.has(pathKey(path))) continue;
    const parentPath = path.slice(0, -1);
    const parent = getAt(r.predicate, parentPath);
    if (!isObject(parent)) continue;
    const merged: Record<string, unknown> = Object.create(null);
    for (const [k, v] of Object.entries(parent)) if (k !== REST) merged[k] = v;
    const rest = parent[REST];
    if (isObject(rest)) for (const [k, v] of Object.entries(rest)) merged[k] = v;
    r.predicate = setAt(r.predicate, parentPath, merged);
  }
  return r;
}

/** The salt a digest over `prefix` was made with, once every withheld path under it is restored: see `digestSalt`. */
export function digestSaltFor<P>(r: Restoration<P>, note: CaptureNote | undefined, prefix: Path): string | undefined {
  return digestSalt((note?.withheld ?? []).filter((w) => under(w, prefix)).map((w) => r.salts.get(pathKey(w)) ?? ""));
}
