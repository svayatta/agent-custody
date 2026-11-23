// Web Bot Auth at the door: an RFC 9421 HTTP message signature, checked against the Ed25519 key that the signer's own
// origin publishes in its key directory (draft-meunier-web-bot-auth-architecture-05,
// draft-meunier-http-message-signatures-directory-05). A signature that checks proves the request was signed by a key
// published at the `Signature-Agent` origin, for this door's authority, inside a short window. It proves nothing about
// the body, the path, or the method unless the signature covers them.
//
// A signature whose `keyid` is a did:key is checked against the key that the did:key names, with no directory. It
// proves that the signer holds that key, and nothing else. Anyone can make such a key, so the door (`classifyArrival`)
// accepts it only with a grant for that did:key.
import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { DID_KEY_PREFIX, publicKeyFromDidKey } from "./did-key.ts";

export const DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
export const DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json";
export const WEB_BOT_AUTH_TAG = "web-bot-auth";
/** an unreachable or unusable directory is asked again after this long, however long a good one is kept */
const DIRECTORY_RETRY_MS = 30_000;

// ---- RFC 8941 structured fields: the subset a signature needs ----

export type BareItem =
  | { t: "string"; v: string }
  | { t: "token"; v: string }
  | { t: "integer"; v: number }
  | { t: "decimal"; v: number }
  | { t: "bytes"; v: Buffer }
  | { t: "boolean"; v: boolean };
export type Params = [string, BareItem][];
export interface SfItem { item: BareItem; params: Params }
export interface SfInnerList { list: SfItem[]; params: Params }
export type SfMember = SfItem | SfInnerList;

class SfParser {
  i = 0;
  s: string;
  constructor(s: string) {
    this.s = s;
  }
  fail(what: string): never {
    throw new Error(`not a structured field: ${what} at character ${this.i}`);
  }
  peek(): string | undefined {
    return this.s[this.i];
  }
  sp() {
    while (this.s[this.i] === " ") this.i++;
  }
  ows() {
    while (this.s[this.i] === " " || this.s[this.i] === "\t") this.i++;
  }
  key(): string {
    const start = this.i;
    if (!/[a-z*]/.test(this.peek() ?? "")) this.fail("a key starts with a lowercase letter or *");
    while (/[a-z0-9_\-.*]/.test(this.peek() ?? "")) this.i++;
    return this.s.slice(start, this.i);
  }
  bare(): BareItem {
    const c = this.peek() ?? "";
    if (c === "-" || /[0-9]/.test(c)) return this.number();
    if (c === '"') return this.string();
    if (c === "*" || /[A-Za-z]/.test(c)) return this.token();
    if (c === ":") return this.bytes();
    if (c === "?") return this.boolean();
    return this.fail("an item");
  }
  number(): BareItem {
    const start = this.i;
    if (this.peek() === "-") this.i++;
    while (/[0-9.]/.test(this.peek() ?? "")) this.i++;
    const text = this.s.slice(start, this.i);
    if (/^-?[0-9]{1,15}$/.test(text)) return { t: "integer", v: Number(text) };
    if (/^-?[0-9]{1,12}\.[0-9]{1,3}$/.test(text)) return { t: "decimal", v: Number(text) };
    return this.fail("a number");
  }
  string(): BareItem {
    this.i++;
    let out = "";
    for (;;) {
      const c = this.s[this.i++];
      if (c === undefined) this.fail("an unterminated string");
      if (c === "\\") {
        const n = this.s[this.i++];
        if (n !== '"' && n !== "\\") this.fail("an escape other than \\\" or \\\\");
        out += n;
      } else if (c === '"') return { t: "string", v: out };
      else if (c < " " || c > "~") this.fail("a character outside a string's range");
      else out += c;
    }
  }
  token(): BareItem {
    const start = this.i;
    this.i++;
    while (/[!#$%&'*+\-.^_`|~0-9A-Za-z:/]/.test(this.peek() ?? "")) this.i++;
    return { t: "token", v: this.s.slice(start, this.i) };
  }
  bytes(): BareItem {
    this.i++;
    const start = this.i;
    while (/[A-Za-z0-9+/=]/.test(this.peek() ?? "")) this.i++;
    if (this.peek() !== ":") this.fail("an unterminated byte sequence");
    const v = Buffer.from(this.s.slice(start, this.i), "base64");
    this.i++;
    return { t: "bytes", v };
  }
  boolean(): BareItem {
    this.i++;
    const c = this.s[this.i++];
    if (c !== "0" && c !== "1") this.fail("a boolean");
    return { t: "boolean", v: c === "1" };
  }
  params(): Params {
    const out: Params = [];
    while (this.peek() === ";") {
      this.i++;
      this.sp();
      const k = this.key();
      let v: BareItem = { t: "boolean", v: true };
      if (this.peek() === "=") {
        this.i++;
        v = this.bare();
      }
      const at = out.findIndex(([name]) => name === k);
      if (at >= 0) out[at] = [k, v];
      else out.push([k, v]);
    }
    return out;
  }
  item(): SfItem {
    const item = this.bare();
    return { item, params: this.params() };
  }
  member(): SfMember {
    if (this.peek() !== "(") return this.item();
    this.i++;
    const list: SfItem[] = [];
    for (;;) {
      this.sp();
      if (this.peek() === ")") {
        this.i++;
        return { list, params: this.params() };
      }
      list.push(this.item());
      if (this.peek() !== " " && this.peek() !== ")") this.fail("an inner list");
    }
  }
  end() {
    this.sp();
    if (this.i !== this.s.length) this.fail("trailing characters");
  }
}

/** An RFC 8941 dictionary. A later member of the same name replaces an earlier one, as the RFC says. */
export function parseDictionary(text: string): Map<string, SfMember> {
  const p = new SfParser(text);
  const out = new Map<string, SfMember>();
  p.sp();
  if (p.i === text.length) return out;
  for (;;) {
    const k = p.key();
    let m: SfMember;
    if (p.peek() === "=") {
      p.i++;
      m = p.member();
    } else m = { item: { t: "boolean", v: true }, params: p.params() };
    out.delete(k);
    out.set(k, m);
    p.ows();
    if (p.i === text.length) return out;
    if (p.peek() !== ",") p.fail("a comma between members");
    p.i++;
    p.ows();
    if (p.i === text.length) p.fail("a trailing comma");
  }
}

/** An RFC 8941 item on its own, such as a legacy `Signature-Agent: "https://..."`. */
export function parseItem(text: string): SfItem {
  const p = new SfParser(text);
  p.sp();
  const it = p.item();
  p.end();
  return it;
}

function serializeBare(b: BareItem): string {
  switch (b.t) {
    case "string": return `"${b.v.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
    case "token": return b.v;
    case "integer": return String(b.v);
    case "decimal": {
      const r = Math.round(b.v * 1000) / 1000;
      return Number.isInteger(r) ? `${r}.0` : String(r);
    }
    case "bytes": return `:${b.v.toString("base64")}:`;
    case "boolean": return b.v ? "?1" : "?0";
  }
}
const serializeParams = (ps: Params) => ps.map(([k, v]) => (v.t === "boolean" && v.v ? `;${k}` : `;${k}=${serializeBare(v)}`)).join("");
const serializeItem = (i: SfItem) => serializeBare(i.item) + serializeParams(i.params);
export const serializeMember = (m: SfMember): string => ("list" in m ? `(${m.list.map(serializeItem).join(" ")})${serializeParams(m.params)}` : serializeItem(m));

const param = (ps: Params, name: string) => ps.find(([k]) => k === name)?.[1];

// ---- RFC 9421 ----

/** What a signature base is built from: the request as the door received it. */
export interface SignedRequest {
  method: string;
  /** the request target as received, path and query, never decoded */
  target: string;
  /** the authority the request was sent to, normalised (`normalizeAuthority`) */
  authority: string;
  /** every value of a header field, lowercase name; undefined when the field is absent */
  header(name: string): string[] | undefined;
}

/** A host as RFC 9421 compares it: lowercase, without the default port of https or http. */
export function normalizeAuthority(host: string): string {
  return host.trim().toLowerCase().replace(/:(443|80)$/, "");
}

/**
 * The RFC 9421 signature base (section 2.5) for the covered components and their parameters. Supports `@method`,
 * `@authority`, `@path`, `@query`, and header fields, whole or one dictionary member (`;key`). Any other derived
 * component or component parameter is refused rather than guessed at.
 */
export function signatureBase(req: SignedRequest, input: SfInnerList): string {
  const lines: string[] = [];
  const seen = new Set<string>();
  const q = req.target.indexOf("?");
  const rawPath = q >= 0 ? req.target.slice(0, q) : req.target;
  for (const c of input.list) {
    if (c.item.t !== "string") throw new Error("a covered component is not a string");
    const name = c.item.v;
    const id = serializeItem(c);
    if (seen.has(id)) throw new Error(`the component ${id} is covered twice`);
    seen.add(id);
    let value: string;
    if (name.startsWith("@")) {
      if (c.params.length) throw new Error(`the component ${id} has parameters this door does not support`);
      if (name === "@method") value = req.method;
      else if (name === "@authority") value = req.authority;
      else if (name === "@path") value = rawPath || "/";
      else if (name === "@query") value = q >= 0 ? req.target.slice(q) : "?";
      else throw new Error(`the component ${name} is not one this door checks (it checks @method, @authority, @path, @query, and header fields)`);
    } else {
      if (name !== name.toLowerCase()) throw new Error(`the component name ${name} is not lowercase`);
      const values = req.header(name);
      if (!values) throw new Error(`the request has no ${name} field, which the signature covers`);
      const joined = values.map((v) => v.trim()).join(", ");
      const key = param(c.params, "key");
      if (c.params.some(([k]) => k !== "key")) throw new Error(`the component ${id} has parameters this door does not support`);
      if (key) {
        if (key.t !== "string") throw new Error(`the key of ${name} is not a string`);
        const member = parseDictionary(joined).get(key.v);
        if (!member) throw new Error(`the ${name} field has no member ${key.v}`);
        value = serializeMember(member);
      } else value = joined;
    }
    lines.push(`${id}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeMember(input)}`);
  return lines.join("\n");
}

/** The RFC 7638 thumbprint of an Ed25519 JWK (RFC 8037 appendix A.3): the base64url SHA-256 of `{"crv","kty","x"}`. */
export function jwkThumbprint(x: string): string {
  return createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest("base64url");
}

export interface WebBotAuthOptions {
  /** the signature agents, as https origins, whose directories the door may fetch; any other is refused unfetched */
  agents: string[];
  /** the authorities this door serves; a signature covering any other `@authority` is refused */
  authorities: string[];
  requireNonce: boolean;
  maxAgeSeconds: number;
  clockSkewSeconds: number;
  timeoutMs: number;
  maxDirectoryBytes: number;
  cacheSeconds: number;
  maxNonces: number;
}

/**
 * What the door made of a request's signature. `verified`: a signature tagged `web-bot-auth` checked against a key
 * that `agent`'s directory publishes, or against the key that its did:key `keyid` names (`agent` is then that did:key).
 * `invalid`: the signature, its parameters, its agent, or the directory was wrong.
 * `unavailable`: the directory could not be fetched, or the door could not record the nonce. `unchecked`: a signature
 * arrived and the door has no `webBotAuth` config. `absent`: no `Signature-Input`.
 */
export type SignatureCheck =
  | { outcome: "verified"; agent: string; keyid: string; label: string }
  | { outcome: "invalid" | "unavailable"; error: string; agent?: string; keyid?: string }
  | { outcome: "unchecked" | "absent" };

interface DirectoryKey { key: KeyObject; nbf?: number; exp?: number }
type Directory = { ok: true; keys: Map<string, DirectoryKey> } | { ok: false; outcome: "invalid" | "unavailable"; error: string };

export interface WebBotAuthVerifier {
  /** `grantAgent`: the did:key that a trusted grant, or a trusted registry's passport, in the request names; a did:key signature keeps its nonce only for that agent */
  verify(req: SignedRequest, grantAgent?: string): Promise<SignatureCheck>;
  /** nonces held now, or undefined when the nonce store does not count them */
  nonces(): number | undefined;
}

/** `free`: not held, and there is room to record it. `replayed`: held, unexpired. `full`: no room to record another. */
export type NonceState = "free" | "replayed" | "full";

/**
 * Where the door remembers the nonces of the signatures it verified, keyed `<agent> <keyid> <nonce>`. `claim` records a
 * key until `until` (milliseconds since the epoch) unless it is held already, and does both as one step: two arrivals
 * with one nonce get one `claimed`. `check` is asked before the directory is fetched, so a replay or a full store costs
 * no fetch; `claim` decides. A store that throws or rejects makes the signature `unavailable`, never `verified`.
 */
export interface NonceStore {
  check?(key: string): NonceState | Promise<NonceState>;
  claim(key: string, until: number): "claimed" | "replayed" | "full" | Promise<"claimed" | "replayed" | "full">;
  /** keys held now, where the store can count them */
  size?(): number;
}

/** The default nonce store: one process's (or one isolate's) memory, at most `maxNonces` keys, an expired key dropped when room is needed. */
export function createMemoryNonceStore(maxNonces: number, now: () => number = () => Date.now()): NonceStore {
  const nonces = new Map<string, number>();
  const held = (key: string) => {
    const until = nonces.get(key);
    return until !== undefined && until > now();
  };
  const room = (): boolean => {
    if (nonces.size < maxNonces) return true;
    const t = now();
    for (const [k, until] of nonces) if (until <= t) nonces.delete(k);
    return nonces.size < maxNonces;
  };
  return {
    check: (key) => (held(key) ? "replayed" : room() ? "free" : "full"),
    claim(key, until) {
      if (held(key)) return "replayed";
      nonces.set(key, until);
      return "claimed";
    },
    size: () => nonces.size,
  };
}

/** A response body up to `max` bytes; null when it passes that, and the rest is not read. */
export async function readCapped(res: Response, max: number): Promise<Buffer | null> {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return Buffer.concat(chunks);
    size += value.length;
    if (size > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
}

/** The directory's Ed25519 keys by thumbprint. Keys of other types are skipped: this door checks Ed25519 only. */
function parseDirectory(body: Buffer): Map<string, DirectoryKey> {
  const doc = JSON.parse(body.toString("utf8")) as { keys?: unknown };
  if (!doc || !Array.isArray(doc.keys)) throw new Error("the directory is not a JWKS: no keys array");
  const keys = new Map<string, DirectoryKey>();
  for (const k of doc.keys as Record<string, unknown>[]) {
    if (!k || k.kty !== "OKP" || k.crv !== "Ed25519" || typeof k.x !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(k.x)) continue;
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k.x }, format: "jwk" });
    keys.set(jwkThumbprint(k.x), { key, ...(typeof k.nbf === "number" ? { nbf: k.nbf } : {}), ...(typeof k.exp === "number" ? { exp: k.exp } : {}) });
  }
  return keys;
}

/** An https origin with nothing after it, as the config holds it; throws on anything else. */
export function agentOrigin(uri: string): string {
  const u = new URL(uri);
  if (u.protocol !== "https:") throw new Error(`the signature agent ${uri} is not https`);
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== DIRECTORY_PATH)) throw new Error(`the signature agent ${uri} is not an origin or its directory`);
  return u.origin;
}

/**
 * Checks Web Bot Auth signatures. The directory of each configured agent is fetched from
 * `<origin>/.well-known/http-message-signatures-directory` over https, never following a redirect, within `timeoutMs`
 * and `maxDirectoryBytes`, and kept for `cacheSeconds` (a failure for 30 seconds). A nonce is remembered until the
 * signature it came with could no longer be accepted, so a signature serves one request. Nonces are kept in `nonceStore`,
 * by default this process's memory (`maxNonces` of them); a door that runs as many processes or isolates needs a store
 * they share, or a signature refused by one is accepted once by another. `now` is for tests.
 */
export function createWebBotAuthVerifier(opts: WebBotAuthOptions, f: typeof fetch, now: () => number = () => Date.now(), nonceStore?: NonceStore): WebBotAuthVerifier {
  const agents = new Set(opts.agents.map(agentOrigin));
  const authorities = new Set(opts.authorities.map(normalizeAuthority));
  const cache = new Map<string, { at: number; dir: Directory }>();
  const inflight = new Map<string, Promise<Directory>>();
  const nonces = nonceStore ?? createMemoryNonceStore(opts.maxNonces, now);
  const storeDown = (e: unknown) => `the door could not reach its nonce store, so it cannot refuse a replay: ${e instanceof Error ? e.message : String(e)}`;

  const fetchDirectory = async (origin: string): Promise<Directory> => {
    const url = `${origin}${DIRECTORY_PATH}`;
    try {
      const res = await f(url, { headers: { accept: DIRECTORY_MEDIA_TYPE }, redirect: "manual", signal: AbortSignal.timeout(opts.timeoutMs) });
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => undefined);
        return { ok: false, outcome: "invalid", error: `the directory at ${url} redirected${res.headers.get("location") ? ` to ${res.headers.get("location")}` : ""}; a directory is served from the signature agent's own origin` };
      }
      if (!res.ok) {
        await res.body?.cancel().catch(() => undefined);
        return { ok: false, outcome: "unavailable", error: `the directory at ${url} answered ${res.status}` };
      }
      const type = (res.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
      if (type !== DIRECTORY_MEDIA_TYPE) {
        await res.body?.cancel().catch(() => undefined);
        return { ok: false, outcome: "invalid", error: `the directory at ${url} is served as ${type || "no media type"}, not ${DIRECTORY_MEDIA_TYPE}` };
      }
      const body = await readCapped(res, opts.maxDirectoryBytes);
      if (!body) return { ok: false, outcome: "invalid", error: `the directory at ${url} is larger than ${opts.maxDirectoryBytes} bytes` };
      try {
        return { ok: true, keys: parseDirectory(body) };
      } catch (e) {
        return { ok: false, outcome: "invalid", error: `the directory at ${url} is not usable: ${e instanceof Error ? e.message : String(e)}` };
      }
    } catch (e) {
      return { ok: false, outcome: "unavailable", error: `the directory at ${url} could not be fetched: ${e instanceof Error ? e.message : String(e)}` };
    }
  };

  const directory = (origin: string): Promise<Directory> => {
    const hit = cache.get(origin);
    if (hit && now() - hit.at < (hit.dir.ok ? opts.cacheSeconds * 1000 : Math.min(DIRECTORY_RETRY_MS, opts.cacheSeconds * 1000))) return Promise.resolve(hit.dir);
    const pending = inflight.get(origin);
    if (pending) return pending;
    const p = fetchDirectory(origin).then((dir) => {
      cache.set(origin, { at: now(), dir });
      inflight.delete(origin);
      return dir;
    });
    inflight.set(origin, p);
    return p;
  };

  async function verify(req: SignedRequest, grantAgent?: string): Promise<SignatureCheck> {
    const inputText = req.header("signature-input");
    const sigText = req.header("signature");
    if (!inputText && !sigText) return { outcome: "absent" };
    const invalid = (error: string, extra: { agent?: string; keyid?: string } = {}): SignatureCheck => ({ outcome: "invalid", error, ...extra });
    if (!inputText || !sigText) return invalid(`${inputText ? "Signature-Input" : "Signature"} arrived without ${inputText ? "Signature" : "Signature-Input"}`);
    let inputs: Map<string, SfMember>;
    let sigs: Map<string, SfMember>;
    try {
      inputs = parseDictionary(inputText.join(", "));
      sigs = parseDictionary(sigText.join(", "));
    } catch (e) {
      return invalid(`the signature headers do not parse: ${e instanceof Error ? e.message : String(e)}`);
    }
    // the first signature tagged web-bot-auth; another tag is a signature for some other purpose
    const entry = [...inputs].find(([, m]) => "list" in m && param(m.params, "tag")?.t === "string" && param(m.params, "tag")!.v === WEB_BOT_AUTH_TAG);
    if (!entry) return invalid(`no signature is tagged ${WEB_BOT_AUTH_TAG}`);
    const [label, member] = entry;
    const input = member as SfInnerList;
    const sig = sigs.get(label);
    if (!sig || "list" in sig || sig.item.t !== "bytes") return invalid(`the Signature field has no byte sequence for ${label}`);
    const keyidP = param(input.params, "keyid");
    const createdP = param(input.params, "created");
    const expiresP = param(input.params, "expires");
    const algP = param(input.params, "alg");
    const nonceP = param(input.params, "nonce");
    if (keyidP?.t !== "string") return invalid(`${label} has no keyid`);
    const keyid = keyidP.v;
    if (createdP?.t !== "integer" || expiresP?.t !== "integer") return invalid(`${label} needs both created and expires`, { keyid });
    if (algP && !(algP.t === "string" && algP.v === "ed25519")) return invalid(`${label} uses alg ${serializeBare(algP)}; this door checks ed25519 only`, { keyid });
    if (nonceP && nonceP.t !== "string") return invalid(`${label} has a nonce that is not a string`, { keyid });

    // the covered components: @authority, and the Signature-Agent member that names the directory (none for a did:key)
    const covered = input.list;
    if (!covered.some((c) => c.item.t === "string" && c.item.v === "@authority" && c.params.length === 0)) return invalid(`${label} does not cover @authority`, { keyid });
    let agent: string;
    let didKey: KeyObject | undefined;
    if (keyid.startsWith(DID_KEY_PREFIX)) {
      // a did:key keyid carries its key: the signer is the did:key, and no Signature-Agent or directory is necessary
      try {
        didKey = publicKeyFromDidKey(keyid).publicKey;
      } catch (e) {
        return invalid(`the keyid of ${label} does not decode: ${e instanceof Error ? e.message : String(e)}`, { keyid });
      }
      agent = keyid;
    } else {
      const agentComponent = covered.find((c) => c.item.t === "string" && c.item.v === "signature-agent");
      const agentText = req.header("signature-agent");
      if (!agentComponent || !agentText) return invalid(agentText ? `${label} does not cover signature-agent` : "no Signature-Agent field names the signer's directory", { keyid });
      let agentUri: string;
      try {
        const key = param(agentComponent.params, "key");
        const named = key?.t === "string" ? parseDictionary(agentText.join(", ")).get(key.v) : parseItem(agentText.join(", "));
        if (!named || "list" in named || named.item.t !== "string") return invalid(`the Signature-Agent ${key?.t === "string" ? `member ${key.v} ` : ""}is not a string`, { keyid });
        agentUri = named.item.v;
      } catch (e) {
        return invalid(`the Signature-Agent field does not parse: ${e instanceof Error ? e.message : String(e)}`, { keyid });
      }
      try {
        agent = agentOrigin(agentUri);
      } catch (e) {
        return invalid(e instanceof Error ? e.message : String(e), { keyid });
      }
      if (!agents.has(agent)) return invalid(`${agent} is not a signature agent this door is configured to check`, { agent, keyid });
    }

    // the window: created is not in the future, the signature has not expired, and it is no older than maxAgeSeconds
    const t = now() / 1000;
    const skew = opts.clockSkewSeconds;
    const created = createdP.v;
    const expires = expiresP.v;
    if (created > t + skew) return invalid(`${label} was created ${Math.round(created - t)} s in the future`, { agent, keyid });
    if (expires <= created) return invalid(`${label} expires before it was created`, { agent, keyid });
    if (t > expires + skew) return invalid(`${label} expired at ${new Date(expires * 1000).toISOString()}`, { agent, keyid });
    if (t > created + opts.maxAgeSeconds + skew) return invalid(`${label} was created ${Math.round(t - created)} s ago, more than the ${opts.maxAgeSeconds} s this door accepts`, { agent, keyid });
    if (!authorities.has(req.authority)) return invalid(`@authority ${req.authority || "(none)"} is not an authority this door serves`, { agent, keyid });

    let base: string;
    try {
      base = signatureBase(req, input);
    } catch (e) {
      return invalid(e instanceof Error ? e.message : String(e), { agent, keyid });
    }
    if (opts.requireNonce && !nonceP) return invalid(`${label} has no nonce, and this door requires one`, { agent, keyid });
    // Anyone can make a did:key, so a stranger's signatures must not fill the nonce store. A did:key signature that no
    // trusted grant or passport names is never accepted by the door, and its nonce is not kept.
    const nonceKey = nonceP && (!didKey || keyid === grantAgent) ? `${agent} ${keyid} ${nonceP.v}` : undefined;
    const full: SignatureCheck = { outcome: "unavailable", error: nonceStore ? "the door's nonce store is full and cannot record another" : `the door holds ${opts.maxNonces} nonces and cannot record another`, agent, keyid };
    if (nonceKey && nonces.check) {
      let state: NonceState;
      try {
        state = await nonces.check(nonceKey);
      } catch (e) {
        return { outcome: "unavailable", error: storeDown(e), agent, keyid };
      }
      if (state === "replayed") return invalid(`${label} repeats a nonce already used`, { agent, keyid });
      if (state === "full") return full;
    }

    let key = didKey;
    if (!key) {
      const dir = await directory(agent);
      if (!dir.ok) return { outcome: dir.outcome, error: dir.error, agent, keyid };
      const k = dir.keys.get(keyid);
      if (!k) return invalid(`keyid ${keyid} is not an Ed25519 key in ${agent}'s directory`, { agent, keyid });
      if ((k.nbf !== undefined && t + skew < k.nbf) || (k.exp !== undefined && t - skew > k.exp)) return invalid(`keyid ${keyid} is outside the validity its directory gives it`, { agent, keyid });
      key = k.key;
    }
    if (!cryptoVerify(null, Buffer.from(base, "utf8"), key, sig.item.v)) return invalid(didKey ? `${label} does not verify with the key that ${keyid} names` : `${label} does not verify with ${agent}'s key ${keyid}`, { agent, keyid });
    if (nonceKey) {
      // claimed only once the signature verifies, so a forgery cannot spend a nonce; an arrival with this nonce that
      // verified while the directory was fetched has claimed it, and this one is refused
      let claim: "claimed" | "replayed" | "full";
      try {
        claim = await nonces.claim(nonceKey, (Math.min(expires, created + opts.maxAgeSeconds) + skew) * 1000 + 1000);
      } catch (e) {
        return { outcome: "unavailable", error: storeDown(e), agent, keyid };
      }
      if (claim === "replayed") return invalid(`${label} repeats a nonce already used`, { agent, keyid });
      if (claim === "full") return full;
    }
    return { outcome: "verified", agent, keyid, label };
  }

  return { verify, nonces: () => nonces.size?.() };
}
