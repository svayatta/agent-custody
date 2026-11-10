// Attestation: evidence from the platform that the gateway's signing key was made inside a measured workload.
// The key is generated in the process at start and never written out. A provider asks the platform for evidence whose
// report data is the keyid (sha256 of the public key), and the gateway signs a statement carrying that evidence with
// the key itself, logs it once, and names its digest on every receipt. A verifier given a release digest walks
// receipt key -> attestation -> image digest -> release. `simulated` evidence is signed by a published test key and
// says so in itself: it shows the plumbing, never a platform, and a verifier refuses it unless told to allow it.
import { createHash, createPrivateKey, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { join } from "node:path";
import { canonicalize, dsseSign, dsseVerify, keyidOf, publicKeyFromPem, publicKeyToPem, sha256Hex, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";
import { leafHash, verifyInclusion, type InclusionProof } from "./log.ts";
import type { LogSink } from "./log-sink.ts";
import { RECEIPT_TYPE, TREEHEAD_TYPE, type TreeHead } from "./receipt.ts";

export const ATTESTATION_PREDICATE_TYPE = "https://agent-custody.dev/attestation/v0.1";
export const SIMULATED_EVIDENCE_TYPE = "application/vnd.agent-custody.simulated-evidence+json";
export const GCP_ISSUER = "https://confidentialcomputing.googleapis.com";
export const DEFAULT_ATTESTATION_AUDIENCE = "https://agent-custody.dev/attestation";
export const GCP_TEE_SOCKET = "/run/container_launcher/teeserver.sock";

// Google's Confidential Space PKI root (CN=Confidential Space Root CA, valid 2024-01-19 to 2034-01-16, SHA-1
// B9:51:20:74:2C:24:E3:AA:34:04:2E:1C:3B:A3:AA:D2:8B:21:23:21, the fingerprint Google publishes). Copied into
// packages/state/src/verify-web.ts; keep the two identical.
export const GCP_CONFIDENTIAL_SPACE_ROOT = `-----BEGIN CERTIFICATE-----
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
uyT5CnJulxSC5CT1
-----END CERTIFICATE-----
`;

/** What the platform returned. The evidence types say what they are; `simulated` is in the type and in the payload. */
export type Evidence =
  /** a DSSE envelope signed by the published simulated key; its payload is `SimulatedEvidencePayload` */
  | { type: "simulated"; envelope: Envelope }
  /** a Confidential Space PKI token: an RS256 JWT whose x5c chain ends at Google's root */
  | { type: "gcp-confidential-space"; token: string };

export interface SimulatedEvidencePayload {
  simulated: true;
  warning: string;
  /** the keyid the evidence is bound to */
  reportData: string;
  /** the image digest the simulation claims; nothing measured it */
  imageDigest: string;
  timestamp: string;
}

export interface AttestationPredicate {
  keyid: string;
  publicKeyPem: string;
  timestamp: string;
  issuer: { kind: "gateway"; version: string };
  evidence: Evidence;
}

export interface AttestationStatement {
  _type: "https://in-toto.io/Statement/v1";
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: typeof ATTESTATION_PREDICATE_TYPE;
  predicate: AttestationPredicate;
}

/** The logged attestation: written to `receipts/attestations/<keyid>.json`. */
export interface AttestationBundle {
  envelope: Envelope;
  treeHead: Envelope;
  inclusion: InclusionProof;
}

export interface AttestationProvider {
  readonly name: Evidence["type"];
  /** evidence whose report data, or nonce, is this keyid */
  evidence(keyid: string): Promise<Evidence>;
}

const SIMULATED_SEED = createHash("sha256").update("agent-custody simulated attestation key: published on purpose, proves nothing").digest();
const SIMULATED_PRIVATE = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SIMULATED_SEED]), format: "der", type: "pkcs8" });
const SIMULATED_KEYPAIR: KeyPair = { privateKey: SIMULATED_PRIVATE, publicKey: createPublicKey(SIMULATED_PRIVATE), keyid: keyidOf(createPublicKey(SIMULATED_PRIVATE)) };
/** The published key that signs simulated evidence. Anyone can derive its private half, which is the point. */
export const SIMULATED_ATTESTATION_KEY: PublicKeyRef = { publicKey: SIMULATED_KEYPAIR.publicKey, keyid: SIMULATED_KEYPAIR.keyid };
export const SIMULATED_ATTESTATION_KEY_PEM = publicKeyToPem(SIMULATED_KEYPAIR.publicKey);
const SIMULATED_WARNING = "SIMULATED: signed by a published test key; no hardware measured this workload";

const DIGEST = /^sha256:[0-9a-f]{64}$/;

export function simulatedProvider(opts: { imageDigest: string }): AttestationProvider {
  if (!DIGEST.test(opts.imageDigest)) throw new Error(`simulated attestation: the image digest must be sha256:<64 hex>, got ${JSON.stringify(opts.imageDigest)}`);
  return {
    name: "simulated",
    async evidence(keyid) {
      const payload: SimulatedEvidencePayload = { simulated: true, warning: SIMULATED_WARNING, reportData: keyid, imageDigest: opts.imageDigest, timestamp: new Date().toISOString() };
      return { type: "simulated", envelope: dsseSign(SIMULATED_EVIDENCE_TYPE, payload, SIMULATED_KEYPAIR) };
    },
  };
}

/** POSTs to the Confidential Space launcher's socket and returns the body: the token. */
function teeServerToken(socketPath: string, body: unknown): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath, path: "/v1/token", method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(10_000) }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (c: string) => { text += c; if (text.length > 65_536) req.destroy(new Error("token response too large")); });
      res.on("end", () => (res.statusCode === 200 ? resolve(text.trim()) : reject(new Error(`the launcher refused the token request: ${res.statusCode} ${text.slice(0, 200)}`))));
    });
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

/** Confidential Space: a PKI token from the launcher, with the keyid as its nonce and the image digest measured by the launcher. */
export function gcpConfidentialSpaceProvider(opts: { audience?: string; socketPath?: string; fetchToken?: (body: { audience: string; token_type: "PKI"; nonces: string[] }) => Promise<string> } = {}): AttestationProvider {
  const audience = opts.audience ?? DEFAULT_ATTESTATION_AUDIENCE;
  const fetchToken = opts.fetchToken ?? ((body) => teeServerToken(opts.socketPath ?? GCP_TEE_SOCKET, body));
  return {
    name: "gcp-confidential-space",
    async evidence(keyid) {
      return { type: "gcp-confidential-space", token: await fetchToken({ audience, token_type: "PKI", nonces: [keyid] }) };
    },
  };
}

export type AttestationConfig = { provider: "simulated"; imageDigestEnv: string } | { provider: "gcp-confidential-space"; audience: string };

export function openAttestationProvider(cfg: AttestationConfig): AttestationProvider {
  if (cfg.provider === "simulated") {
    const digest = process.env[cfg.imageDigestEnv];
    if (!digest) throw new Error(`simulated attestation: environment variable ${cfg.imageDigestEnv} is not set; it holds the image digest the simulation claims`);
    return simulatedProvider({ imageDigest: digest });
  }
  return gcpConfidentialSpaceProvider({ audience: cfg.audience });
}

/** sha256 over the canonical attestation envelope: what a receipt's `issuer.attestation` names. */
export const attestationDigest = (env: Envelope): string => sha256Hex(canonicalize(env));

/** The attestation statement for this key, signed by the key itself. */
export async function attestKey(key: KeyPair, provider: AttestationProvider, version: string): Promise<Envelope> {
  const evidence = await provider.evidence(key.keyid);
  const st: AttestationStatement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: `issuer-key:${key.keyid}`, digest: { sha256: key.keyid } }],
    predicateType: ATTESTATION_PREDICATE_TYPE,
    predicate: { keyid: key.keyid, publicKeyPem: publicKeyToPem(key.publicKey), timestamp: new Date().toISOString(), issuer: { kind: "gateway", version }, evidence },
  };
  return dsseSign(RECEIPT_TYPE, st, key);
}

/** Attests the key, appends the statement to the log once, and writes the bundle under `<receiptsDir>/attestations/`. */
export async function logAttestation(key: KeyPair, provider: AttestationProvider, sink: LogSink, receiptsDir: string, version: string): Promise<{ bundle: AttestationBundle; digest: string; file: string }> {
  const envelope = await attestKey(key, provider, version);
  const entry = await sink.append(canonicalize(envelope));
  const bundle: AttestationBundle = { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
  const dir = join(receiptsDir, "attestations");
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${key.keyid}.json`);
  writeFileSync(file, JSON.stringify(bundle, null, 2) + "\n");
  return { bundle, digest: attestationDigest(envelope), file };
}

// ---- verification ----

export interface AttestationCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface AttestationVerifyOptions {
  bundle: AttestationBundle;
  /** the release the verifier expects: the image digest of a published, signed build (`sha256:<hex>`) */
  releaseDigest: string;
  /** accept simulated evidence; for local tests only */
  allowSimulated?: boolean;
  /** the audience the gateway asked for; default DEFAULT_ATTESTATION_AUDIENCE */
  audience?: string;
  /** PEM roots for Confidential Space tokens; default Google's root */
  gcpRoots?: string[];
}

export interface AttestationResult {
  checks: AttestationCheck[];
  /** the attested key, when its statement, evidence, and binding verify */
  key: PublicKeyRef | null;
  keyid: string | null;
  digest: string;
  simulated: boolean;
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** The statement's own public key, read before anything is trusted, so its signature can be checked with it. */
function selfKey(env: Envelope): { st: AttestationStatement; key: PublicKeyRef } | string {
  try {
    if (!env || typeof env.payload !== "string") return "malformed envelope";
    const st = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")) as AttestationStatement;
    if (!isObject(st) || st.predicateType !== ATTESTATION_PREDICATE_TYPE || !isObject(st.predicate) || typeof st.predicate.publicKeyPem !== "string") return "not an attestation statement";
    const key = publicKeyFromPem(st.predicate.publicKeyPem);
    if (key.publicKey.asymmetricKeyType !== "ed25519") return "the statement's key is not an Ed25519 key";
    return { st, key };
  } catch (e) {
    return `unreadable: ${e instanceof Error ? e.message : String(e)}`;
  }
}

interface EvidenceVerdict {
  ok: boolean;
  detail: string;
  reportData: string[];
  imageDigest: string | null;
  simulated: boolean;
}

function verifySimulated(ev: { envelope?: unknown }): EvidenceVerdict {
  const bad = (detail: string): EvidenceVerdict => ({ ok: false, detail, reportData: [], imageDigest: null, simulated: true });
  const env = ev.envelope as Envelope;
  if (!isObject(env) || env.payloadType !== SIMULATED_EVIDENCE_TYPE) return bad("the simulated evidence is not a simulated-evidence envelope");
  const v = dsseVerify(env, [SIMULATED_ATTESTATION_KEY]);
  if (!v.ok) return bad(`simulated evidence signature: ${v.error}`);
  const p = v.payload as SimulatedEvidencePayload;
  if (!isObject(p) || p.simulated !== true || typeof p.reportData !== "string" || typeof p.imageDigest !== "string" || !DIGEST.test(p.imageDigest)) return bad("the simulated evidence does not say it is simulated, or lacks its report data or image digest");
  return { ok: true, detail: "SIMULATED evidence, signed by the published test key", reportData: [p.reportData], imageDigest: p.imageDigest, simulated: true };
}

// A minimal DER reader: enough of X.509 to check a chain of RSA certificates. The browser verifier has the same one.
interface Tlv { tag: number; at: number; start: number; end: number }
function tlv(b: Buffer, at: number, limit = b.length): Tlv {
  if (at + 2 > limit) throw new Error("truncated DER");
  const tag = b[at]!;
  let len = b[at + 1]!;
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > limit) throw new Error("bad DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[start + i]!;
    start += n;
  }
  if (start + len > limit) throw new Error("truncated DER");
  return { tag, at, start, end: start + len };
}
function kids(b: Buffer, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let at = t.start; at < t.end; ) { const c = tlv(b, at, t.end); out.push(c); at = c.end; }
  return out;
}
const SHA256_RSA_OID = "06092a864886f70d01010b";
function derTime(b: Buffer, t: Tlv): number {
  const s = b.subarray(t.start, t.end).toString("latin1");
  const m = t.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : t.tag === 0x18 ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : null;
  if (!m) throw new Error("bad certificate time");
  const y = t.tag === 0x17 ? (Number(m[1]) < 50 ? 2000 : 1900) + Number(m[1]) : Number(m[1]);
  return Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}
interface Cert { tbs: Buffer; sig: Buffer; issuer: Buffer; subject: Buffer; notBefore: number; notAfter: number; spki: Buffer; raw: Buffer }
function parseCert(raw: Buffer): Cert {
  const top = tlv(raw, 0);
  if (top.tag !== 0x30 || top.end !== raw.length) throw new Error("not a certificate");
  const [tbsT, algT, sigT] = kids(raw, top);
  if (!tbsT || !algT || !sigT || sigT.tag !== 0x03 || sigT.end === sigT.start) throw new Error("not a certificate");
  const oid = kids(raw, algT)[0];
  if (!oid || raw.subarray(oid.at, oid.end).toString("hex") !== SHA256_RSA_OID) throw new Error("certificate is not signed with sha256WithRSAEncryption");
  let f = kids(raw, tbsT);
  if (f[0]?.tag === 0xa0) f = f.slice(1);
  const [, , issuer, validity, subject, spki] = f;
  if (!issuer || !validity || !subject || !spki) throw new Error("certificate is missing a field");
  const [nb, na] = kids(raw, validity);
  if (!nb || !na) throw new Error("certificate validity is malformed");
  if (raw[sigT.start] !== 0) throw new Error("signature has unused bits");
  const whole = (t: Tlv) => raw.subarray(t.at, t.end);
  return { tbs: whole(tbsT), sig: raw.subarray(sigT.start + 1, sigT.end), issuer: whole(issuer), subject: whole(subject), notBefore: derTime(raw, nb), notAfter: derTime(raw, na), spki: whole(spki), raw };
}
const pemDer = (pem: string): Buffer => Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
const b64url = (s: string): Buffer => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const rsaVerify = (spki: Buffer, data: Buffer, sig: Buffer): boolean => {
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  return key.asymmetricKeyType === "rsa" && cryptoVerify("sha256", data, key, sig);
};
const SUPPORTED_HW = ["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"];

function verifyGcp(ev: { token?: unknown }, opts: AttestationVerifyOptions): EvidenceVerdict {
  const bad = (detail: string): EvidenceVerdict => ({ ok: false, detail, reportData: [], imageDigest: null, simulated: false });
  if (typeof ev.token !== "string") return bad("the evidence carries no token");
  const parts = ev.token.split(".");
  if (parts.length !== 3) return bad("the token is not a JWT");
  const [h, p, s] = parts as [string, string, string];
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = JSON.parse(b64url(h).toString("utf8"));
    claims = JSON.parse(b64url(p).toString("utf8"));
  } catch {
    return bad("the token header or claims are not JSON");
  }
  if (!isObject(header) || !isObject(claims)) return bad("the token header or claims are not objects");
  if (header.alg !== "RS256") return bad(`the token is signed with ${String(header.alg)}, not RS256`);
  const x5c = header.x5c;
  if (!Array.isArray(x5c) || x5c.length !== 3 || !x5c.every((c) => typeof c === "string")) return bad("the token header does not carry a chain of three certificates (x5c)");
  let chain: Cert[];
  let roots: Buffer[];
  try {
    chain = x5c.map((c: string) => parseCert(Buffer.from(c, "base64")));
    roots = (opts.gcpRoots ?? [GCP_CONFIDENTIAL_SPACE_ROOT]).map(pemDer);
  } catch (e) {
    return bad(`the token's certificates: ${e instanceof Error ? e.message : String(e)}`);
  }
  const [leaf, mid, root] = chain as [Cert, Cert, Cert];
  if (!roots.some((r) => r.equals(root.raw))) return bad("the token's chain does not end at a pinned Confidential Space root");
  if (!leaf.issuer.equals(mid.subject) || !mid.issuer.equals(root.subject)) return bad("the token's chain is out of order: an issuer is not the next certificate's subject");
  try {
    if (!rsaVerify(mid.spki, leaf.tbs, leaf.sig) || !rsaVerify(root.spki, mid.tbs, mid.sig)) return bad("a certificate in the token's chain is not signed by the next one");
    if (!rsaVerify(leaf.spki, Buffer.from(`${h}.${p}`), b64url(s))) return bad("the token signature does not verify with its leaf certificate");
  } catch (e) {
    return bad(`the token's chain: ${e instanceof Error ? e.message : String(e)}`);
  }
  const iat = typeof claims.iat === "number" ? claims.iat * 1000 : NaN;
  for (const c of chain) if (!(c.notBefore <= iat && iat <= c.notAfter)) return bad("the token was issued outside a certificate's validity");
  if (claims.iss !== GCP_ISSUER) return bad(`the token's issuer is ${String(claims.iss)}`);
  const audience = opts.audience ?? DEFAULT_ATTESTATION_AUDIENCE;
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(audience)) return bad(`the token's audience is not ${audience}`);
  if (claims.swname !== "CONFIDENTIAL_SPACE") return bad(`the token's software is ${String(claims.swname)}, not CONFIDENTIAL_SPACE`);
  if (claims.dbgstat !== "disabled-since-boot") return bad(`the token's debug status is ${String(claims.dbgstat)}: a debug image lets the operator in`);
  if (typeof claims.hwmodel !== "string" || !SUPPORTED_HW.includes(claims.hwmodel)) return bad(`the token's hardware is ${String(claims.hwmodel)}`);
  if (claims.secboot !== true) return bad("the token does not say secure boot");
  const submods = isObject(claims.submods) ? claims.submods : {};
  const cs = isObject(submods.confidential_space) ? submods.confidential_space : {};
  if (!Array.isArray(cs.support_attributes) || !cs.support_attributes.includes("STABLE")) return bad("the token's Confidential Space image is not a STABLE production image");
  const container = isObject(submods.container) ? submods.container : {};
  if (typeof container.image_digest !== "string" || !DIGEST.test(container.image_digest)) return bad("the token carries no container image digest");
  const nonces = (Array.isArray(claims.eat_nonce) ? claims.eat_nonce : [claims.eat_nonce]).filter((n): n is string => typeof n === "string");
  return { ok: true, detail: `Confidential Space token from ${String(claims.hwmodel)}, chain to the pinned root`, reportData: nonces, imageDigest: container.image_digest, simulated: false };
}

/**
 * The checks from a receipt's key to a release: the statement is signed by the key it names and in the log, the
 * platform's evidence verifies, its report data is that key, and the measured image is the release the verifier gave.
 */
export function verifyAttestation(opts: AttestationVerifyOptions, logKeys: PublicKeyRef[] = []): AttestationResult {
  const checks: AttestationCheck[] = [];
  const add = (name: string, ok: boolean, detail?: string) => { checks.push(detail === undefined ? { name, ok } : { name, ok, detail }); return ok; };
  const b = opts.bundle;
  const digest = isObject(b) && isObject(b.envelope) ? attestationDigest(b.envelope) : "";
  const fail = (): AttestationResult => ({ checks, key: null, keyid: null, digest, simulated: false });
  const self = isObject(b) ? selfKey(b.envelope) : "the attestation is not a bundle";
  if (typeof self === "string") {
    add("attestation statement signature (attested key)", false, self);
    return fail();
  }
  const { st, key } = self;
  const sig = dsseVerify(b.envelope, [key]);
  const named = sig.ok && b.envelope.payloadType === RECEIPT_TYPE && st.predicate.keyid === key.keyid && st.subject?.[0]?.digest?.sha256 === key.keyid;
  if (!add("attestation statement signature (attested key)", named, sig.ok ? (named ? `keyid ${key.keyid.slice(0, 12)}` : "the statement names a key other than the one that signed it") : sig.error)) return fail();
  const th = dsseVerify(b.treeHead, [...logKeys, key]);
  let logged = false;
  if (th.ok && b.treeHead.payloadType === TREEHEAD_TYPE && isObject(b.inclusion)) {
    const head = th.payload as TreeHead;
    logged = head.treeSize === b.inclusion.treeSize && verifyInclusion(leafHash(canonicalize(b.envelope)), b.inclusion, head.rootHash);
  }
  add("attestation log inclusion", logged, th.ok ? `leaf ${b.inclusion?.leafIndex} of ${b.inclusion?.treeSize}` : th.error);
  const ev = st.predicate.evidence as { type?: unknown; envelope?: unknown; token?: unknown };
  const verdict: EvidenceVerdict = !isObject(ev) ? { ok: false, detail: "the statement carries no evidence", reportData: [], imageDigest: null, simulated: false }
    : ev.type === "simulated" ? verifySimulated(ev)
    : ev.type === "gcp-confidential-space" ? verifyGcp(ev, opts)
    : { ok: false, detail: `unknown evidence type ${String(ev.type)}`, reportData: [], imageDigest: null, simulated: false };
  add("attestation evidence", verdict.ok, verdict.detail);
  const bound = verdict.ok && verdict.reportData.includes(key.keyid);
  add("attestation binds the issuer key", bound, bound ? `report data is keyid ${key.keyid.slice(0, 12)}` : "the evidence's report data is not this key's keyid");
  const sameImage = verdict.ok && verdict.imageDigest === opts.releaseDigest;
  const built = sameImage && (!verdict.simulated || opts.allowSimulated === true);
  add("attested build", built, !verdict.ok ? "the evidence did not verify" : !sameImage ? `the measured image ${verdict.imageDigest} is not the release ${opts.releaseDigest}` : verdict.simulated ? (opts.allowSimulated ? `SIMULATED: ${verdict.imageDigest} (allowed for testing; not hardware evidence)` : "SIMULATED evidence: refused without the allow-simulated test flag") : `image ${verdict.imageDigest} is the release`);
  return { checks, key: verdict.ok && bound ? key : null, keyid: key.keyid, digest, simulated: verdict.simulated };
}
