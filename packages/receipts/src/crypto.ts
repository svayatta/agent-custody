// Hashing, Ed25519 keys, and DSSE envelopes. No third-party crypto.
import { createHash, generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

/** Deterministic JSON: sorted keys, no whitespace, undefined dropped. Not full RFC 8785, but stable across runs. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    // A null-prototype object: an own property named __proto__ (which JSON.parse produces) stays a property here,
    // where on a plain object the assignment would set the prototype and the key would vanish from the digest.
    const out: Record<string, unknown> = Object.create(null);
    for (const k of Object.keys(v as object).sort()) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== undefined) out[k] = sortKeys(x);
    }
    return out;
  }
  return v;
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** sha256 over the canonical JSON of a value. */
/** sha256 over the canonical JSON of a value; with a salt (hex), over salt || canonical, so a digest over withheld values confirms no guess (issue #126). */
export function digestOf(value: unknown, salt?: string): string {
  const canonical = Buffer.from(canonicalize(value), "utf8");
  return sha256Hex(salt ? Buffer.concat([Buffer.from(salt, "hex"), canonical]) : canonical);
}

export interface PublicKeyRef {
  publicKey: KeyObject;
  keyid: string;
}

export interface KeyPair extends PublicKeyRef {
  privateKey: KeyObject;
}

/** keyid = sha256 of the SPKI DER encoding of the public key. */
export function keyidOf(publicKey: KeyObject): string {
  return sha256Hex(publicKey.export({ type: "spki", format: "der" }));
}

export function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey, keyid: keyidOf(publicKey) };
}

/** Writes <dir>/<name>.key (PKCS8 PEM, mode 0600) and <dir>/<name>.pub (SPKI PEM). */
export function writeKeyPair(kp: KeyPair, dir: string, name: string): { keyFile: string; pubFile: string } {
  mkdirSync(dir, { recursive: true });
  const keyFile = join(dir, `${name}.key`);
  const pubFile = join(dir, `${name}.pub`);
  writeFileSync(keyFile, kp.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(pubFile, kp.publicKey.export({ type: "spki", format: "pem" }));
  return { keyFile, pubFile };
}

export function loadPrivateKey(path: string): KeyPair {
  const privateKey = createPrivateKey(readFileSync(path));
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey, keyid: keyidOf(publicKey) };
}

export function loadPublicKey(path: string): PublicKeyRef {
  return publicKeyFromPem(readFileSync(path, "utf8"));
}

/** A public key from its SPKI PEM text, as found in a .pub file or a conformance vector. */
/** The SPKI PEM of a public key: what a grant carries as `agentKey`, and what `.pub` files hold. */
export function publicKeyToPem(publicKey: KeyObject): string {
  return publicKey.export({ type: "spki", format: "pem" }).toString();
}

export function publicKeyFromPem(pem: string): PublicKeyRef {
  const publicKey = createPublicKey(pem);
  return { publicKey, keyid: keyidOf(publicKey) };
}

// ---- DSSE (https://github.com/secure-systems-lab/dsse) ----

export interface Envelope {
  payloadType: string;
  payload: string; // base64
  signatures: { keyid: string; sig: string }[]; // sig base64
}

function pae(payloadType: string, payload: Buffer): Buffer {
  const header = `DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `;
  return Buffer.concat([Buffer.from(header), payload]);
}

export function dsseSign(payloadType: string, payloadObj: unknown, kp: KeyPair): Envelope {
  const payload = Buffer.from(canonicalize(payloadObj));
  const sig = sign(null, pae(payloadType, payload), kp.privateKey);
  return {
    payloadType,
    payload: payload.toString("base64"),
    signatures: [{ keyid: kp.keyid, sig: sig.toString("base64") }],
  };
}

/** Adds a signature over the same payload: a countersignature, the DSSE way. The envelope keeps every earlier signature. */
export function dsseCountersign(env: Envelope, kp: KeyPair): Envelope {
  const payload = Buffer.from(env.payload, "base64");
  const sig = sign(null, pae(env.payloadType, payload), kp.privateKey);
  return { ...env, signatures: [...env.signatures.filter((s) => s.keyid !== kp.keyid), { keyid: kp.keyid, sig: sig.toString("base64") }] };
}

/** Every trusted key whose signature on the envelope verifies, by keyid. Empty when none does. */
export function dsseVerifiers(env: Envelope, trusted: PublicKeyRef[]): string[] {
  if (!env || typeof env.payload !== "string" || !Array.isArray(env.signatures)) return [];
  const payload = Buffer.from(env.payload, "base64");
  const data = pae(env.payloadType, payload);
  const out: string[] = [];
  for (const s of env.signatures) {
    const key = trusted.find((t) => t.keyid === s.keyid);
    if (key && verify(null, data, key.publicKey, Buffer.from(s.sig, "base64"))) out.push(s.keyid);
  }
  return out;
}

export type DsseVerifyResult =
  | { ok: true; payload: unknown; keyid: string }
  | { ok: false; error: string };

/** Verifies the envelope against any of the given trusted keys, matched by keyid. */
export function dsseVerify(env: Envelope, trusted: PublicKeyRef[]): DsseVerifyResult {
  if (!env || typeof env.payload !== "string" || !Array.isArray(env.signatures) || env.signatures.length === 0) {
    return { ok: false, error: "malformed envelope" };
  }
  const payload = Buffer.from(env.payload, "base64");
  const data = pae(env.payloadType, payload);
  for (const s of env.signatures) {
    const key = trusted.find((t) => t.keyid === s.keyid);
    if (!key) continue;
    const good = verify(null, data, key.publicKey, Buffer.from(s.sig, "base64"));
    if (good) {
      try {
        return { ok: true, payload: JSON.parse(payload.toString()), keyid: s.keyid };
      } catch {
        return { ok: false, error: "payload is not JSON" };
      }
    }
    return { ok: false, error: `signature by ${s.keyid.slice(0, 12)} did not verify` };
  }
  return { ok: false, error: `no trusted key matches keyids [${env.signatures.map((s) => s.keyid.slice(0, 12)).join(", ")}]` };
}
