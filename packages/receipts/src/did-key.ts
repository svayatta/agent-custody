// did:key identifiers for Ed25519 keys (W3C CCG did:key method): "did:key:z" followed by the base58btc encoding of the
// multicodec prefix for ed25519-pub (0xed 0x01) and the 32-byte public key. The identifier is the key: anyone can
// derive the key from it, and nothing about it says who holds the key or whether a principal trusts it.
import { createPublicKey, type KeyObject } from "node:crypto";
import { keyidOf, publicKeyFromPem, type PublicKeyRef } from "./crypto.ts";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_PUB = [0xed, 0x01];
export const DID_KEY_PREFIX = "did:key:";

export function base58btcEncode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

export function base58btcDecode(text: string): Uint8Array {
  let n = 0n;
  for (const ch of text) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`"${ch}" is not a base58btc character`);
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const ch of text) {
    if (ch !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/** The did:key of an Ed25519 public key. */
export function didKeyOf(publicKey: KeyObject): string {
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error(`did:key here is for Ed25519 keys; got ${publicKey.asymmetricKeyType}`);
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  return `${DID_KEY_PREFIX}z${base58btcEncode(Uint8Array.from([...ED25519_PUB, ...raw]))}`;
}

/** The Ed25519 key a did:key names; throws, saying why, when it does not decode to one. */
export function publicKeyFromDidKey(did: string): PublicKeyRef {
  // an Ed25519 did:key is 56 characters; the decode is quadratic, so a much longer one is refused before it
  if (did.length > 100) throw new Error(`the did:key is ${did.length} characters; an Ed25519 did:key is 56`);
  if (!did.startsWith(`${DID_KEY_PREFIX}z`)) throw new Error(`"${did.slice(0, 40)}" is not a base58btc did:key (did:key:z...)`);
  const bytes = base58btcDecode(did.slice(DID_KEY_PREFIX.length + 1));
  if (bytes[0] !== ED25519_PUB[0] || bytes[1] !== ED25519_PUB[1]) throw new Error("the did:key does not name an Ed25519 key (multicodec 0xed01)");
  if (bytes.length !== 34) throw new Error(`the did:key's Ed25519 key is ${bytes.length - 2} bytes, not 32`);
  const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(bytes.subarray(2)).toString("base64url") }, format: "jwk" });
  return { publicKey, keyid: keyidOf(publicKey) };
}

/** Why a did:key agent does not check out, or null when it decodes and agrees with the grant's agentKey. */
export function didKeyAgentFault(did: string, agentKey: string | undefined): string | null {
  let named: PublicKeyRef;
  try {
    named = publicKeyFromDidKey(did);
  } catch (e) {
    return `the grant's did:key agent does not decode: ${e instanceof Error ? e.message : String(e)}`;
  }
  if (agentKey === undefined) return null;
  try {
    if (publicKeyFromPem(agentKey).keyid === named.keyid) return null;
  } catch {
    return "the grant's agentKey is not a public key";
  }
  return "the grant's agentKey is not the key its did:key agent names";
}
