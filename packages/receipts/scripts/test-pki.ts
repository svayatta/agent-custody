// A test PKI for the Confidential Space attestation checks: a three-certificate RSA chain and tokens signed with its
// leaf, shaped like the PKI tokens Google documents. Every name says TEST; nothing here passes against Google's root.
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";

const len = (n: number): Buffer => (n < 128 ? Buffer.from([n]) : (() => { const b: number[] = []; for (let x = n; x > 0; x = Math.floor(x / 256)) b.unshift(x % 256); return Buffer.from([0x80 | b.length, ...b]); })());
const tag = (t: number, ...parts: Buffer[]): Buffer => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([t]), len(body.length), body]); };
const seq = (...p: Buffer[]) => tag(0x30, ...p);
const int = (n: number) => tag(0x02, Buffer.from([n]));
const oid = (hex: string) => Buffer.from(hex, "hex");
const SHA256_RSA = seq(oid("06092a864886f70d01010b"), Buffer.from([0x05, 0x00]));
const name = (cn: string) => seq(tag(0x31, seq(oid("0603550403"), tag(0x0c, Buffer.from(cn, "utf8")))));
const utc = (d: Date) => tag(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z", "latin1"));

export interface TestCert { der: Buffer; key: KeyObject; publicKey: KeyObject; pem: string }

function cert(cn: string, issuerCn: string, serial: number, subjectKey: KeyObject, issuerKey: KeyObject, notBefore: Date, notAfter: Date): Buffer {
  const tbs = seq(tag(0xa0, int(2)), int(serial), SHA256_RSA, name(issuerCn), seq(utc(notBefore), utc(notAfter)), name(cn), subjectKey.export({ type: "spki", format: "der" }));
  return seq(tbs, SHA256_RSA, tag(0x03, Buffer.from([0]), sign("sha256", tbs, issuerKey)));
}
const rsa = () => generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;

export interface TestChain { root: TestCert; intermediate: TestCert; leaf: TestCert }

/** A TEST root, intermediate, and leaf, valid from a year ago to ten years ahead. */
export function testChain(opts: { notBefore?: Date; notAfter?: Date } = {}): TestChain {
  const nb = opts.notBefore ?? new Date(Date.now() - 365 * 86_400_000);
  const na = opts.notAfter ?? new Date(Date.now() + 3650 * 86_400_000);
  const [r, i, l] = [rsa(), rsa(), rsa()];
  const rootDer = cert("agent-custody TEST root, not Google", "agent-custody TEST root, not Google", 1, r.publicKey, r.privateKey, nb, na);
  const midDer = cert("agent-custody TEST intermediate", "agent-custody TEST root, not Google", 2, i.publicKey, r.privateKey, nb, na);
  const leafDer = cert("agent-custody TEST token signer", "agent-custody TEST intermediate", 3, l.publicKey, i.privateKey, nb, na);
  const wrap = (der: Buffer, k: { publicKey: KeyObject; privateKey: KeyObject }): TestCert => ({ der, key: k.privateKey, publicKey: k.publicKey, pem: pem(der) });
  return { root: wrap(rootDer, r), intermediate: wrap(midDer, i), leaf: wrap(leafDer, l) };
}

/** An intermediate for `leaf` signed by a key of the caller's choosing: a forged link under someone else's root. */
export function forgedIntermediate(subjectKey: KeyObject, signer: KeyObject, issuerCn: string): Buffer {
  return cert("agent-custody TEST intermediate", issuerCn, 9, subjectKey, signer, new Date(Date.now() - 86_400_000), new Date(Date.now() + 86_400_000));
}

const b64url = (b: Buffer) => b.toString("base64url");

/** A JWT in the shape of a Confidential Space PKI token, signed by the chain's leaf. */
export function testToken(claims: Record<string, unknown>, x5c: Buffer[], key: KeyObject, header: Record<string, unknown> = {}): string {
  const h = b64url(Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", x5c: x5c.map((d) => d.toString("base64")), ...header })));
  const p = b64url(Buffer.from(JSON.stringify(claims)));
  return `${h}.${p}.${b64url(sign("sha256", Buffer.from(`${h}.${p}`), key))}`;
}

/** The claims a production Confidential Space token carries, by Google's token claims reference, for this key and image. */
export function testClaims(keyid: string, imageDigest: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: "https://confidentialcomputing.googleapis.com",
    aud: "https://agent-custody.dev/attestation",
    sub: "https://www.googleapis.com/compute/v1/projects/TEST/zones/TEST/instances/TEST",
    iat: now,
    nbf: now,
    exp: now + 3600,
    eat_nonce: keyid,
    secboot: true,
    oemid: 11129,
    hwmodel: "GCP_AMD_SEV",
    swname: "CONFIDENTIAL_SPACE",
    swversion: ["TEST"],
    dbgstat: "disabled-since-boot",
    submods: {
      confidential_space: { support_attributes: ["LATEST", "STABLE", "USABLE"] },
      container: { image_reference: "ghcr.io/svayatta/agent-custody-gateway@" + imageDigest, image_digest: imageDigest, restart_policy: "Never" },
      gce: { zone: "TEST", project_id: "TEST", instance_name: "TEST" },
    },
    ...over,
  };
}
