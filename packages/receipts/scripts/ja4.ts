// The JA4 TLS client fingerprint of a ClientHello, after the FoxIO specification (JA4 TLS client, BSD-3-Clause):
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md. Only the capture script uses it: a door reads
// the JA4 that its proxy or Cloudflare computed.
import { createHash } from "node:crypto";

const VERSIONS: Record<number, string> = { 0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3" };
const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && v >> 8 === (v & 0xff);
const hex4 = (v: number) => v.toString(16).padStart(4, "0");
const hash12 = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 12);
const two = (n: number) => String(Math.min(n, 99)).padStart(2, "0");

/**
 * The first TLS handshake message in `data`, joined from its records, or null when more bytes are needed. Throws when
 * the bytes are not a ClientHello in TLS handshake records.
 */
export function clientHelloBytes(data: Buffer): Buffer | null {
  const parts: Buffer[] = [];
  let have = 0;
  let need = 4;
  for (let at = 0; have < need; ) {
    if (data.length < at + 5) return null;
    if (data[at] !== 0x16) throw new Error("not a TLS handshake record");
    const length = data.readUInt16BE(at + 3);
    if (data.length < at + 5 + length) return null;
    parts.push(data.subarray(at + 5, at + 5 + length));
    have += length;
    at += 5 + length;
    if (need === 4 && have >= 4) {
      const head = Buffer.concat(parts);
      if (head[0] !== 0x01) throw new Error("not a ClientHello");
      need = 4 + head.readUIntBE(1, 3);
    }
  }
  return Buffer.concat(parts).subarray(0, need);
}

/** The JA4 of a ClientHello handshake message (from its type byte), for a TCP connection. */
export function ja4Of(hello: Buffer): string {
  let at = 4;
  const legacyVersion = hello.readUInt16BE(at);
  at += 2 + 32;
  at += 1 + hello[at]!;
  const cipherBytes = hello.readUInt16BE(at);
  at += 2;
  const ciphers: number[] = [];
  for (let i = 0; i < cipherBytes; i += 2) ciphers.push(hello.readUInt16BE(at + i));
  at += cipherBytes;
  at += 1 + hello[at]!;
  const extensions: number[] = [];
  let signatureAlgorithms: number[] = [];
  let versions: number[] = [];
  let alpn = "00";
  if (at < hello.length) {
    const end = at + 2 + hello.readUInt16BE(at);
    at += 2;
    while (at + 4 <= end) {
      const type = hello.readUInt16BE(at);
      const length = hello.readUInt16BE(at + 2);
      const body = hello.subarray(at + 4, at + 4 + length);
      at += 4 + length;
      extensions.push(type);
      if (type === 0x000d) for (let i = 2; i + 1 < body.length; i += 2) signatureAlgorithms.push(body.readUInt16BE(i));
      if (type === 0x002b) for (let i = 1; i + 1 < body.length; i += 2) versions.push(body.readUInt16BE(i));
      if (type === 0x0010 && body.length > 3) {
        const first = body.subarray(3, 3 + body[2]!);
        const alnum = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
        if (first.length) {
          const [a, b] = [first[0]!, first[first.length - 1]!];
          alpn = alnum(a) && alnum(b) ? String.fromCharCode(a, b) : first.toString("hex")[0]! + first.toString("hex").slice(-1);
        }
      }
    }
  }
  versions = versions.filter((v) => !isGrease(v));
  signatureAlgorithms = signatureAlgorithms.filter((v) => !isGrease(v));
  const realCiphers = ciphers.filter((v) => !isGrease(v));
  const realExtensions = extensions.filter((v) => !isGrease(v));
  const version = VERSIONS[versions.length ? Math.max(...versions) : legacyVersion] ?? "00";
  const a = `t${version}${realExtensions.includes(0x0000) ? "d" : "i"}${two(realCiphers.length)}${two(realExtensions.length)}${alpn}`;
  const b = realCiphers.length ? hash12(realCiphers.map(hex4).sort().join(",")) : "000000000000";
  const hashed = realExtensions.filter((v) => v !== 0x0000 && v !== 0x0010).map(hex4).sort().join(",");
  const c = realExtensions.length ? hash12(signatureAlgorithms.length ? `${hashed}_${signatureAlgorithms.map(hex4).join(",")}` : hashed) : "000000000000";
  return `${a}_${b}_${c}`;
}
