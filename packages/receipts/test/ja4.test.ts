// The JA4 of scripts/ja4.ts, which the capture script uses to fill the door's known-tool table. A wrong JA4 there would
// put a fingerprint in the table that no proxy ever sends. The known values are FoxIO's: the example of the JA4
// specification, and the Chromium rows of ja4plus-mapping.csv, each built here from the cipher and extension lists.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { clientHelloBytes, ja4Of } from "../scripts/ja4.ts";

const u16 = (v: number) => Buffer.from([v >> 8, v & 0xff]);
const sized = (bytes: Buffer, lengthBytes: number) => Buffer.concat([Buffer.from(bytes.length.toString(16).padStart(lengthBytes * 2, "0"), "hex"), bytes]);
const list = (values: number[]) => Buffer.concat(values.map(u16));
/** A ClientHello handshake message with these cipher suites and extensions. */
const hello = (ciphers: number[], extensions: [number, Buffer][]) => {
  const body = Buffer.concat([u16(0x0303), Buffer.alloc(32, 7), sized(Buffer.alloc(0), 1), sized(list(ciphers), 2), Buffer.from([1, 0]), sized(Buffer.concat(extensions.map(([type, data]) => Buffer.concat([u16(type), sized(data, 2)]))), 2)]);
  return Buffer.concat([Buffer.from([1]), sized(body, 3)]);
};
const record = (payload: Buffer) => Buffer.concat([Buffer.from([0x16, 3, 1]), sized(payload, 2)]);

const GREASE = 0x1a1a;
const CHROME_CIPHERS = [GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];
const SNI: [number, Buffer] = [0x0000, sized(Buffer.concat([Buffer.from([0]), sized(Buffer.from("example.com"), 2)]), 2)];
const ALPN: [number, Buffer] = [0x0010, sized(Buffer.concat([sized(Buffer.from("h2"), 1), sized(Buffer.from("http/1.1"), 1)]), 2)];
const SIGNATURES: [number, Buffer] = [0x000d, sized(list([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]), 2)];
const VERSIONS: [number, Buffer] = [0x002b, sized(list([0x2a2a, 0x0304, 0x0303]), 1)];
const empty = (type: number): [number, Buffer] => [type, Buffer.alloc(0)];
const chrome = (more: number[], sni = true) => hello(CHROME_CIPHERS, [empty(0x4a4a), ...(sni ? [SNI] : []), empty(0x0017), empty(0xff01), empty(0x000a), empty(0x000b), empty(0x0023), ALPN, empty(0x0005), SIGNATURES, empty(0x0012), empty(0x0033), empty(0x002d), VERSIONS, empty(0x001b), ...more.map(empty), empty(0x3a3a)]);

describe("the JA4 of a ClientHello", () => {
  it("gives the specification's example and the Chromium values of FoxIO's mapping", () => {
    expect(ja4Of(chrome([0x0015, 0x4469]))).toBe("t13d1516h2_8daaf6152771_e5627efa2ab1");
    expect(ja4Of(chrome([0x4469, 0xfe0d]))).toBe("t13d1516h2_8daaf6152771_02713d6af862");
    expect(ja4Of(chrome([0x0015, 0x4469, 0xfe0d]))).toBe("t13d1517h2_8daaf6152771_b1ff8ab2d16f");
    expect(ja4Of(chrome([0x4469, 0xfe0d, 0x0029]))).toBe("t13d1517h2_8daaf6152771_b0da82dd1658");
    // no server name: i, and one extension fewer
    expect(ja4Of(chrome([0x4469, 0xfe0d], false))).toBe("t13i1515h2_8daaf6152771_02713d6af862");
  });

  it("reads the TLS version of the hello when there is no supported_versions, and 00 when there is no ALPN", () => {
    expect(ja4Of(hello([0xc02f, 0x009c], [SNI, SIGNATURES]))).toMatch(/^t12d020200_[0-9a-f]{12}_[0-9a-f]{12}$/);
    expect(ja4Of(hello([0xc02f], []))).toMatch(/^t12i010000_[0-9a-f]{12}_000000000000$/);
  });

  it("gives the recorded JA4 again for each ClientHello of the committed capture", () => {
    const hellos = JSON.parse(readFileSync(join(import.meta.dirname, "..", "labelled", "capture.hellos.json"), "utf8")) as { session: string; ja4: string; hex: string }[];
    expect(hellos.length).toBeGreaterThan(5);
    for (const h of hellos) expect(ja4Of(Buffer.from(h.hex, "hex")), h.session).toBe(h.ja4);
    // FoxIO's mapping has the same cipher hashes for Chromium, Safari, and Go
    const of = (name: string) => hellos.find((h) => h.session.startsWith(name))!.ja4;
    expect(of("chrome-tls")).toContain("_8daaf6152771_");
    expect(of("safari-tls")).toMatch(/^t13d2014h2_a09f3c656075_/);
    expect(of("go-")).toContain("_9dc949149365_");
  });
});

describe("the ClientHello in the first bytes of a connection", () => {
  const message = chrome([0x4469, 0xfe0d]);
  it("waits for the whole message, joins it from its records, and leaves what follows", () => {
    const whole = record(message);
    expect(clientHelloBytes(whole.subarray(0, 3))).toBeNull();
    expect(clientHelloBytes(whole.subarray(0, whole.length - 1))).toBeNull();
    expect(clientHelloBytes(Buffer.concat([whole, Buffer.from([0x16, 3, 3])]))).toEqual(message);
    const split = Buffer.concat([record(message.subarray(0, 50)), record(message.subarray(50))]);
    expect(clientHelloBytes(split.subarray(0, 60))).toBeNull();
    expect(ja4Of(clientHelloBytes(split)!)).toBe("t13d1516h2_8daaf6152771_02713d6af862");
  });

  it("refuses bytes that are not a ClientHello", () => {
    expect(() => clientHelloBytes(Buffer.from("GET / HTTP/1.1\r\n\r\n"))).toThrow("not a TLS handshake record");
    expect(() => clientHelloBytes(record(Buffer.from([2, 0, 0, 0])))).toThrow("not a ClientHello");
  });
});
