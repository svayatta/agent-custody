// The browser verifier must agree with the reference on every published vector. This is the conformance suite in use.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditExtends, canonicalize, digestOf, dsseVerify, publicKeyFromPem, verifyBundle, verifyConsistency } from "./verify-web.ts";

const dir = join(import.meta.dirname, "..", "..", "packages", "receipts", "vectors");
const load = (f: string) => JSON.parse(readFileSync(join(dir, f), "utf8"));
const receipts = load("receipts.json");
const audit = load("audit.json");
const merkle = load("merkle.json");
const canonical = load("canonical.json");
const keyOf = (name: string) => publicKeyFromPem(receipts.keys[name].publicKeyPem);
const all = (names: string[]) => Promise.all(names.map(keyOf));

describe("browser verifier against the conformance vectors", () => {
  it("keyids", async () => {
    for (const [name, k] of Object.entries<any>(receipts.keys)) expect((await publicKeyFromPem(k.publicKeyPem)).keyid, name).toBe(k.keyid);
  });
  for (const c of receipts.cases as any[]) {
    it(`receipts: ${c.name}`, async () => {
      const r = await verifyBundle(c.bundle, { issuerKeys: await all(c.issuerKeys), principalKeys: await all(c.principalKeys), logKeys: await all(c.logKeys), ...(c.approvalKeys ? { approvalKeys: await all(c.approvalKeys) } : {}), ...(c.upstreamKeys ? { upstreamKeys: await all(c.upstreamKeys) } : {}), ...(c.providerSecrets ? { providerSecrets: c.providerSecrets } : {}), ...(c.logId ? { logId: c.logId } : {}), ...(c.log ? { logLeaves: c.log } : {}) });
      expect({ ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) }).toEqual(c.expected);
    });
  }
  for (const c of audit.cases as any[]) {
    it(`audit: ${c.name}`, async () => {
      const r = await auditExtends(c.older, c.newer, c.proof, await all(c.keys));
      expect({ ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) }).toEqual(c.expected);
    });
  }
  it("merkle consistency", async () => {
    for (const c of merkle.consistency) expect(await verifyConsistency(c.oldSize, c.oldRoot, c.newSize, c.newRoot, c.hashes), `${c.oldSize}->${c.newSize}`).toBe(c.expected);
  });
  it("canonical JSON, digests, DSSE", async () => {
    for (const v of canonical.values) { expect(canonicalize(v.value)).toBe(v.canonical); expect(await digestOf(v.value)).toBe(v.digest); }
    expect((await publicKeyFromPem(canonical.keyid.publicKeyPem)).keyid).toBe(canonical.keyid.keyid);
    expect((await dsseVerify(canonical.dsse.envelope, [await publicKeyFromPem(canonical.dsse.publicKeyPem)])).ok).toBe(canonical.dsse.expected);
  });
});
