// The attested-build check: a receipt key is trusted only through an attestation whose evidence binds that key and
// whose measured image is the release the verifier names. Each test here fails when one link of that chain is
// skipped: a different image, a key outside the attestation, simulated evidence without the test flag, or evidence
// edited after the fact. The gateway tests run the real gateway with the simulated provider, as the local demo does.
import { spawnSync } from "node:child_process";
import { X509Certificate, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { attestationDigest, attestKey, GCP_CONFIDENTIAL_SPACE_ROOT, gcpConfidentialSpaceProvider, SIMULATED_ATTESTATION_KEY_PEM, SIMULATED_EVIDENCE_TYPE, simulatedProvider, verifyAttestation, type AttestationBundle, type AttestationProvider, type AttestationStatement } from "../src/attestation.ts";
import { GatewayConfigSchema, loadConfig } from "../src/config.ts";
import { canonicalize, dsseSign, generateKeyPair, loadPrivateKey, publicKeyFromPem, publicKeyToPem, type Envelope, type KeyPair } from "../src/crypto.ts";
import { createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import { serveHttp } from "../src/gateway-http.ts";
import { fileLog } from "../src/log-sink.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { forgedIntermediate, testChain, testClaims, testToken } from "../scripts/test-pki.ts";

const IMAGE = `sha256:${"a1".repeat(32)}`;
const OTHER = `sha256:${"b2".repeat(32)}`;
const decode = <T>(env: Envelope) => JSON.parse(Buffer.from(env.payload, "base64").toString()) as T;
const failing = (r: { checks: { name: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.name);

async function logged(key: KeyPair, provider: AttestationProvider, edit?: (st: AttestationStatement) => void): Promise<AttestationBundle> {
  let envelope = await attestKey(key, provider, "test");
  if (edit) {
    const st = decode<AttestationStatement>(envelope);
    edit(st);
    envelope = dsseSign(RECEIPT_TYPE, st, key);
  }
  const entry = await fileLog(join(mkdtempSync(join(tmpdir(), "att-log-")), "log.jsonl"), key).append(canonicalize(envelope));
  return { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
}

describe("the pinned Confidential Space root", () => {
  it("is Google's root by the fingerprint Google publishes", () => {
    const c = new X509Certificate(GCP_CONFIDENTIAL_SPACE_ROOT);
    expect(c.fingerprint).toBe("B9:51:20:74:2C:24:E3:AA:34:04:2E:1C:3B:A3:AA:D2:8B:21:23:21");
    expect(c.subject).toContain("CN=Confidential Space Root CA");
  });

  it("the browser verifier pins the same root and the same simulated key", () => {
    const web = readFileSync(join(import.meta.dirname, "..", "..", "state", "src", "verify-web.ts"), "utf8");
    expect(web).toContain(GCP_CONFIDENTIAL_SPACE_ROOT.trim());
    expect(web).toContain(SIMULATED_ATTESTATION_KEY_PEM.trim());
  });
});

describe("simulated attestation", () => {
  it("verifies as an attested build only with the test flag, and says SIMULATED", async () => {
    const key = generateKeyPair();
    const bundle = await logged(key, simulatedProvider({ imageDigest: IMAGE }));
    const refused = verifyAttestation({ bundle, releaseDigest: IMAGE });
    expect(failing(refused)).toEqual(["attested build"]);
    expect(refused.checks.find((c) => c.name === "attested build")?.detail).toMatch(/SIMULATED evidence: refused/);
    const allowed = verifyAttestation({ bundle, releaseDigest: IMAGE, allowSimulated: true });
    expect(failing(allowed)).toEqual([]);
    expect(allowed.simulated).toBe(true);
    expect(allowed.key?.keyid).toBe(key.keyid);
    expect(allowed.checks.find((c) => c.name === "attested build")?.detail).toMatch(/^SIMULATED/);
  });

  it("the evidence says simulated in itself, and losing that marker fails it", async () => {
    const key = generateKeyPair();
    const bundle = await logged(key, simulatedProvider({ imageDigest: IMAGE }));
    const ev = decode<AttestationStatement>(bundle.envelope).predicate.evidence as { type: string; envelope: Envelope };
    expect(ev.type).toBe("simulated");
    expect(ev.envelope.payloadType).toBe(SIMULATED_EVIDENCE_TYPE);
    expect(decode<{ simulated: boolean; warning: string }>(ev.envelope)).toMatchObject({ simulated: true, warning: expect.stringMatching(/^SIMULATED/) });
  });

  it("a different release digest fails attested build", async () => {
    const bundle = await logged(generateKeyPair(), simulatedProvider({ imageDigest: IMAGE }));
    const r = verifyAttestation({ bundle, releaseDigest: OTHER, allowSimulated: true });
    expect(failing(r)).toEqual(["attested build"]);
  });

  it("evidence edited after it was signed fails, even inside a statement the key re-signed", async () => {
    const key = generateKeyPair();
    const bundle = await logged(key, simulatedProvider({ imageDigest: IMAGE }), (st) => {
      const ev = st.predicate.evidence as { envelope: Envelope };
      const p = decode<Record<string, unknown>>(ev.envelope);
      ev.envelope = { ...ev.envelope, payload: Buffer.from(canonicalize({ ...p, imageDigest: OTHER })).toString("base64") };
    });
    const r = verifyAttestation({ bundle, releaseDigest: OTHER, allowSimulated: true });
    expect(failing(r)).toEqual(["attestation evidence", "attestation binds the issuer key", "attested build"]);
    expect(r.key).toBeNull();
  });

  it("evidence bound to another key does not attest this one", async () => {
    const key = generateKeyPair();
    const other = await simulatedProvider({ imageDigest: IMAGE }).evidence(generateKeyPair().keyid);
    const bundle = await logged(key, simulatedProvider({ imageDigest: IMAGE }), (st) => { st.predicate.evidence = other; });
    const r = verifyAttestation({ bundle, releaseDigest: IMAGE, allowSimulated: true });
    expect(failing(r)).toEqual(["attestation binds the issuer key"]);
    expect(r.key).toBeNull();
  });

  it("a statement edited without the key's signature fails its signature", async () => {
    const key = generateKeyPair();
    const bundle = await logged(key, simulatedProvider({ imageDigest: IMAGE }));
    const st = decode<AttestationStatement>(bundle.envelope);
    st.predicate.timestamp = "2020-01-01T00:00:00.000Z";
    const r = verifyAttestation({ bundle: { ...bundle, envelope: { ...bundle.envelope, payload: Buffer.from(canonicalize(st)).toString("base64") } }, releaseDigest: IMAGE, allowSimulated: true });
    expect(failing(r)).toEqual(["attestation statement signature (attested key)"]);
  });

  it("a statement signed by a key other than the one it names fails", async () => {
    const key = generateKeyPair();
    const thief = generateKeyPair();
    const env = await attestKey(key, simulatedProvider({ imageDigest: IMAGE }), "test");
    const st = decode<AttestationStatement>(env);
    st.predicate.publicKeyPem = publicKeyToPem(thief.publicKey);
    const resigned = dsseSign(RECEIPT_TYPE, st, thief);
    const entry = await fileLog(join(mkdtempSync(join(tmpdir(), "att-log-")), "log.jsonl"), thief).append(canonicalize(resigned));
    const r = verifyAttestation({ bundle: { envelope: resigned, treeHead: entry.treeHead, inclusion: entry.inclusion }, releaseDigest: IMAGE, allowSimulated: true });
    expect(failing(r)).toContain("attestation statement signature (attested key)");
  });

  it("a statement that names an RSA key fails its signature check rather than throwing", async () => {
    const key = generateKeyPair();
    const bundle = await logged(key, simulatedProvider({ imageDigest: IMAGE }));
    const st = decode<AttestationStatement>(bundle.envelope);
    st.predicate.publicKeyPem = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }) as string;
    const r = verifyAttestation({ bundle: { ...bundle, envelope: { ...bundle.envelope, payload: Buffer.from(canonicalize(st)).toString("base64") } }, releaseDigest: IMAGE, allowSimulated: true });
    expect(failing(r)).toEqual(["attestation statement signature (attested key)"]);
  });

  it("an attestation that is not in the log fails log inclusion", async () => {
    const key = generateKeyPair();
    const bundle = await logged(key, simulatedProvider({ imageDigest: IMAGE }));
    const r = verifyAttestation({ bundle: { ...bundle, inclusion: { ...bundle.inclusion, leafIndex: bundle.inclusion.leafIndex + 1 } }, releaseDigest: IMAGE, allowSimulated: true });
    expect(failing(r)).toEqual(["attestation log inclusion"]);
  });
});

describe("Confidential Space evidence", () => {
  const chain = testChain();
  const roots = [chain.root.pem];
  const x5c = [chain.leaf.der, chain.intermediate.der, chain.root.der];
  const tokenFor = (keyid: string, over: Record<string, unknown> = {}) => testToken(testClaims(keyid, IMAGE, over), x5c, chain.leaf.key);
  const provider = (token: (keyid: string) => string): AttestationProvider => ({ name: "gcp-confidential-space", async evidence(keyid) { return { type: "gcp-confidential-space", token: token(keyid) }; } });

  it("the test certificates are well-formed X.509, so the reader is not only checked against its own writer", () => {
    expect(new X509Certificate(chain.leaf.der).verify(chain.intermediate.publicKey)).toBe(true);
    expect(new X509Certificate(chain.intermediate.der).verify(chain.root.publicKey)).toBe(true);
  });

  it("a production token for this key and image verifies as an attested build", async () => {
    const key = generateKeyPair();
    const bundle = await logged(key, provider((k) => tokenFor(k)));
    const r = verifyAttestation({ bundle, releaseDigest: IMAGE, gcpRoots: roots });
    expect(failing(r)).toEqual([]);
    expect(r.simulated).toBe(false);
  });

  it("the gateway asks the launcher for a PKI token with the keyid as its nonce", async () => {
    let asked: unknown;
    const p = gcpConfidentialSpaceProvider({ fetchToken: async (body) => { asked = body; return "a.b.c"; } });
    const key = generateKeyPair();
    expect(await p.evidence(key.keyid)).toEqual({ type: "gcp-confidential-space", token: "a.b.c" });
    expect(asked).toEqual({ audience: "https://agent-custody.dev/attestation", token_type: "PKI", nonces: [key.keyid] });
  });

  it("a chain that does not end at a pinned root fails: by default only Google's root is pinned", async () => {
    const bundle = await logged(generateKeyPair(), provider((k) => tokenFor(k)));
    const r = verifyAttestation({ bundle, releaseDigest: IMAGE });
    expect(failing(r)).toEqual(["attestation evidence", "attestation binds the issuer key", "attested build"]);
    expect(r.checks.find((c) => c.name === "attestation evidence")?.detail).toMatch(/pinned Confidential Space root/);
  });

  it("Google's real root at the end of a chain whose intermediate it never signed fails", async () => {
    const googleRoot = Buffer.from(GCP_CONFIDENTIAL_SPACE_ROOT.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
    const forged = forgedIntermediate(chain.intermediate.publicKey, chain.root.key, "Confidential Space Root CA");
    const bundle = await logged(generateKeyPair(), provider((k) => testToken(testClaims(k, IMAGE), [chain.leaf.der, forged, googleRoot], chain.leaf.key)));
    const r = verifyAttestation({ bundle, releaseDigest: IMAGE });
    expect(failing(r)).toContain("attestation evidence");
    expect(r.checks.find((c) => c.name === "attestation evidence")?.detail).toMatch(/out of order|not signed by the next one/);
  });

  for (const [what, over, pattern] of [
    ["a debug image", { dbgstat: "enabled" }, /debug/],
    ["a token for another audience", { aud: "https://example.com" }, /audience/],
    ["a plain GCE VM", { swname: "GCE" }, /CONFIDENTIAL_SPACE/],
    ["a Shielded VM without memory encryption", { hwmodel: "GCP_SHIELDED_VM" }, /hardware/],
    ["an image not marked STABLE", { submods: { confidential_space: { support_attributes: ["EXPERIMENTAL"] }, container: { image_digest: IMAGE } } }, /STABLE/],
    ["a token from another issuer", { iss: "https://portal.trustauthority.intel.com" }, /issuer/],
  ] as const) {
    it(`${what} fails the evidence`, async () => {
      const bundle = await logged(generateKeyPair(), provider((k) => tokenFor(k, over)));
      const r = verifyAttestation({ bundle, releaseDigest: IMAGE, gcpRoots: roots });
      expect(failing(r)).toContain("attestation evidence");
      expect(r.checks.find((c) => c.name === "attestation evidence")?.detail).toMatch(pattern);
    });
  }

  it("a token whose claims were edited fails its signature", async () => {
    const bundle = await logged(generateKeyPair(), provider((k) => {
      const [h, , s] = tokenFor(k).split(".");
      return `${h}.${Buffer.from(JSON.stringify(testClaims(k, OTHER))).toString("base64url")}.${s}`;
    }));
    const r = verifyAttestation({ bundle, releaseDigest: OTHER, gcpRoots: roots });
    expect(failing(r)).toContain("attestation evidence");
    expect(r.checks.find((c) => c.name === "attestation evidence")?.detail).toMatch(/token signature/);
  });

  it("a token whose nonce is another key does not attest this one", async () => {
    const bundle = await logged(generateKeyPair(), provider(() => tokenFor(generateKeyPair().keyid)));
    expect(failing(verifyAttestation({ bundle, releaseDigest: IMAGE, gcpRoots: roots }))).toEqual(["attestation binds the issuer key"]);
  });

  it("a token for another image fails attested build", async () => {
    const bundle = await logged(generateKeyPair(), provider((k) => tokenFor(k)));
    expect(failing(verifyAttestation({ bundle, releaseDigest: OTHER, gcpRoots: roots }))).toEqual(["attested build"]);
  });

  it("a token issued outside its certificates' validity fails", async () => {
    const old = testChain({ notBefore: new Date(Date.now() - 2 * 86_400_000), notAfter: new Date(Date.now() - 86_400_000) });
    const bundle = await logged(generateKeyPair(), provider((k) => testToken(testClaims(k, IMAGE), [old.leaf.der, old.intermediate.der, old.root.der], old.leaf.key)));
    const r = verifyAttestation({ bundle, releaseDigest: IMAGE, gcpRoots: [old.root.pem] });
    expect(r.checks.find((c) => c.name === "attestation evidence")?.detail).toMatch(/validity/);
  });
});

describe("the gateway with an attested key", () => {
  const saved = process.env.AGENT_CUSTODY_IMAGE_DIGEST;
  afterEach(() => { if (saved === undefined) delete process.env.AGENT_CUSTODY_IMAGE_DIGEST; else process.env.AGENT_CUSTODY_IMAGE_DIGEST = saved; });

  function attestedFixture() {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "att-gw-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    delete cfg.identity.keyFile;
    cfg.attestation = { provider: "simulated" };
    writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
    return fx;
  }

  async function oneReceipt(fx: ReturnType<typeof buildFixture>) {
    process.env.AGENT_CUSTODY_IMAGE_DIGEST = IMAGE;
    const cfg = loadConfig(fx.configFile);
    const host = await createGatewayHost(cfg);
    try {
      const gw = host.open(JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope);
      const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
      const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(res._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
      const attestation = JSON.parse(readFileSync(host.attestationFile!, "utf8")) as AttestationBundle;
      return { host, bundle, attestation };
    } finally {
      await host.close();
    }
  }

  it("makes its key in memory, writes no key file, logs the attestation once, and names it on every receipt", async () => {
    const fx = attestedFixture();
    const before = readdirSync(join(fx.dir, "keys")).sort();
    const { host, bundle, attestation } = await oneReceipt(fx);
    expect(readdirSync(join(fx.dir, "keys")).sort()).toEqual(before);
    const st = decode<ReceiptStatement>(bundle.envelope);
    expect(st.predicate.issuer.attestation).toBe(attestationDigest(attestation.envelope));
    expect(st.predicate.issuer.keyid).toBe(host.keyid);
    expect(attestation.inclusion.leafIndex).toBe(0);
    expect(bundle.inclusion.leafIndex).toBeGreaterThan(0);
    expect(readFileSync(fx.logFile, "utf8")).toContain(JSON.stringify(canonicalize(attestation.envelope)));
  });

  it("a receipt verifies as an attested build (simulated) with only the attestation, and fails without the test flag", async () => {
    const fx = attestedFixture();
    const { bundle, attestation } = await oneReceipt(fx);
    const principal = loadPrivateKey(join(fx.dir, "keys", "principal.key"));
    const base = { issuerKeys: [], principalKeys: [{ publicKey: principal.publicKey, keyid: principal.keyid }], logFile: fx.logFile };
    const ok = verifyBundle(bundle, { ...base, attestation: { bundle: attestation, releaseDigest: IMAGE, allowSimulated: true } });
    expect(failing(ok)).toEqual([]);
    expect(ok.checks.map((c) => c.name)).toEqual(expect.arrayContaining(["attested build", "receipt signed by the attested key", "receipt names the attestation"]));
    expect(failing(verifyBundle(bundle, { ...base, attestation: { bundle: attestation, releaseDigest: IMAGE } }))).toEqual(["attested build"]);
    expect(failing(verifyBundle(bundle, { ...base, attestation: { bundle: attestation, releaseDigest: OTHER, allowSimulated: true } }))).toEqual(["attested build"]);
  });

  it("a receipt signed by a key outside the attestation fails, whether or not the verifier trusts that key", async () => {
    const fx = attestedFixture();
    const { bundle, attestation } = await oneReceipt(fx);
    const outside = generateKeyPair();
    const st = decode<ReceiptStatement>(bundle.envelope);
    st.predicate.issuer.keyid = outside.keyid;
    const forged = { ...bundle, envelope: dsseSign(RECEIPT_TYPE, st, outside) };
    const att = { bundle: attestation, releaseDigest: IMAGE, allowSimulated: true };
    expect(failing(verifyBundle(forged, { issuerKeys: [], principalKeys: [], attestation: att }))).toContain("receipt signature (issuer key)");
    const trusted = verifyBundle(forged, { issuerKeys: [{ publicKey: outside.publicKey, keyid: outside.keyid }], principalKeys: [], attestation: att });
    expect(failing(trusted)).toContain("receipt signed by the attested key");
  });

  it("a receipt that names another attestation fails", async () => {
    const fx = attestedFixture();
    const { bundle } = await oneReceipt(fx);
    const st = decode<ReceiptStatement>(bundle.envelope);
    const key = generateKeyPair();
    const own = await logged(key, simulatedProvider({ imageDigest: IMAGE }));
    st.predicate.issuer.keyid = key.keyid;
    const resigned = { ...bundle, envelope: dsseSign(RECEIPT_TYPE, st, key) };
    const r = verifyBundle(resigned, { issuerKeys: [], principalKeys: [], attestation: { bundle: own, releaseDigest: IMAGE, allowSimulated: true } });
    expect(failing(r)).toContain("receipt names the attestation");
  });

  it("serves its attestation at GET /attestation, and the CLI checks it alone before any receipt", async () => {
    const fx = attestedFixture();
    process.env.AGENT_CUSTODY_IMAGE_DIGEST = IMAGE;
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const running = await serveHttp(host, { port: 0 });
    let served: AttestationBundle;
    try {
      const res = await fetch(new URL("/attestation", running.url), { signal: AbortSignal.timeout(5000) });
      expect(res.status).toBe(200);
      served = (await res.json()) as AttestationBundle;
    } finally {
      await running.close();
      await host.close();
    }
    expect(served).toEqual(JSON.parse(readFileSync(host.attestationFile!, "utf8")));
    const file = join(fx.dir, "served-attestation.json");
    writeFileSync(file, JSON.stringify(served));
    const cli = (...args: string[]) => spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "verify", "--attestation", file, ...args], { encoding: "utf8" });
    const allowed = cli("--release-digest", IMAGE, "--allow-simulated-attestation");
    expect(allowed.status, allowed.stderr).toBe(0);
    expect(allowed.stdout).toMatch(/RESULT: ATTESTED BUILD \(SIMULATED\)/);
    const refused = cli("--release-digest", IMAGE);
    expect(refused.status).toBe(1);
    expect(refused.stdout).toMatch(/FAIL  attested build/);
  });

  it("a gateway with a key file answers 404 at /attestation", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "att-plain-")));
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const running = await serveHttp(host, { port: 0 });
    try {
      expect((await fetch(new URL("/attestation", running.url), { signal: AbortSignal.timeout(5000) })).status).toBe(404);
    } finally {
      await running.close();
      await host.close();
    }
  });

  it("refuses to start without the image digest the simulation claims", async () => {
    const fx = attestedFixture();
    delete process.env.AGENT_CUSTODY_IMAGE_DIGEST;
    await expect(createGatewayHost(loadConfig(fx.configFile))).rejects.toThrow(/AGENT_CUSTODY_IMAGE_DIGEST/);
    expect(existsSync(join(fx.receiptsDir, "attestations"))).toBe(false);
  });

  it("the config takes a key file or an attestation, never both and never neither", () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "att-cfg-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    expect(GatewayConfigSchema.safeParse(cfg).success).toBe(true);
    expect(GatewayConfigSchema.safeParse({ ...cfg, attestation: { provider: "simulated" } }).success).toBe(false);
    expect(GatewayConfigSchema.safeParse({ ...cfg, identity: {} }).success).toBe(false);
    expect(GatewayConfigSchema.safeParse({ ...cfg, identity: {}, attestation: { provider: "gcp-confidential-space" } }).success).toBe(true);
  });
});


describe("the attestation vectors", () => {
  const v = JSON.parse(readFileSync(join(import.meta.dirname, "..", "vectors", "attestation.json"), "utf8"));
  const key = (n: string) => publicKeyFromPem(v.keys[n].publicKeyPem);
  for (const c of v.cases) {
    it(`reproduces ${c.name}`, () => {
      const r = verifyBundle(c.bundle, { issuerKeys: c.issuerKeys.map(key), principalKeys: c.principalKeys.map(key), attestation: c.attestation });
      expect({ ok: r.ok, failing: failing(r) }).toEqual(c.expected);
    });
  }
  it("cover a pass and every refusal this slice promises", () => {
    const names = v.cases.map((c: { name: string }) => c.name);
    expect(names).toEqual(expect.arrayContaining(["attested-simulated-allowed", "attested-simulated-refused", "attested-simulated-other-release", "attested-key-outside", "attested-evidence-tampered", "attested-gcp-test-chain"]));
  });
});
