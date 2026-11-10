// Generates vectors/attestation.json: receipts from gateways with attested keys, each with the attestation and the
// release digest a verifier is given, and the checks that must fail. Run with `bun run vectors:attestation`; commit
// the result. Regenerate only when the attestation format or a check changes, never to make a test pass.
// The simulated cases are signed by the published simulated key. The Confidential Space cases use a TEST chain whose
// root is in the case (`gcpRoots`); no case claims to be a genuine Google token.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize, dsseSign, generateKeyPair, loadPublicKey, publicKeyFromPem, type Envelope } from "../src/crypto.ts";
import { loadConfig } from "../src/config.ts";
import { createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import type { AttestationBundle, AttestationProvider, AttestationVerifyOptions } from "../src/attestation.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "./fixture.ts";
import { testChain, testClaims, testToken } from "./test-pki.ts";

const out = join(import.meta.dirname, "..", "vectors", "attestation.json");
const IMAGE = `sha256:${"a1".repeat(32)}`;
const OTHER = `sha256:${"b2".repeat(32)}`;
const decode = <T>(env: Envelope) => JSON.parse(Buffer.from(env.payload, "base64").toString()) as T;

async function attestedReceipt(provider?: AttestationProvider) {
  const fx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-attested-")));
  const raw = JSON.parse(readFileSync(fx.configFile, "utf8"));
  delete raw.identity.keyFile;
  raw.attestation = { provider: "simulated" };
  writeFileSync(fx.configFile, JSON.stringify(raw, null, 2));
  process.env.AGENT_CUSTODY_IMAGE_DIGEST = IMAGE;
  const cfg = loadConfig(fx.configFile);
  const host = await createGatewayHost(cfg, provider ? { attestationProvider: provider } : {});
  const gw = host.open(JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope);
  const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
  await host.close();
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(res._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  const attestation = JSON.parse(readFileSync(host.attestationFile!, "utf8")) as AttestationBundle;
  return { bundle, attestation, principalPem: readFileSync(fx.principalPub, "utf8"), principal: loadPublicKey(fx.principalPub) };
}

interface Case {
  name: string;
  description: string;
  bundle: ReceiptBundle;
  attestation: Omit<AttestationVerifyOptions, "bundle"> & { bundle: AttestationBundle };
  issuerKeys: string[];
  principalKeys: string[];
  expected: { ok: boolean; failing: string[] };
}
const keys: Record<string, { publicKeyPem: string; keyid: string }> = {};
const cases: Case[] = [];
function addCase(c: Omit<Case, "expected">) {
  const r = verifyBundle(c.bundle, {
    issuerKeys: c.issuerKeys.map(loadKey),
    principalKeys: c.principalKeys.map(loadKey),
    attestation: c.attestation,
  });
  cases.push({ ...c, expected: { ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) } });
}
const loadKey = (n: string) => publicKeyFromPem(keys[n]!.publicKeyPem);

const sim = await attestedReceipt();
keys.principal = { publicKeyPem: sim.principalPem, keyid: sim.principal.keyid };
const P = { issuerKeys: [] as string[], principalKeys: ["principal"] };

addCase({ name: "attested-simulated-allowed", description: "A gateway with a simulated attestation; the verifier is given the attestation, the release digest the simulation claims, and the test flag. Every check passes, and attested build says SIMULATED.", bundle: sim.bundle, attestation: { bundle: sim.attestation, releaseDigest: IMAGE, allowSimulated: true }, ...P });
addCase({ name: "attested-simulated-refused", description: "The same receipt without the test flag: simulated evidence never passes attested build.", bundle: sim.bundle, attestation: { bundle: sim.attestation, releaseDigest: IMAGE }, ...P });
addCase({ name: "attested-simulated-other-release", description: "The same receipt checked against another release digest.", bundle: sim.bundle, attestation: { bundle: sim.attestation, releaseDigest: OTHER, allowSimulated: true }, ...P });

const outside = generateKeyPair();
keys.outside = { publicKeyPem: outside.publicKey.export({ type: "spki", format: "pem" }) as string, keyid: outside.keyid };
const st = decode<ReceiptStatement>(sim.bundle.envelope);
st.predicate.issuer.keyid = outside.keyid;
addCase({ name: "attested-key-outside", description: "The receipt re-signed by a key outside the attestation, which the verifier also trusts: the receipt is not signed by the attested key.", bundle: { ...sim.bundle, envelope: dsseSign(RECEIPT_TYPE, st, outside) }, attestation: { bundle: sim.attestation, releaseDigest: IMAGE, allowSimulated: true }, issuerKeys: ["outside"], principalKeys: ["principal"] });

const ast = decode<Record<string, any>>(sim.attestation.envelope);
const evp = decode<Record<string, unknown>>(ast.predicate.evidence.envelope);
ast.predicate.evidence.envelope.payload = Buffer.from(canonicalize({ ...evp, imageDigest: OTHER })).toString("base64");
addCase({ name: "attested-evidence-tampered", description: "The attestation's evidence edited to claim another image, without the attested key's signature: the statement signature fails and the key is not trusted.", bundle: sim.bundle, attestation: { bundle: { ...sim.attestation, envelope: { ...sim.attestation.envelope, payload: Buffer.from(canonicalize(ast)).toString("base64") } }, releaseDigest: OTHER, allowSimulated: true }, ...P });

const chain = testChain();
const gcpProvider: AttestationProvider = { name: "gcp-confidential-space", async evidence(keyid) { return { type: "gcp-confidential-space", token: testToken(testClaims(keyid, IMAGE), [chain.leaf.der, chain.intermediate.der, chain.root.der], chain.leaf.key) }; } };
const gcp = await attestedReceipt(gcpProvider);
keys["gcp-principal"] = { publicKeyPem: gcp.principalPem, keyid: gcp.principal.keyid };
const G = { issuerKeys: [] as string[], principalKeys: ["gcp-principal"] };
addCase({ name: "attested-gcp-test-chain", description: "A Confidential Space token in the documented shape, signed by a TEST chain whose root the verifier pins (gcpRoots). Every check passes.", bundle: gcp.bundle, attestation: { bundle: gcp.attestation, releaseDigest: IMAGE, gcpRoots: [chain.root.pem] }, ...G });
addCase({ name: "attested-gcp-default-root", description: "The same token with only Google's root pinned (the default): the TEST chain does not end there.", bundle: gcp.bundle, attestation: { bundle: gcp.attestation, releaseDigest: IMAGE }, ...G });
addCase({ name: "attested-gcp-other-release", description: "The same token checked against another release digest.", bundle: gcp.bundle, attestation: { bundle: gcp.attestation, releaseDigest: OTHER, gcpRoots: [chain.root.pem] }, ...G });

writeFileSync(out, JSON.stringify({
  version: "0.1",
  generated: new Date().toISOString(),
  note: "Each case: verify `bundle` with the named keys (see `keys`) and `attestation` (the attestation bundle, the release digest, and the options). The gateway key is trusted only through the attestation. `expected.failing` lists the check names that must fail. The Confidential Space cases use a TEST chain, never a genuine Google token; the simulated cases use the published simulated key.",
  keys,
  cases,
}, null, 2) + "\n");
console.log(`wrote ${cases.length} attestation cases to ${out}`);
