// Aspect: an attested gateway key. Source: src/attestation.ts, src/gateway.ts, src/verify.ts
// Run:    node examples/45-attested-gateway.ts
//
// A receipt proves that a gateway key signed it, not which gateway code held the key. With `attestation` in the
// config, the gateway makes its key in memory at start, asks the platform for evidence binding the key to the
// measured image, logs that once, and names it on every receipt. A verifier given the release digest walks
// receipt key -> attestation -> image -> release. This example uses the SIMULATED provider, which runs anywhere and
// proves nothing about hardware: a verifier refuses it unless told to allow it.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AttestationBundle } from "../src/attestation.ts";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey, type Envelope } from "../src/crypto.ts";
import { createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("45-attested-gateway"));
const IMAGE = `sha256:${"a1".repeat(32)}`;
const failing = (r: { checks: { name: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.name);

step(1, "the config names an attestation provider in place of a key file");
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
delete cfg.identity.keyFile;
cfg.attestation = { provider: "simulated" };
writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
process.env.AGENT_CUSTODY_IMAGE_DIGEST = IMAGE;
const keysBefore = readdirSync(join(fx.dir, "keys")).sort();
const host = await createGatewayHost(loadConfig(fx.configFile));
console.log(`   key ${host.keyid.slice(0, 12)} made in memory; attestation logged at ${host.attestationFile!.slice(fx.dir.length + 1)}`);
assert.deepEqual(readdirSync(join(fx.dir, "keys")).sort(), keysBefore);

step(2, "a call; its receipt names the attestation");
const gw = host.open(JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope);
const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
await host.close();
const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(res._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
const attestation = JSON.parse(readFileSync(host.attestationFile!, "utf8")) as AttestationBundle;
const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
console.log(`   issuer.attestation ${p.issuer.attestation?.slice(0, 12)}`);
assert.ok(p.issuer.attestation);

step(3, "verified with only the attestation and the release digest, simulated allowed for this test");
const base = { issuerKeys: [], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
const ok = verifyBundle(bundle, { ...base, attestation: { bundle: attestation, releaseDigest: IMAGE, allowSimulated: true } });
console.log(formatReport(ok).split("\n").filter((l) => /^(PASS|FAIL)  (attest|receipt (signed|names))|^ATTESTATION|^RESULT/.test(l)).map((l) => `   ${l}`).join("\n"));
assert.equal(ok.ok, true);

step(4, "without the test flag, against another release, or with edited evidence: refused");
const refused = verifyBundle(bundle, { ...base, attestation: { bundle: attestation, releaseDigest: IMAGE } });
console.log(`   no flag:        ${failing(refused).join(", ")}`);
assert.deepEqual(failing(refused), ["attested build"]);
const other = verifyBundle(bundle, { ...base, attestation: { bundle: attestation, releaseDigest: `sha256:${"b2".repeat(32)}`, allowSimulated: true } });
console.log(`   other release:  ${failing(other).join(", ")}`);
assert.deepEqual(failing(other), ["attested build"]);
const st = JSON.parse(Buffer.from(attestation.envelope.payload, "base64").toString());
st.predicate.evidence.envelope.payload = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(st.predicate.evidence.envelope.payload, "base64").toString()), imageDigest: `sha256:${"b2".repeat(32)}` })).toString("base64");
const edited = verifyBundle(bundle, { ...base, attestation: { bundle: { ...attestation, envelope: { ...attestation.envelope, payload: Buffer.from(JSON.stringify(st)).toString("base64") } }, releaseDigest: IMAGE, allowSimulated: true } });
console.log(`   edited:         ${failing(edited).join(", ")}`);
assert.ok(failing(edited).includes("attestation statement signature (attested key)"));

console.log("\nOK");
