// Aspect: strict mode. Source: src/config.ts, src/gateway.ts, src/check.ts, src/verify.ts
// Run:    node examples/34-strict-mode.ts
//
// An operator who runs the gateway could keep an ordinary call off the record: the call goes out before its receipt
// is appended, so a kill or a deleted outbox entry at that moment leaves nothing, and a local log can be rewritten.
// Strict mode refuses a local log, precommits every tool to a remote hash-only log, keeps no outbox, and says so on
// every receipt, so a verifier can require it.
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkConfig } from "../src/check.ts";
import { loadConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair, type Envelope } from "../src/crypto.ts";
import { createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import { serveLog } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("34-strict-mode"));
const ordinary = JSON.parse(readFileSync(fx.configFile, "utf8"));
const grant = JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope;
const strictFile = join(fx.dir, "gateway-strict.json");
const write = (config: Record<string, unknown>) => writeFileSync(strictFile, JSON.stringify(config, null, 2));
const bundleOf = (id: unknown) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(id)}.json`), "utf8")) as ReceiptBundle;
const predicateOf = (b: ReceiptBundle) => (JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;

step(1, "check on the ordinary config, with its local log, says what strict mode would refuse");
const findings = await checkConfig(fx.configFile);
const strictFinding = findings.find((f) => f.check === "strict")!;
console.log("  ", strictFinding.message);
assert.match(strictFinding.message, /would refuse: strict mode needs a remote log/);

step(2, "turned on with that local log, the gateway does not start");
const { logFile: _local, ...remoteBase } = ordinary;
write({ ...ordinary, strict: true });
assert.throws(() => loadConfig(strictFile), /strict mode needs a remote log/);
console.log("   refused: strict mode needs a remote log");

step(3, "a log someone else runs, which accepts leaf hashes only; the gateway pins its key");
process.env.STRICT_LOG_TOKEN = "demo-token";
const logKey = writeKeyPair(generateKeyPair(), join(fx.dir, "log-keys"), "log");
const log = await serveLog(join(fx.dir, "server-log.jsonl"), loadPrivateKey(logKey.keyFile), { port: 0, tokens: ["demo-token"], hashOnly: true });
const remoteLog = { url: log.url, tokenEnv: "STRICT_LOG_TOKEN", keys: [logKey.pubFile] };
write({ ...remoteBase, strict: true, log: remoteLog });
assert.throws(() => loadConfig(strictFile), /strict mode needs log.hashOnly/);
console.log("   without hashOnly: refused");
write({ ...remoteBase, strict: true, log: { ...remoteLog, hashOnly: true } });
const host = await createGatewayHost(loadConfig(strictFile));
const gw = host.open(grant);
console.log("   with hashOnly and keys: the gateway starts, logging to", log.url);

step(4, "a read, which no precommit list names, is precommitted all the same, and the receipt says strict");
const read = await gw.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
const readBundle = bundleOf(read._meta?.[RECEIPT_META_KEY]);
const p = predicateOf(readBundle);
console.log(`   issuer.strict ${p.issuer.strict}; authorization at leaf ${p.authorization?.inclusion.leafIndex}, receipt at leaf ${readBundle.inclusion.leafIndex}`);
assert.equal(p.issuer.strict, true);
assert.ok(p.authorization && p.authorization.inclusion.leafIndex < readBundle.inclusion.leafIndex);

step(5, "a verifier that requires strict mode accepts it");
const keys = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logKeys: [loadPublicKey(logKey.pubFile)], requireStrict: true };
const verified = verifyBundle(readBundle, keys);
assert.deepEqual(verified.checks.filter((c) => !c.ok), []);
for (const c of verified.checks.filter((x) => x.name.startsWith("strict"))) console.log(`   PASS ${c.name}`);

step(6, "and refuses a receipt from the ordinary gateway, whose call went out before anything was logged");
const plain = await createGatewayHost(loadConfig(fx.configFile));
const plainCall = await plain.open(grant).handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
await plain.close();
const refused = verifyBundle(bundleOf(plainCall._meta?.[RECEIPT_META_KEY]), { ...keys, logKeys: [], logFile: fx.logFile });
const failing = refused.checks.filter((c) => !c.ok).map((c) => c.name);
console.log("   FAIL", failing.join(", "));
assert.deepEqual(failing, ["strict mode in force", "strict: call precommitted before forwarding"]);

step(7, "the log goes down: a refund is not forwarded, and nothing waits in an outbox the operator could empty");
await log.close();
const refund = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } }).then(() => "answered", (e: Error) => e.message);
console.log("   the call fails:", refund.slice(0, 90));
assert.notEqual(refund, "answered");
assert.equal(host.pendingReceipts(), 0);
assert.equal(existsSync(join(fx.receiptsDir, "outbox")), false);
await host.close();

console.log("\nOK");
