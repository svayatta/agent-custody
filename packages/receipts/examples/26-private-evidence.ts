// Aspect: private evidence, what the receipt file carries of a call. Source: src/capture.ts, src/verify.ts
// Run:    node examples/26-private-evidence.ts
//
// A refund review should show the amount, the customer id, and the decision, and nothing a reviewer has no business
// seeing: not the note with the caller's phone number, not the customer record the policy decided on, not the
// provider's full answer. The capture rule says so per tool, the digests and signatures stay over the whole call, and
// the verifier recomputes them when the values are revealed with the customer's key or disclosed by whoever holds them.
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

step(1, "a capture rule: refund arguments encrypted except the amount and the customer id, the provider's answer and the customer record withheld");
const fx = buildFixture(out("26-private-evidence"));
process.env.EXAMPLE_CAPTURE_KEY = randomBytes(32).toString("hex");
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.capture = {
  "stripe.refund": { args: { mode: "encrypted", clear: ["customer_id", "amount"] }, result: { mode: "digest" }, facts: { mode: "encrypted" } },
  "customer.lookup": { result: { mode: "digest" } },
};
cfg.captureKeyEnv = "EXAMPLE_CAPTURE_KEY";
writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
console.log(JSON.stringify(cfg.capture, null, 2).split("\n").map((l) => `   ${l}`).join("\n"));

step(2, "the agent refunds £25 with a note no reviewer needs; the policy decides on the customer record the gateway fetched");
const gw = await createGateway(loadConfig(fx.configFile));
const args = { customer_id: "cust_123", amount: 2500, reason: "customer called from +44 20 7946 0000 about the card ending 4242" };
const r = await gw.handleCall({ name: "stripe.refund", arguments: args });
await gw.close();
const id = String(r._meta![RECEIPT_META_KEY]);
const file = join(fx.receiptsDir, `${id}.json`);
const bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
console.log(`   the agent got: ${(r.content[0] as { text: string }).text}`);
console.log(`   the receipt carries: args ${JSON.stringify(Object.fromEntries(Object.entries(p.request.args).map(([k, v]) => [k, typeof v === "object" ? `<${(v as { $custody: string }).$custody}>` : v])))}`);
console.log(`   withheld (${p.capture!.mode}): ${p.capture!.withheld.map((w) => w.join(".")).join(", ")}`);
// the statement is base64 inside the file: a leak check reads it decoded, the authorization inside it too
const statement = Buffer.from(bundle.envelope.payload, "base64").toString();
const authorization = p.authorization ? Buffer.from(p.authorization.envelope.payload, "base64").toString() : "";
const text = statement + authorization + readFileSync(file, "utf8");
// the sentinels carry a space or quotes: digits alone can appear by chance in the hex and base64 of salts, ciphertexts, and signatures
const leaks = ["7946 0000", "ending 4242", "called from", '"plan":"pro"', "succeeded"].filter((s) => text.includes(s));
if (leaks.length) throw new Error(`the receipt still carries ${leaks.join(", ")}`);
console.log("   the receipt file contains none of: the phone number, the card, the note, the customer record, the provider's answer");

step(3, "a reviewer without the key verifies it: every signature and proof checks, the withheld parts are committed, not recomputed");
const opts = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], logFile: fx.logFile };
const bare = verifyBundle(bundle, opts);
console.log(formatReport(bare).split("\n").filter((l) => /args digest|execution result digest|upstream signature|RESULT/.test(l)).map((l) => `   ${l}`).join("\n"));

step(4, "with the customer's key, agent-custody reveal writes the disclosure, and verify --disclose recomputes every digest from it");
const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const disclosureFile = join(fx.dir, "disclosure.json");
const reveal = spawnSync(process.execPath, [cli, "reveal", file, "--capture-key-env", "EXAMPLE_CAPTURE_KEY", "--out", disclosureFile], { encoding: "utf8" });
if (reveal.status !== 0) throw new Error(reveal.stderr);
console.log(`   ${reveal.stdout.trim()}`);
const disclosure = JSON.parse(readFileSync(disclosureFile, "utf8")) as { request: { args: Record<string, unknown> }; facts: { customer: { value: unknown } } };
console.log(`   revealed reason: ${JSON.stringify(disclosure.request.args.reason)}`);
console.log(`   revealed customer record: ${JSON.stringify(disclosure.facts.customer.value)}`);
const verified = spawnSync(process.execPath, [cli, "verify", file, "--issuer-key", fx.gatewayPub, "--principal-key", fx.principalPub, "--upstream-key", fx.upstreamPub, "--log", fx.logFile, "--capture-key-env", "EXAMPLE_CAPTURE_KEY"], { encoding: "utf8" });
if (verified.status !== 0) throw new Error(verified.stdout + verified.stderr);
console.log(verified.stdout.split("\n").filter((l) => /args digest|execution result digest|upstream signature|RESULT/.test(l)).map((l) => `   ${l}`).join("\n"));

step(5, "a disclosure that lies about the note fails the commitment");
const lie = verifyBundle(bundle, { ...opts, disclosed: { request: { args: { reason: "a different note" } } } });
console.log(`   ${formatReport(lie).split("\n").find((l) => /args digest/.test(l))}`);
if (!bare.ok || !lie.checks.some((c) => c.name === "request args digest" && !c.ok)) throw new Error("expected the bare receipt to verify and the lying disclosure to fail");
console.log("\nOK");
