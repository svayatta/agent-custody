// Aspect: what blast radius cannot see, and says so. Source: src/blast.ts, and the receipts gateway's capture rules
// Run:    node examples/07-incomplete-evidence.ts        (after `bun run build` at the repository root)
// Example 06 with one change: the refund's receipt is private. A capture rule withholds its arguments, except the
// customer id and the amount, and with them which beliefs the agent had been shown before it refunded. When the
// belief is retracted, a query without the customer's key cannot tell whether the refund relied on it. It does not
// answer "nothing relied on it": it lists the refund as INCOMPLETE. With the key the same query sees the dependency.
// Everything here is synthetic: generated keys, a stand-in payments API, a made-up customer.
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { captureKeyFrom, createDelegation, createGateway, generateKeyPair, loadConfig, loadPublicKey, verifyBundle, writeKeyPair, type ReceiptBundle } from "@agent-custody/receipts";
import { Ledger, blastRadius, formatBlastRadius, loadReceipts } from "../src/index.ts";

// a fixed, gitignored directory, so the receipts, keys, and log can be inspected after the run
const dir = resolve(import.meta.dirname, "..", "examples-out", "07-incomplete-evidence");
rmSync(dir, { recursive: true, force: true });
mkdirSync(dir, { recursive: true });
const step = (n: number, s: string) => console.log(`\n${n}. ${s}`);
const value = (r: any) => JSON.parse(r.content[0].text);
const indent = (s: string) => s.split("\n").map((l) => "   " + l).join("\n");

step(1, "example 06's gateway, memory and payments behind one grant, with a capture rule on the refund");
writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
const principalKp = generateKeyPair();
writeKeyPair(principalKp, join(dir, "keys"), "principal");
const now = Date.now();
writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "memory.retract", "stripe.refund"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
writeFileSync(join(dir, "policy.cedar"), `permit(principal, action, resource);\n`);
// the customer's key: a demo key, generated for this run and written beside the receipts so the run can be replayed
const captureKeyHex = randomBytes(32).toString("hex");
process.env.DEMO_CAPTURE_KEY = captureKeyHex;
writeFileSync(join(dir, "demo-capture-key.hex"), captureKeyHex + "\n");
const ledgerFile = join(dir, "ledger.jsonl");
const stripe = resolve(import.meta.dirname, "..", "..", "receipts", "scripts", "fake-stripe.ts");
const rule = { "stripe.refund": { args: { mode: "encrypted", clear: ["customer_id", "amount"] } } };
writeFileSync(join(dir, "gateway.json"), JSON.stringify({
  identity: { keyFile: "keys/gateway.key" },
  upstreams: [
    { name: "memory", command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile] },
    { name: "payments", command: process.execPath, args: [stripe] },
  ],
  grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl",
  capture: rule, captureKeyEnv: "DEMO_CAPTURE_KEY",
}));
console.log("   capture:", JSON.stringify(rule));
const gw = await createGateway(loadConfig(join(dir, "gateway.json")));

step(2, "the agent records what the CRM said, reads it back, and refunds on the strength of it");
const plan = value(await gw.handleCall({ name: "memory.write", arguments: { subject: "cust_123", predicate: "plan", value: "enterprise", space: "team:support" } })).fact;
await gw.handleCall({ name: "memory.read", arguments: { subject: "cust_123" } });
const refund = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000, reason: "enterprise plan goodwill" } });
const refundId = String(refund._meta?.["agent-custody/receipt"]);
console.log("   refund:", value(refund).status, "receipt", refundId.slice(0, 8));

step(3, "the refund's receipt verifies without the key, and shows what it withholds");
const bundle = JSON.parse(readFileSync(join(dir, "receipts", `${refundId}.json`), "utf8")) as ReceiptBundle;
const v = verifyBundle(bundle, { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))], logFile: join(dir, "log.jsonl") });
const p = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()).predicate;
console.log("   verified:", v.ok, "| in clear:", JSON.stringify({ customer_id: p.request.args.customer_id, amount: p.request.args.amount }));
console.log("   withheld:", p.capture.withheld.map((w: string[]) => w.join(".")).join(", "));

step(4, "the CRM was wrong; the belief is retracted, and blast radius is asked without the key");
await gw.handleCall({ name: "memory.retract", arguments: { factId: plan.factId, reason: "CRM sync bug" } });
await gw.close();
const ledger = new Ledger(ledgerFile);
const blind = await blastRadius(ledger, loadReceipts(join(dir, "receipts")), plan.factId);
console.log(indent(formatBlastRadius(blind, plan.factId)));

step(5, "the same query with the customer's key: the refund is found");
const seeing = await blastRadius(ledger, loadReceipts(join(dir, "receipts"), { captureKey: captureKeyFrom(captureKeyHex) }), plan.factId);
console.log(indent(formatBlastRadius(seeing, plan.factId)));

const ok = v.ok && !blind.receipts.some((r) => r.tool === "stripe.refund") && blind.withheld.some((r) => r.receiptId === refundId) && seeing.receipts.some((r) => r.receiptId === refundId) && seeing.withheld.length === 0;
if (!ok) throw new Error("unexpected");
console.log("\nOK");
