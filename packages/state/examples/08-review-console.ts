// Aspect: find a payment receipt and hand its evidence to a reviewer. Source: src/search.ts, src/case-file.ts
// Run:    node examples/08-review-console.ts        (after `bun run build` at the repository root)
// The real gateway fronts the local fake Stripe MCP server. No payment provider or network is needed.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createDelegation, createGateway, generateKeyPair, loadConfig, loadPublicKey, RECEIPT_META_KEY, writeKeyPair } from "@agent-custody/receipts";
import { buildCaseFile, listReceipts, renderCaseFile, verifyCaseFile } from "../src/index.ts";

const dir = mkdtempSync(join(tmpdir(), "review-example-"));
const step = (n: number, text: string) => console.log(`\n${n}. ${text}`);

step(1, "a principal grants support-agent refunds; the gateway checks a customer fact and precommits authorization");
writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
const principal = generateKeyPair();
writeKeyPair(principal, join(dir, "keys"), "principal");
const now = Date.now();
writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principal, {
  version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["customer.lookup", "stripe.refund"],
  issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString(),
})));
writeFileSync(join(dir, "policy.cedar"), `permit(principal, action == Action::"customer.lookup", resource);
permit(principal, action == Action::"stripe.refund", resource)
when { context.args.amount <= 100000 && context.facts.customer.verified == true };
`);
writeFileSync(join(dir, "gateway.json"), JSON.stringify({
  identity: { keyFile: "keys/gateway.key" },
  upstream: { command: process.execPath, args: [resolve(import.meta.dirname, "..", "..", "receipts", "scripts", "fake-stripe.ts")] },
  grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar",
  facts: [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.refund"] }],
  precommit: ["stripe.refund"], receiptsDir: "receipts", logFile: "log.jsonl",
}));
const gateway = await createGateway(loadConfig(join(dir, "gateway.json")));
let receiptId: string;
let transactionId: string;
try {
  const result = await gateway.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
  const refund = JSON.parse((result.content[0] as { text: string }).text) as { refund_id: string; status: string };
  if (result.isError || refund.status !== "succeeded") throw new Error("the refund did not succeed");
  const id = result._meta?.[RECEIPT_META_KEY];
  if (typeof id !== "string") throw new Error("the gateway did not return a receipt id");
  receiptId = id;
  transactionId = refund.refund_id;
} finally {
  await gateway.close();
}

step(2, "find the receipt by the returned refund id and by customer; combined filters narrow the same public evidence");
const keys = {
  issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))],
  principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))],
};
const options = { receiptsDir: join(dir, "receipts"), keys };
for (const search of [{ transaction: transactionId }, { customer: "cust_123" }, { transaction: transactionId, customer: "cust_123", agent: "support-agent" }]) {
  const rows = listReceipts(options, search);
  if (rows.length !== 1 || rows[0]!.receiptId !== receiptId || rows[0]!.verified !== true) throw new Error("search did not find the verified refund receipt");
}
console.log(`   refund ${transactionId}; customer cust_123; receipt ${receiptId}`);

step(3, "export one portable case; verify its receipts, signed authorization, log head and inclusion proofs afresh");
const file = await buildCaseFile(options, receiptId);
const checked = verifyCaseFile(file, keys);
if (!checked.ok || checked.trust !== "independent") throw new Error("case verification failed");
if (checked.complete || !file.explanation.includes("unknown without a ledger")) throw new Error("belief dependencies must remain unknown without a ledger");
const html = join(dir, "refund.case.html");
const json = join(dir, "refund.case.json");
writeFileSync(html, renderCaseFile(file));
writeFileSync(json, JSON.stringify(file, null, 2));
console.log(`   Open offline in a browser: ${html}`);
console.log(`   Case data for independent verification: ${json}`);
console.log("   Compare bundled public key fingerprints with a trusted source. The ledger is absent, so belief dependencies are unknown.");
console.log("   This proves the recorded gateway decision and detects receipt tampering; it does not prove an external payment occurred.");
console.log("\nOK");
