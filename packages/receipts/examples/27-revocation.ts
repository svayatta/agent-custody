// Aspect: revoking an agent's authority mid-session. Source: src/gateway.ts, src/delegation.ts, src/cli.ts
// Run:    node examples/27-revocation.ts
//
// A support agent holds a grant from a customer to look them up and refund them, and has delegated a lookup-only
// grant to a sub-agent. Both are mid-session when the operator revokes the support agent's grant from another
// process, with the CLI. Neither key is rotated and neither process is restarted: the gateway re-reads the revocation
// list on every call, so the next call of each session is refused, the refusal is a signed receipt that verifies,
// and a repacked copy of the grant does not get past the list.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { loadConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey, publicKeyToPem, type Envelope } from "../src/crypto.ts";
import { createDelegation, delegateFrom } from "../src/delegation.ts";
import { createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("27-revocation"));
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.revokedGrants = "revoked.json";
writeFileSync(fx.configFile, JSON.stringify(cfg));
const keys = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
const text = (r: { content: unknown[] }) => (r.content[0] as { text: string }).text;
/** the receipt the gateway issued for a call, verified, with what it says */
const receipt = (r: { _meta?: Record<string, unknown> }) => {
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
  return { p, verified: verifyBundle(bundle, keys).ok };
};

step(1, "user_456 grants support-agent lookups and refunds for an hour; support-agent delegates lookups only to lookup-agent");
const agentKey = generateKeyPair();
const now = Date.now();
const grant = createDelegation(loadPrivateKey(join(fx.dir, "keys", "principal.key")), {
  version: "0.1",
  principal: "user_456",
  agent: "support-agent",
  scopes: ["customer.lookup", "stripe.refund"],
  issuedAt: new Date(now - 1000).toISOString(),
  expiresAt: new Date(now + 3_600_000).toISOString(),
  agentKey: publicKeyToPem(agentKey.publicKey),
});
const grantFile = join(fx.dir, "grant.json");
writeFileSync(grantFile, JSON.stringify(grant, null, 2));
const child = delegateFrom(grant, agentKey, { agent: "lookup-agent", scopes: ["customer.lookup"] });
console.log("   support-agent: customer.lookup, stripe.refund | lookup-agent: customer.lookup, signed by support-agent's key");

step(2, "both sessions are open on one running gateway, and both act");
const host = await createGatewayHost(loadConfig(fx.configFile));
const support = host.open(grant);
const sub = host.open(child);
const refund = await support.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
const lookup = await sub.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
const r1 = receipt(refund);
const r2 = receipt(lookup);
console.log(`   support-agent refunds 25.00 -> ${r1.p.execution.status} (receipt verifies: ${r1.verified})`);
console.log(`   lookup-agent looks up cust_123 -> ${r2.p.execution.status} (receipt verifies: ${r2.verified})`);

step(3, "the operator revokes support-agent's grant from another process: agent-custody revoke --config gateway.json --grant grant.json");
const cli = spawnSync(process.execPath, ["--import", "tsx", resolve(import.meta.dirname, "..", "src", "cli.ts"), "revoke", "--config", fx.configFile, "--grant", grantFile], { encoding: "utf8" });
if (cli.status !== 0) throw new Error(cli.stderr);
console.log(`   ${cli.stdout.trim().replace(`${fx.dir}/`, "")}`);
console.log("   no key is rotated and the gateway is not restarted");

step(4, "the same sessions, their next calls");
const refused = await support.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
const r3 = receipt(refused);
console.log(`   support-agent refunds again -> the agent sees: ${text(refused)}`);
console.log(`   the receipt says: ${r3.p.execution.status}, nothing forwarded to the upstream (receipt verifies: ${r3.verified})`);
const subRefused = await sub.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
const r4 = receipt(subRefused);
console.log(`   lookup-agent, delegated before the revocation, looks up again -> ${r4.p.execution.status}: revoking a grant revokes every grant delegated from it`);

step(5, "no way back in under that grant");
const attempts: [string, () => unknown][] = [
  ["a new session", () => host.open(grant)],
  ["the grant repacked with an extra signature", () => host.open({ ...grant, signatures: [...grant.signatures, { keyid: "x", sig: "AA==" }] })],
  ["the grant with an extra field", () => host.open({ ...grant, note: "renewed" } as Envelope)],
  ["a fresh delegation from it", () => host.open(delegateFrom(grant, agentKey, { agent: "fresh-agent", scopes: ["customer.lookup"] }))],
];
const refusedAll = attempts.map(([what, open]) => {
  try {
    open();
    console.log(`   ${what}: opened`);
    return false;
  } catch (e) {
    console.log(`   ${what}: refused (${(e as Error).message})`);
    return true;
  }
});
await host.close();

const ok =
  r1.p.execution.status === "executed" && r2.p.execution.status === "executed" && r3.p.execution.status === "denied" && r4.p.execution.status === "denied" && [r1, r2, r3, r4].every((r) => r.verified) && refusedAll.every(Boolean) && JSON.parse(readFileSync(join(fx.dir, "revoked.json"), "utf8")).length === 1;
if (!ok) throw new Error("unexpected state");
console.log("\nOK");
