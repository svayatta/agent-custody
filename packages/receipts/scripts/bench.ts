// Honest numbers for the site: how long a policy decision, a gateway call, and a verification take on one machine.
// Run: node scripts/bench.ts   (prints medians over many iterations; the site quotes them with the machine named)
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import { evaluate } from "../src/policy.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";

const median = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]!; };
const fx = buildFixture(mkdtempSync(join(tmpdir(), "bench-")));
const policy = readFileSync(join(fx.dir, "policy.cedar"), "utf8");
const req = { agentId: "support-agent", tool: "stripe.refund", context: { args: { customer_id: "cust_123", amount: 50000 }, facts: { customer: { id: "cust_123", verified: true } }, grant: { principal: "user_456", scopes: ["stripe.refund"] } } };
for (let i = 0; i < 200; i++) evaluate(policy, req); // warm
const dec: number[] = [];
for (let i = 0; i < 2000; i++) { const t = performance.now(); evaluate(policy, req); dec.push(performance.now() - t); }

const gw = await createGateway(loadConfig(fx.configFile));
for (let i = 0; i < 20; i++) await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
const calls: number[] = [];
let last = "";
for (let i = 0; i < 200; i++) { const t = performance.now(); const r = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } }); calls.push(performance.now() - t); last = String(r._meta?.[RECEIPT_META_KEY]); }
await gw.close();

const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${last}.json`), "utf8"));
const opts = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)] };
for (let i = 0; i < 50; i++) await verifyBundle(bundle, opts);
const ver: number[] = [];
for (let i = 0; i < 500; i++) { const t = performance.now(); await verifyBundle(bundle, opts); ver.push(performance.now() - t); }
const size = Buffer.byteLength(JSON.stringify(bundle));
console.log(JSON.stringify({ node: process.version, platform: `${process.platform}/${process.arch}`, policyDecisionMs: +median(dec).toFixed(3), gatewayCallMs: +median(calls).toFixed(2), gatewayCallNote: "agent -> gateway -> fact lookup -> policy -> stand-in upstream -> receipt signed and logged -> back, stdio upstream on the same machine", verifyMs: +median(ver).toFixed(2), receiptBytes: size }, null, 2));
