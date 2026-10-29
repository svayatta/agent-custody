// Aspect: completeness from the provider's side. Source: src/completeness.ts
// Run:    node examples/35-completeness.ts
//
// Receipts prove what went through the gateway, but nothing on the gateway's side can see a refund issued straight
// through the provider. An auditor with a read-only key of their own lists the provider's refunds over a window and
// matches each to a verified receipt. Here the provider's list comes from a stand-in that answers the way Stripe's
// list API does; in production, `stripeSource` calls Stripe with a restricted read-only key.
import { checkCompleteness, formatCompleteness, stripeSource } from "../src/completeness.ts";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway } from "../src/gateway.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("35-completeness"));
const since = Date.now() - 60_000;

step(1, "a support agent refunds two customers through the gateway; each refund gets a signed receipt");
const gw = await createGateway(loadConfig(fx.configFile));
const refunds: { id: string; amount: number; created: number }[] = [];
for (const amount of [5000, 2500]) {
  const r = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount, currency: "GBP" } });
  const id = (JSON.parse((r.content as { text: string }[])[0]!.text) as { refund_id: string }).refund_id;
  refunds.push({ id, amount, created: Math.floor(Date.now() / 1000) });
  console.log(`   refund ${id} for ${amount}`);
}
await gw.close();

step(2, "someone with the Stripe key issues a third refund straight through the API; the gateway never sees it");
const provider = [...refunds, { id: "re_issued_directly", amount: 20000, created: Math.floor(Date.now() / 1000) }].map((r) => ({ object: "refund", id: r.id, amount: r.amount, currency: "gbp", created: r.created }));
const KEY = "rk_test_auditor_read_only";
const standIn = (async (_url: string | URL | Request, init?: RequestInit) => {
  if ((init?.headers as Record<string, string>).authorization !== `Bearer ${KEY}`) return new Response("unauthorised", { status: 401 });
  return Response.json({ object: "list", data: provider, has_more: false });
}) as typeof fetch;

step(3, "the auditor lists the provider's refunds for the window and matches each to a verified receipt");
const report = await checkCompleteness({
  receiptsDir: fx.receiptsDir,
  verify: { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile },
  source: stripeSource({ secretKey: KEY, object: "refunds", fetch: standIn }),
  tools: ["stripe.refund"],
  sinceMs: since,
  untilMs: Date.now() + 60_000,
  idPath: "refund_id",
});
console.log(formatCompleteness(report).replace(/^/gm, "   "));

const ok = report.matched.length === 2 && report.providerOnly.length === 1 && report.providerOnly[0]!.providerId === "re_issued_directly" && !report.complete;
if (!ok) throw new Error("unexpected result");
console.log("\nOK");
