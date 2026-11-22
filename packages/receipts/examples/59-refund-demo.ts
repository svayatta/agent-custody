// Aspect: Demo 1, the refund, API leg. Source: src/door.ts, src/gateway.ts, src/approval-requests.ts, src/completeness.ts
// Run:    node examples/59-refund-demo.ts
//
// A shop puts the door in front of its refund API, and pays refunds through the gateway. A shopping agent with a
// passport asks for a refund within the limit and is paid at once, and paid once when it retries. Over the limit, or
// with a forged passport, it is refused at the door and the shop never hears of it. An agent with no passport is let
// through to a person instead: the refund waits until someone approves those exact arguments with their own key. Then an
// auditor, holding only public keys and a read-only view of Stripe, verifies every receipt and finds the one refund
// that someone made in Stripe directly. Stripe is a local stand-in, so the demo needs no key and no network. The phone
// leg (tells flags a synthetic voice) waits for the tells service and the Twilio hook.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { APPROVAL_REQUEST_META_KEY } from "../src/approval-requests.ts";
import { checkCompleteness, stripeSource } from "../src/completeness.ts";
import { loadConfig, loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { CLASS_HEADER, RECEIPT_HEADER, createDoorHost, serveDoor } from "../src/door.ts";
import { createGateway } from "../src/gateway.ts";
import { grantHeader } from "../src/grant-header.ts";
import { initRefunds, STRIPE_BEARER_ENV } from "../src/refunds-init.ts";
import type { ReceiptBundle } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

const dir = out("59-refund-demo");
const started = Date.now();

// Stripe, as far as the shop and the auditor see it: payment intents, refunds with an idempotency key, and the list API.
const intents = new Map<string, Record<string, unknown>>();
const refunds: Record<string, unknown>[] = [];
const stripe = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const send = (status: number, v: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(v));
    };
    const url = new URL(req.url ?? "/", "http://stripe.test");
    const form = new URLSearchParams(body);
    const intent = /^\/v1\/payment_intents\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && intent) return send(200, intents.get(intent[1]!) ?? { error: { message: "No such payment_intent" } });
    if (req.method === "GET" && url.pathname === "/v1/refunds") {
      const pi = url.searchParams.get("payment_intent");
      const gte = Number(url.searchParams.get("created[gte]") ?? 0);
      const lt = Number(url.searchParams.get("created[lt]") ?? Infinity);
      const data = refunds.filter((r) => (pi ? r.payment_intent === pi : Number(r.created) >= gte && Number(r.created) < lt));
      return send(200, { object: "list", data, has_more: false });
    }
    if (req.method === "POST" && url.pathname === "/v1/refunds") {
      const refund = { id: `re_${refunds.length + 1}`, object: "refund", amount: Number(form.get("amount")), currency: "gbp", payment_intent: form.get("payment_intent"), status: "succeeded", created: Math.floor(Date.now() / 1000), metadata: {} };
      refunds.push(refund);
      return send(200, refund);
    }
    send(404, { error: { message: "Unrecognized request URL" } });
  });
});
await new Promise<void>((r) => stripe.listen(0, "127.0.0.1", r));
const stripeUrl = `http://127.0.0.1:${(stripe.address() as { port: number }).port}`;
for (const [id, amount] of [["pi_order_1", 4000], ["pi_order_2", 4000], ["pi_order_3", 10000]] as const) intents.set(id, { id, object: "payment_intent", amount, amount_received: amount, currency: "gbp", status: "succeeded" });

step(1, "the shop: two payment lanes through the gateway, each one refund per payment, up to £50");
const quiet = () => {};
const auto = initRefunds({ dir: join(dir, "shop/auto"), limit: 5000, currency: "gbp", ttlHours: 1, stripeUrl, print: quiet });
const reviewed = initRefunds({ dir: join(dir, "shop/reviewed"), limit: 5000, currency: "gbp", ttlHours: 1, stripeUrl, print: quiet });
const approver = writeKeyPair(generateKeyPair(), join(dir, "shop/reviewed/keys"), "approver");
const reviewedCfg = JSON.parse(readFileSync(reviewed.configFile, "utf8"));
reviewedCfg.approvals = { trustedKeys: ["keys/approver.pub"], usedDir: "approvals-used", maxLifetimeSeconds: 900, requests: { dir: "approval-requests" }, tools: [{ tool: "stripe.refund" }] };
writeFileSync(reviewed.configFile, JSON.stringify(reviewedCfg, null, 2));
process.env[STRIPE_BEARER_ENV] = "Bearer sk_test_demo";
const lanes = { auto: await createGateway(loadConfig(auto.configFile)), reviewed: await createGateway(loadConfig(reviewed.configFile)) };
console.log("   verified agents: paid at once; any other arrival: a person approves the exact refund first");

// The shop's refund API. The door in front of it is the only way in, so its class header is the door's word.
const reached: string[] = [];
const shop = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", async () => {
    const send = (status: number, v: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(v));
    };
    const { payment_intent, amount } = JSON.parse(body) as { payment_intent: string; amount: number };
    const lane = req.headers[CLASS_HEADER] === "verified" ? "auto" : "reviewed";
    reached.push(`${lane} ${payment_intent} ${amount}`);
    const r = await lanes[lane].handleCall({ name: "stripe.refund", arguments: { payment_intent, amount } });
    const text = (r.content as { text: string }[])[0]!.text;
    const request = r._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string; status: string } | undefined;
    if (!r.isError) return send(200, { lane, refund: JSON.parse(text).id });
    if (request?.status === "pending") return send(202, { lane, status: "waiting for a person", request: request.requestId });
    send(409, { lane, error: text });
  });
});
await new Promise<void>((r) => shop.listen(0, "127.0.0.1", r));

step(2, "the door in front of the refund API: a verified passport, or no passport, up to £50; nothing else");
const fx = buildDoorFixture(join(dir, "door"), `http://127.0.0.1:${(shop.address() as { port: number }).port}`);
writeFileSync(join(fx.dir, "policy.cedar"), `// A refund of a positive amount up to £50. A verified agent is paid at once; an arrival with no passport goes to a
// person at the shop. A passport that does not check out is refused.
permit(principal, action == Action::"refund", resource)
when {
  (context.facts.arrival.class == "verified" || context.facts.arrival.class == "unknown") &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};
`);
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: quiet });
const passport = (key = fx.principalKey) => grantHeader(createDelegation(key, { version: "0.1", principal: "acme-agents", agent: "acme-shopper", scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() }));
const ask = async (body: { payment_intent: string; amount: number }, grant?: string) => {
  const r = await fetch(`${door.url}/refunds`, { method: "POST", headers: { "content-type": "application/json", ...(grant ? { "x-agent-custody-grant": grant } : {}) }, body: JSON.stringify(body) });
  const answer = (await r.json()) as Record<string, unknown>;
  return { status: r.status, klass: r.headers.get(CLASS_HEADER), receipt: r.headers.get(RECEIPT_HEADER), answer };
};
const show = (what: string, r: Awaited<ReturnType<typeof ask>>) => console.log(`   ${what}: ${r.status}, class ${r.klass}, ${JSON.stringify(r.answer.refund ?? r.answer.status ?? r.answer.error ?? r.answer.reason ?? r.answer).slice(0, 110)}`);
console.log(`   door ${door.url}, passports from acme-agents' key ${loadPublicKey(fx.principalPub).keyid.slice(0, 12)}`);

try {
  step(3, "acme-shopper, with its passport, asks for £25 back on order 1: paid at once");
  const first = await ask({ payment_intent: "pi_order_1", amount: 2500 }, passport());
  show("refund £25", first);
  assert.equal(first.status, 200);
  assert.equal(first.klass, "verified");

  step(4, "it retries, as after a lost response: Stripe pays once");
  const retry = await ask({ payment_intent: "pi_order_1", amount: 2500 }, passport());
  show("same refund again", retry);
  assert.equal(retry.status, 409);
  assert.equal(refunds.filter((r) => r.payment_intent === "pi_order_1").length, 1);

  step(5, "£80 on order 3, over the limit, and £25 with a forged passport: refused at the door; the shop never hears of them");
  const before = reached.length;
  const over = await ask({ payment_intent: "pi_order_3", amount: 8000 }, passport());
  const forged = await ask({ payment_intent: "pi_order_3", amount: 2500 }, passport(generateKeyPair()));
  show("refund £80", over);
  show("forged passport", forged);
  assert.equal(over.status, 403);
  assert.equal(forged.status, 403);
  assert.equal(forged.klass, "claimed");
  assert.equal(reached.length, before);

  step(6, "an agent with no passport asks for £20 on order 2: let through to a person, and nothing is paid yet");
  const unknown = await ask({ payment_intent: "pi_order_2", amount: 2000 });
  show("refund £20", unknown);
  assert.equal(unknown.status, 202);
  assert.equal(unknown.klass, "unknown");
  assert.equal(refunds.filter((r) => r.payment_intent === "pi_order_2").length, 0);

  step(7, "a person at the shop reads the exact refund and approves it with their own key, for five minutes");
  const approvals = (...a: string[]) => {
    const r = spawnSync(process.execPath, [join(import.meta.dirname, "../src/cli.ts"), "approvals", ...a, "--config", reviewed.configFile], { encoding: "utf8", timeout: 30_000 });
    assert.equal(r.status, 0, r.stderr);
    return r.stdout.trim();
  };
  console.log(`   ${approvals("list")}`);
  console.log(`   ${approvals("approve", String(unknown.answer.request), "--key", approver.keyFile, "--expires", "5m")}`);

  step(8, "the agent sends the same request again: paid, once");
  const approved = await ask({ payment_intent: "pi_order_2", amount: 2000 });
  show("refund £20", approved);
  assert.equal(approved.status, 200);
  assert.equal(refunds.filter((r) => r.payment_intent === "pi_order_2").length, 1);

  step(9, "meanwhile someone refunds £10 on order 3 in the Stripe dashboard, around the door and the gateway");
  await fetch(`${stripeUrl}/v1/refunds`, { method: "POST", body: new URLSearchParams({ payment_intent: "pi_order_3", amount: "1000" }) });
  console.log(`   Stripe now holds ${refunds.length} refunds: ${refunds.map((r) => `${String(r.id)} ${String(r.payment_intent)} £${Number(r.amount) / 100}`).join(", ")}`);

  step(10, "the auditor, with public keys and a read-only view of Stripe: every receipt verifies, and the stray refund is found");
  const audit = join(dir, "auditor/receipts");
  mkdirSync(audit, { recursive: true });
  for (const lane of [auto, reviewed]) for (const f of readdirSync(join(lane.dir, "receipts")).filter((f) => f.endsWith(".json"))) copyFileSync(join(lane.dir, "receipts", f), join(audit, f));
  const shopKeys = { issuerKeys: [auto, reviewed].map((l) => loadPublicKey(join(l.dir, "keys/gateway.pub"))), principalKeys: [auto, reviewed].map((l) => loadPublicKey(join(l.dir, "keys/principal.pub"))), approvalKeys: [loadPublicKey(approver.pubFile)] };
  const doorKeys = { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
  const read = (d: string) => readdirSync(d).filter((f) => f.endsWith(".json") && !f.includes(".authorization")).map((f) => JSON.parse(readFileSync(join(d, f), "utf8")) as ReceiptBundle);
  const gatewayReceipts = read(audit);
  const doorReceipts = read(fx.receiptsDir);
  const failed = [...gatewayReceipts.map((b) => verifyBundle(b, shopKeys)), ...doorReceipts.map((b) => verifyBundle(b, doorKeys))].filter((v) => !v.ok);
  console.log(`   ${doorReceipts.length} door receipts and ${gatewayReceipts.length} gateway receipts, ${failed.length} failing verification`);
  assert.equal(failed.length, 0, JSON.stringify(failed.map((v) => v.checks.filter((c) => !c.ok))));
  const report = await checkCompleteness({ receiptsDir: audit, verify: shopKeys, source: stripeSource({ secretKey: "rk_test_auditor_read_only", object: "refunds", baseUrl: `${stripeUrl}/` }), tools: ["stripe.refund"], sinceMs: started - 60_000, untilMs: Date.now() + 60_000 });
  console.log(`   matched to a receipt: ${report.matched.map((m) => m.providerId).join(", ")}`);
  console.log(`   in Stripe with no receipt: ${report.providerOnly.map((m) => `${m.providerId} (£${Number(m.amount) / 100})`).join(", ")}`);
  console.log(`   complete: ${report.complete}`);
  assert.deepEqual(report.matched.map((m) => m.providerId).sort(), ["re_1", "re_2"]);
  assert.deepEqual(report.providerOnly.map((m) => m.providerId), ["re_3"]);
  assert.deepEqual([report.unverified, report.receiptOnly, report.duplicates, report.forwardedWithoutOutcome], [[], [], [], []]);
  assert.equal(report.complete, false);

  step(11, "the phone leg: not in this run");
  console.log("   tells scoring the caller's voice, and the Twilio hook that carries the call, are not built yet");
} finally {
  await door.close();
  await host.close();
  await lanes.auto.close();
  await lanes.reviewed.close();
  shop.close();
  stripe.close();
}
console.log("\nOK");
