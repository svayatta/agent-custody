// `init refunds` is the pilot in a box. These tests hold it to what a pilot promises: the refund is decided by the
// team's policy on a payment the gateway looked up itself, sent with a key the agent never holds, the over-limit
// request never reaches Stripe, the receipt verifies, and nothing runs against a live Stripe key.
import { createServer, type Server } from "node:http";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initRefunds, runRefunds } from "../src/refunds-init.ts";

type Seen = { method: string; path: string; auth: string | undefined; type: string | undefined; body: string };

/** A Stripe stand-in: form bodies only, as Stripe's v1 API; payment intents carry nulls, as real ones do. */
function fakeStripe(paymentStatus = "succeeded"): Promise<{ server: Server; url: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const intents = new Map<string, Record<string, unknown>>();
  const refunds: Record<string, unknown>[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method!, path: req.url!, auth: req.headers.authorization, type: req.headers["content-type"], body });
      const send = (status: number, v: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(v));
      };
      if (req.headers.authorization !== "Bearer sk_test_pilot") return send(401, { error: { message: "Invalid API Key" } });
      const form = new URLSearchParams(body);
      if (req.method === "POST" && req.url === "/v1/payment_intents") {
        const id = `pi_${intents.size + 1}`;
        const amount = Number(form.get("amount"));
        const pi = { id, object: "payment_intent", amount, amount_received: paymentStatus === "succeeded" ? amount : 0, currency: form.get("currency"), status: paymentStatus, description: null, customer: null, metadata: {}, last_payment_error: null };
        intents.set(id, pi);
        return send(200, pi);
      }
      const m = /^\/v1\/payment_intents\/([^/?]+)$/.exec(req.url!);
      if (req.method === "GET" && m) return intents.has(m[1]!) ? send(200, intents.get(m[1]!)) : send(404, { error: { message: "No such payment_intent" } });
      const list = /^\/v1\/refunds\?payment_intent=([^&]+)$/.exec(req.url!);
      if (req.method === "GET" && list) return send(200, { object: "list", data: refunds.filter((r) => r.payment_intent === decodeURIComponent(list[1]!)), has_more: false, url: "/v1/refunds" });
      if (req.method === "POST" && req.url === "/v1/refunds") {
        const pi = intents.get(form.get("payment_intent") ?? "");
        const amount = Number(form.get("amount"));
        if (!pi || !form.get("amount")) return send(400, { error: { message: "Must provide payment_intent or charge" } });
        const refunded = refunds.filter((r) => r.payment_intent === pi.id).reduce((n, r) => n + (r.amount as number), 0);
        if (amount <= 0 || refunded + amount > (pi.amount_received as number)) return send(400, { error: { message: "Refund amount is greater than unrefunded amount on charge" } });
        const refund = { id: `re_${refunds.length + 1}`, object: "refund", amount, payment_intent: pi.id, status: "succeeded", reason: null };
        refunds.push(refund);
        return send(200, refund);
      }
      send(404, { error: { message: "Unrecognized request URL" } });
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, seen })));
}

const quiet = () => {};

describe("init refunds", () => {
  let stripe: Awaited<ReturnType<typeof fakeStripe>>;
  beforeAll(async () => { stripe = await fakeStripe(); });
  afterAll(() => stripe.server.close());

  it("writes keys, a grant, the policy and a gateway config, and refuses to overwrite them", () => {
    const dir = join(mkdtempSync(join(tmpdir(), "refunds-")), "pilot");
    initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl: stripe.url, print: quiet });
    for (const f of ["keys/gateway.key", "keys/principal.pub", "grant.json", "policy.cedar", "gateway.json"]) expect(existsSync(join(dir, f))).toBe(true);
    const cfg = JSON.parse(readFileSync(join(dir, "gateway.json"), "utf8"));
    expect(cfg.precommit).toEqual(["stripe.refund"]);
    expect(cfg.upstream.rest.tools.find((t: { name: string }) => t.name === "stripe.refund").body).toBe("form");
    expect(JSON.stringify(cfg)).not.toMatch(/sk_test|sk_live/);
    expect(() => initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, print: quiet })).toThrow(/already exists/);
    expect(() => initRefunds({ dir: dir + "2", limit: 50.5, currency: "gbp", ttlHours: 24, print: quiet })).toThrow(/--limit/);
    expect(() => initRefunds({ dir: dir + "3", limit: 5000, currency: "GBP", ttlHours: 24, print: quiet })).toThrow(/--currency/);
  });

  it("runs only with a Stripe test-mode key, so it cannot move real money", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "refunds-")), "pilot");
    initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl: stripe.url, print: quiet });
    const before = stripe.seen.length;
    await expect(runRefunds({ dir, env: {}, print: quiet })).rejects.toThrow(/STRIPE_SECRET_KEY is not set/);
    await expect(runRefunds({ dir, env: { STRIPE_SECRET_KEY: "sk_live_x" }, print: quiet })).rejects.toThrow(/not a test-mode key/);
    expect(stripe.seen.length).toBe(before);
  });

  it("refunds through the gateway with a form body and the gateway's key, refuses the over-limit request before Stripe, and the receipt verifies", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "refunds-")), "pilot");
    initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl: stripe.url, print: quiet });
    const start = stripe.seen.length;
    const r = await runRefunds({ dir, env: { STRIPE_SECRET_KEY: "sk_test_pilot" }, print: quiet });
    expect(r).toMatchObject({ refused: true, verified: true });
    const refunds = stripe.seen.slice(start).filter((s) => s.path === "/v1/refunds");
    expect(refunds).toHaveLength(1);
    expect(refunds[0]!.type).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(refunds[0]!.body))).toEqual({ payment_intent: r.paymentIntent, amount: "5000" });
    expect(stripe.seen.slice(start).some((s) => s.path === `/v1/payment_intents/${r.paymentIntent}`)).toBe(true);
  });

  // A refund after a lost response must not pay twice. Stripe has no lookup by idempotency key, so the gateway looks up
  // the payment's refunds itself and the policy permits one refund per payment.
  it("refuses a retried refund because the gateway's own lookup finds the first one, and Stripe sees only one", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "refunds-")), "pilot");
    initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl: stripe.url, print: quiet });
    const start = stripe.seen.length;
    const lines: string[] = [];
    const r = await runRefunds({ dir, env: { STRIPE_SECRET_KEY: "sk_test_pilot" }, print: (l) => lines.push(l) });
    expect(r.refused).toBe(true);
    expect(lines.join("\n")).toMatch(/retries the same refund.*refused, because the gateway found the first refund/);
    expect(stripe.seen.slice(start).filter((s) => s.method === "POST" && s.path === "/v1/refunds")).toHaveLength(1);
    expect(stripe.seen.slice(start).some((s) => s.path === `/v1/refunds?payment_intent=${r.paymentIntent}`)).toBe(true);
  });

  // An amount of 0 or less is not a refund; Cedar allows a negative Long, so the policy has to say so.
  it("denies a refund of 0 or less before it reaches Stripe", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "refunds-")), "pilot");
    initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl: stripe.url, print: quiet });
    const { evaluate } = await import("../src/policy.ts");
    const policy = readFileSync(join(dir, "policy.cedar"), "utf8");
    const facts = { payment: { status: "succeeded", currency: "gbp", amount_received: 10000 }, refunds: { data: [] } };
    const ask = (amount: number) => evaluate(policy, { agentId: "refund-agent", tool: "stripe.refund", context: { args: { payment_intent: "pi_1", amount }, facts } }).decision;
    expect([ask(-1), ask(0), ask(1), ask(5000), ask(5001)]).toEqual(["deny", "deny", "allow", "allow", "deny"]);
  });

  // --run exits 0 only when the policy refused: a request Stripe received and rejected is not a policy refusal.
  it("does not count a call that reached Stripe as refused, even when Stripe rejected it", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "refunds-")), "pilot");
    initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl: stripe.url, print: quiet });
    writeFileSync(join(dir, "policy.cedar"), '// what --run reads: context.args.amount <= 5000, context.facts.payment.currency == "gbp"\npermit(principal, action, resource);\n');
    const r = await runRefunds({ dir, env: { STRIPE_SECRET_KEY: "sk_test_pilot" }, print: quiet });
    expect(r.refused).toBe(false);
  });

  it("refuses a refund against a payment the gateway did not see succeed", async () => {
    const failed = await fakeStripe("requires_payment_method");
    try {
      const dir = join(mkdtempSync(join(tmpdir(), "refunds-")), "pilot");
      initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl: failed.url, print: quiet });
      const r = await runRefunds({ dir, env: { STRIPE_SECRET_KEY: "sk_test_pilot" }, print: quiet });
      expect(r.verified).toBe(false);
      expect(failed.seen.some((s) => s.path === "/v1/refunds")).toBe(false);
    } finally {
      failed.server.close();
    }
  });
});

describe("agent-custody init refunds (CLI)", () => {
  const cli = join(import.meta.dirname, "../src/cli.ts");
  const run = (args: string[], env: Record<string, string> = {}) => spawnSync(process.execPath, [cli, "init", "refunds", ...args], { encoding: "utf8", env: { PATH: process.env.PATH ?? "", ...env } });
  it("writes the pilot, says what to run next, and --run without a test key exits 1 before touching Stripe", () => {
    const dir = join(mkdtempSync(join(tmpdir(), "refunds-cli-")), "pilot");
    const first = run(["--dir", dir, "--limit", "2500"]);
    expect(first.status).toBe(0);
    expect(first.stdout).toContain("one refund per payment, up to 2500 GBP minor units");
    expect(first.stdout).toContain("--run");
    expect(run(["--dir", dir]).stderr).toContain("already exists; add --run");
    const live = run(["--dir", dir, "--run"], { STRIPE_SECRET_KEY: "sk_live_x" });
    expect(live.status).toBe(1);
    expect(live.stderr).toContain("not a test-mode key");
  });
});
