// Completeness exists for the auditor's question after "can this record be trusted?": "is anything missing from it?".
// Nothing on the gateway's side can see an action taken straight through the provider, so the provider's own list is
// matched against verified receipts. These tests drive a real gateway against the stand-in Stripe, then answer the
// auditor's list call from a stub, so nothing reaches the network.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkCompleteness, formatCompleteness, stripeSource, type CompletenessOptions } from "../src/completeness.ts";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import { buildFixture, type Fixture } from "../scripts/fixture.ts";

const KEY = "rk_test_auditor_read_only";

interface StubObject {
  id: string;
  created: number;
  amount?: number;
  currency?: string;
  metadata?: Record<string, string>;
}

/** Answers GET /v1/refunds the way Stripe pages a list, and records what was asked. */
function stripeStub(objects: StubObject[], pageSize = 100) {
  const calls: URL[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    calls.push(url);
    if ((init?.headers as Record<string, string> | undefined)?.authorization !== `Bearer ${KEY}`) return new Response("unauthorised", { status: 401 });
    const gte = Number(url.searchParams.get("created[gte]"));
    const lt = Number(url.searchParams.get("created[lt]"));
    const after = url.searchParams.get("starting_after");
    const inRange = objects.filter((o) => o.created >= gte && o.created < lt).sort((a, b) => b.created - a.created);
    const start = after ? inRange.findIndex((o) => o.id === after) + 1 : 0;
    const data = inRange.slice(start, start + pageSize).map((o) => ({ object: "refund", ...o }));
    return Response.json({ object: "list", data, has_more: start + pageSize < inRange.length });
  }) as typeof fetch;
  return { f, calls };
}

describe("completeness from the provider's side", () => {
  let fx: Fixture;
  let refunds: { receiptId: string; refundId: string; amount: number; created: number }[] = [];
  let sinceMs: number;
  let untilMs: number;
  const opts = (objects: StubObject[], extra: Partial<CompletenessOptions> = {}) => ({
    receiptsDir: fx.receiptsDir,
    verify: { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile },
    source: stripeSource({ secretKey: KEY, object: "refunds", fetch: stripeStub(objects).f }),
    tools: ["stripe.refund"],
    sinceMs,
    untilMs,
    idPath: "refund_id",
    ...extra,
  });
  /** what the provider holds when everything went through the gateway */
  const theProvider = (): StubObject[] => refunds.map((r) => ({ id: r.refundId, created: r.created, amount: r.amount, currency: "gbp", metadata: { customer_id: "cust_123" } }));

  beforeAll(async () => {
    fx = buildFixture(mkdtempSync(join(tmpdir(), "completeness-")));
    sinceMs = Date.now() - 60_000;
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      for (const amount of [5000, 2500]) {
        const r = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount, currency: "GBP" } });
        const receiptId = String(r._meta![RECEIPT_META_KEY]);
        const text = (r.content as { text: string }[])[0]!.text;
        refunds.push({ receiptId, refundId: (JSON.parse(text) as { refund_id: string }).refund_id, amount, created: Math.floor(Date.now() / 1000) });
      }
      // denied by policy: never forwarded, so the provider is not expected to hold anything for it
      await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_999", amount: 100 } });
    } finally {
      await gw.close();
    }
    untilMs = Date.now() + 60_000;
  });
  afterAll(() => rmSync(fx.dir, { recursive: true, force: true }));

  it("is complete when every provider object in the window has a verified receipt, reading every page of the list", async () => {
    const stub = stripeStub(theProvider(), 1);
    const report = await checkCompleteness({ ...opts([]), source: stripeSource({ secretKey: KEY, object: "refunds", fetch: stub.f }) });
    expect(report.complete).toBe(true);
    expect(report.matched.map((m) => m.providerId).sort()).toEqual(refunds.map((r) => r.refundId).sort());
    expect(report.receiptsRead).toBe(3);
    // one object a page: the second request continues after the first page's object, and has_more stops the loop
    expect(stub.calls).toHaveLength(2);
    expect(stub.calls[0]!.searchParams.get("starting_after")).toBeNull();
    expect(refunds.map((r) => r.refundId)).toContain(stub.calls[1]!.searchParams.get("starting_after"));
    // the window is widened by the margin, so an object just outside a boundary still finds its receipt
    expect(Number(stub.calls[0]!.searchParams.get("created[gte]"))).toBe(Math.floor((sinceMs - 15 * 60_000) / 1000));
    expect(formatCompleteness(report)).toMatch(/RESULT: COMPLETE$/);
  });

  it("reports a refund issued straight through the provider, outside the gateway, as an action with no receipt", async () => {
    const direct: StubObject = { id: "re_direct_api", created: Math.floor(Date.now() / 1000), amount: 9999, currency: "gbp" };
    const report = await checkCompleteness(opts([...theProvider(), direct]));
    expect(report.complete).toBe(false);
    expect(report.providerOnly).toEqual([{ providerId: "re_direct_api", created: new Date(direct.created * 1000).toISOString(), amount: 9999, currency: "gbp" }]);
    expect(formatCompleteness(report)).toMatch(/PROVIDER ACTIONS WITH NO RECEIPT \(1\)\n {2}re_direct_api/);
  });

  it("reports a receipt whose refund the provider does not have", async () => {
    const report = await checkCompleteness(opts(theProvider().slice(1)));
    expect(report.complete).toBe(false);
    expect(report.receiptOnly).toEqual([expect.objectContaining({ receiptId: refunds[0]!.receiptId, providerId: refunds[0]!.refundId })]);
  });

  it("reports an amount the provider recorded differently from the receipt", async () => {
    const provider = theProvider();
    provider[0]!.amount = 50000;
    const report = await checkCompleteness(opts(provider));
    expect(report.mismatches).toEqual([{ receiptId: refunds[0]!.receiptId, providerId: refunds[0]!.refundId, field: "amount", receipt: 5000, provider: 50000 }]);
    expect(report.complete).toBe(false);
  });

  it("compares the currency, ignoring case, and fails on a different one", async () => {
    // the receipts say "GBP", the provider "gbp": the same currency
    expect((await checkCompleteness(opts(theProvider()))).mismatches).toEqual([]);
    const provider = theProvider();
    provider[1]!.currency = "usd";
    const report = await checkCompleteness(opts(provider));
    expect(report.mismatches).toEqual([{ receiptId: refunds[1]!.receiptId, providerId: refunds[1]!.refundId, field: "currency", receipt: "GBP", provider: "usd" }]);
  });

  it("compares a beneficiary argument with the provider's field, and fails on a difference", async () => {
    const same = await checkCompleteness(opts(theProvider(), { beneficiary: { customer_id: "metadata.customer_id" } }));
    expect(same.complete).toBe(true);
    const provider = theProvider();
    provider[1]!.metadata = { customer_id: "cust_other" };
    const different = await checkCompleteness(opts(provider, { beneficiary: { customer_id: "metadata.customer_id" } }));
    expect(different.mismatches).toEqual([expect.objectContaining({ receiptId: refunds[1]!.receiptId, field: "customer_id", receipt: "cust_123", provider: "cust_other" })]);
  });

  it("does not report objects created outside the window, though it lists them to find their receipts", async () => {
    const early: StubObject = { id: "re_before_window", created: Math.floor((sinceMs - 5 * 60_000) / 1000), amount: 1 };
    const report = await checkCompleteness(opts([...theProvider(), early]));
    expect(report.complete).toBe(true);
  });

  it("matches only receipts that verify: an edited receipt is reported, and its provider object then has no receipt", async () => {
    const copy = mkdtempSync(join(tmpdir(), "completeness-copy-"));
    for (const name of readdirSync(fx.receiptsDir).filter((n) => n.endsWith(".json"))) writeFileSync(join(copy, name), readFileSync(join(fx.receiptsDir, name)));
    const file = join(copy, `${refunds[0]!.receiptId}.json`);
    const bundle = JSON.parse(readFileSync(file, "utf8")) as { envelope: { payload: string } };
    const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString());
    st.predicate.request.args.amount = 1;
    bundle.envelope.payload = Buffer.from(JSON.stringify(st)).toString("base64");
    writeFileSync(file, JSON.stringify(bundle));
    const report = await checkCompleteness({ ...opts(theProvider()), receiptsDir: copy });
    expect(report.unverified.map((u) => u.file)).toEqual([`${refunds[0]!.receiptId}.json`]);
    expect(report.providerOnly.map((p) => p.providerId)).toEqual([refunds[0]!.refundId]);
    expect(report.complete).toBe(false);
    rmSync(copy, { recursive: true, force: true });
  });

  it("does not match a receipt whose signature holds but whose log proof does not", async () => {
    const copy = mkdtempSync(join(tmpdir(), "completeness-proof-"));
    for (const name of readdirSync(fx.receiptsDir).filter((n) => n.endsWith(".json"))) writeFileSync(join(copy, name), readFileSync(join(fx.receiptsDir, name)));
    const file = join(copy, `${refunds[1]!.receiptId}.json`);
    const bundle = JSON.parse(readFileSync(file, "utf8")) as { inclusion: { hashes: string[] } };
    bundle.inclusion.hashes = bundle.inclusion.hashes.map(() => "00".repeat(32));
    writeFileSync(file, JSON.stringify(bundle));
    const report = await checkCompleteness({ ...opts(theProvider()), receiptsDir: copy });
    expect(report.unverified).toEqual([{ file: `${refunds[1]!.receiptId}.json`, failing: expect.arrayContaining(["log inclusion proof"]) }]);
    expect(report.matched.map((m) => m.receiptId)).not.toContain(refunds[1]!.receiptId);
    expect(report.providerOnly.map((p) => p.providerId)).toEqual([refunds[1]!.refundId]);
    rmSync(copy, { recursive: true, force: true });
  });

  it("calls a receipt unmatchable, never matched or missing, when a capture rule withholds its result", async () => {
    const priv = buildFixture(mkdtempSync(join(tmpdir(), "completeness-private-")));
    const cfg = JSON.parse(readFileSync(priv.configFile, "utf8"));
    cfg.capture = { "stripe.refund": { result: { mode: "digest" } } };
    writeFileSync(priv.configFile, JSON.stringify(cfg));
    const gw = await createGateway(loadConfig(priv.configFile));
    let receiptId: string;
    try {
      receiptId = String((await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 700 } }))._meta![RECEIPT_META_KEY]);
    } finally {
      await gw.close();
    }
    const report = await checkCompleteness({ ...opts([]), receiptsDir: priv.receiptsDir, verify: { issuerKeys: [loadPublicKey(priv.gatewayPub)], principalKeys: [loadPublicKey(priv.principalPub)], logFile: priv.logFile } });
    expect(report.unmatchable).toEqual([{ receiptId, reason: expect.stringMatching(/withheld under a capture rule/) }]);
    expect(report.receiptOnly).toEqual([]);
    expect(report.complete).toBe(false);
    rmSync(priv.dir, { recursive: true, force: true });
  });

  it("lists a call committed and forwarded whose outcome receipt is missing, so its provider object is explained, not just counted", async () => {
    const pre = buildFixture(mkdtempSync(join(tmpdir(), "completeness-precommit-")));
    const cfg = JSON.parse(readFileSync(pre.configFile, "utf8"));
    cfg.precommit = ["stripe.refund"];
    writeFileSync(pre.configFile, JSON.stringify(cfg));
    const gw = await createGateway(loadConfig(pre.configFile));
    let receiptId: string;
    try {
      receiptId = String((await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 300 } }))._meta![RECEIPT_META_KEY]);
    } finally {
      await gw.close();
    }
    // the gateway died after forwarding: the authorization was committed, the outcome receipt never written
    rmSync(join(pre.receiptsDir, `${receiptId}.json`));
    const report = await checkCompleteness({ ...opts([]), receiptsDir: pre.receiptsDir, verify: { issuerKeys: [loadPublicKey(pre.gatewayPub)], principalKeys: [loadPublicKey(pre.principalPub)], logFile: pre.logFile } });
    expect(report.forwardedWithoutOutcome).toEqual([{ receiptId, tool: "stripe.refund" }]);
    expect(report.complete).toBe(false);
    rmSync(pre.dir, { recursive: true, force: true });
  });

  it("stops on a provider error instead of reporting a partial list as complete", async () => {
    const report = checkCompleteness({ ...opts([]), source: stripeSource({ secretKey: "rk_wrong", object: "refunds", fetch: stripeStub(theProvider()).f }) });
    await expect(report).rejects.toThrow(/HTTP 401/);
  });

  it("the CLI takes the key from the environment and refuses what it cannot check", () => {
    const cli = join(import.meta.dirname, "..", "src", "cli.ts");
    const base = ["--import", "tsx", cli, "completeness", "--receipts", fx.receiptsDir, "--issuer-key", fx.gatewayPub, "--tool", "stripe.refund", "--since", new Date(sinceMs).toISOString(), "--until", new Date(untilMs).toISOString()];
    const run = (extra: string[], env: Record<string, string> = {}) => spawnSync(process.execPath, [...base, ...extra], { encoding: "utf8", timeout: 30_000, env: { ...process.env, ...env } });
    expect(run(["--provider", "stripe", "--key-env", "COMPLETENESS_TEST_KEY"]).stderr).toMatch(/COMPLETENESS_TEST_KEY is not set/);
    expect(run(["--provider", "paypal", "--key-env", "K"], { K: KEY }).stderr).toMatch(/supports --provider stripe/);
    expect(run(["--provider", "stripe", "--key-env", "K", "--object", "charges"], { K: KEY }).stderr).toMatch(/--object is one of refunds, payouts, transfers/);
    expect(run(["--provider", "stripe", "--key-env", "K", "--beneficiary", "charge"], { K: KEY }).stderr).toMatch(/--beneficiary takes/);
  });
});
