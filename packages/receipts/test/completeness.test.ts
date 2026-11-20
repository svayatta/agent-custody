// Completeness exists for the auditor's question after "can this record be trusted?": "is anything missing from it?".
// Nothing on the gateway's side can see an action taken straight through the provider, so the provider's own list is
// matched against verified receipts. These tests drive a real gateway against the stand-in Stripe, then answer the
// auditor's list call from a stub, so nothing reaches the network.
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkCompleteness, formatCompleteness, githubSource, stripeSource, type CompletenessOptions } from "../src/completeness.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import { createSdkIssuer, receiptIdOf } from "../src/sdk/index.ts";
import { buildFixture, buildSdkFixture, type Fixture, type SdkFixture } from "../scripts/fixture.ts";

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

  /** A fresh gateway under a config change, the calls it made, and options that verify its receipts. */
  const gatewayWith = async (change: (cfg: Record<string, unknown>) => void, calls: Record<string, unknown>[]) => {
    const g = buildFixture(mkdtempSync(join(tmpdir(), "completeness-gw-")));
    const cfg = JSON.parse(readFileSync(g.configFile, "utf8"));
    change(cfg);
    writeFileSync(g.configFile, JSON.stringify(cfg));
    const gw = await createGateway(loadConfig(g.configFile));
    const made: { receiptId: string; text: string }[] = [];
    try {
      for (const args of calls) {
        const r = await gw.handleCall({ name: "stripe.refund", arguments: args });
        made.push({ receiptId: String(r._meta![RECEIPT_META_KEY]), text: (r.content as { text: string }[])[0]!.text });
      }
    } finally {
      await gw.close();
    }
    const verify = { issuerKeys: [loadPublicKey(g.gatewayPub)], principalKeys: [loadPublicKey(g.principalPub)], logFile: g.logFile };
    return { g, made, with: (objects: StubObject[], extra: Partial<CompletenessOptions> = {}) => ({ ...opts(objects), receiptsDir: g.receiptsDir, verify, ...extra }) };
  };

  it("keeps every receipt that names one provider object, so a contradicting receipt cannot be dropped", async () => {
    // both refunds name the same customer: read as the object id, two verified receipts claim one provider object
    const object: StubObject = { id: "cust_123", created: Math.floor(Date.now() / 1000), amount: 2500 };
    const report = await checkCompleteness(opts([object], { idPath: "customer_id" }));
    expect(report.duplicates).toEqual([{ providerId: "cust_123", receiptIds: refunds.map((r) => r.receiptId).sort() }]);
    expect(report.mismatches).toEqual([{ receiptId: refunds[0]!.receiptId, providerId: "cust_123", field: "amount", receipt: 5000, provider: 2500 }]);
    expect(report.complete).toBe(false);
    expect(formatCompleteness(report)).toMatch(/ONE PROVIDER OBJECT, SEVERAL RECEIPTS \(1\)\n {2}cust_123 is named by/);
  });

  it("does not let another valid receipt, copied under the missing outcome's name, hide a call forwarded without an outcome", async () => {
    const { g, made, with: w } = await gatewayWith((cfg) => (cfg.precommit = ["stripe.refund"]), [{ customer_id: "cust_123", amount: 300 }, { customer_id: "cust_123", amount: 400 }]);
    const [a, b] = made.map((m) => m.receiptId) as [string, string];
    writeFileSync(join(g.receiptsDir, `${a}.json`), readFileSync(join(g.receiptsDir, `${b}.json`)));
    // and A's authorization renamed to B's, whose outcome exists: matched by the signed id, not the name
    writeFileSync(join(g.receiptsDir, `${b}.authorization.json`), readFileSync(join(g.receiptsDir, `${a}.authorization.json`)));
    rmSync(join(g.receiptsDir, `${a}.authorization.json`));
    const report = await checkCompleteness(w([]));
    expect(report.forwardedWithoutOutcome).toEqual([{ receiptId: a, tool: "stripe.refund" }]);
    expect(report.unverified).toHaveLength(2);
    expect(report.unverified).toEqual(expect.arrayContaining([
      { file: `${a}.json`, failing: [`the file name does not match the signed receipt id ${b}`] },
      { file: `${b}.authorization.json`, failing: [`the file name does not match the signed receipt id ${a}`] },
    ]));
    expect(report.complete).toBe(false);
    rmSync(g.dir, { recursive: true, force: true });
  });

  it("reports only what falls in the window: an earlier orphan, or an earlier mismatched pair found through the margin, is not a finding", async () => {
    const { g, made, with: w } = await gatewayWith((cfg) => (cfg.precommit = ["stripe.refund"]), [{ customer_id: "cust_123", amount: 300 }, { customer_id: "cust_123", amount: 400 }]);
    rmSync(join(g.receiptsDir, `${made[0]!.receiptId}.json`));
    const kept = JSON.parse(made[1]!.text) as { refund_id: string };
    // the call and the provider object are both five minutes before the window, inside the margin
    const later = { sinceMs: Date.now() + 5 * 60_000, untilMs: Date.now() + 60 * 60_000 };
    const report = await checkCompleteness(w([{ id: kept.refund_id, created: Math.floor(Date.now() / 1000), amount: 999 }], later));
    expect(report.forwardedWithoutOutcome).toEqual([]);
    expect(report.mismatches).toEqual([]);
    expect(report.complete).toBe(true);
    // the same evidence, in the window, is reported
    const now = await checkCompleteness(w([{ id: kept.refund_id, created: Math.floor(Date.now() / 1000), amount: 999 }]));
    expect(now.forwardedWithoutOutcome.map((f) => f.receiptId)).toEqual([made[0]!.receiptId]);
    expect(now.mismatches.map((m) => m.field)).toEqual(["amount"]);
    rmSync(g.dir, { recursive: true, force: true });
  });

  it("calls a currency withheld under a capture rule unmatchable, instead of skipping the comparison", async () => {
    const { g, made, with: w } = await gatewayWith((cfg) => (cfg.capture = { "stripe.refund": { args: { mode: "digest", clear: ["amount"] }, result: { mode: "clear" } } }), [{ customer_id: "cust_123", amount: 300, currency: "USD" }]);
    const { refund_id } = JSON.parse(made[0]!.text) as { refund_id: string };
    const report = await checkCompleteness(w([{ id: refund_id, created: Math.floor(Date.now() / 1000), amount: 300, currency: "eur" }]));
    expect(report.matched.map((m) => m.providerId)).toEqual([refund_id]);
    expect(report.unmatchable).toEqual([{ receiptId: made[0]!.receiptId, reason: expect.stringMatching(/"currency" is withheld/) }]);
    expect(report.complete).toBe(false);
    rmSync(g.dir, { recursive: true, force: true });
  });

  it("reads the provider id from result content kept in clear beside a commitment over the other fields", async () => {
    const { g, made, with: w } = await gatewayWith((cfg) => (cfg.capture = { "stripe.refund": { args: { mode: "digest", clear: ["customer_id", "amount"] }, result: { mode: "digest", clear: ["content"] } } }), [{ customer_id: "cust_123", amount: 300 }]);
    const receipt = JSON.parse(readFileSync(join(g.receiptsDir, `${made[0]!.receiptId}.json`), "utf8")) as { envelope: { payload: string } };
    expect(JSON.parse(Buffer.from(receipt.envelope.payload, "base64").toString()).predicate.execution.result).toHaveProperty("$rest");
    const { refund_id } = JSON.parse(made[0]!.text) as { refund_id: string };
    const report = await checkCompleteness(w([{ id: refund_id, created: Math.floor(Date.now() / 1000), amount: 300 }]));
    expect(report.matched).toEqual([{ receiptId: made[0]!.receiptId, providerId: refund_id }]);
    expect(report.complete).toBe(true);
    rmSync(g.dir, { recursive: true, force: true });
  });

  it("calls a receipt unmatchable when the id path does not reach a string in its result", async () => {
    const report = await checkCompleteness(opts(theProvider(), { idPath: "refund_id.0" }));
    expect(report.unmatchable).toEqual(expect.arrayContaining(refunds.map((r) => ({ receiptId: r.receiptId, reason: 'the result has no string or integer at "refund_id.0"' }))));
    expect(report.unmatchable).toHaveLength(2);
    expect(report.matched).toEqual([]);
    expect(report.providerOnly.map((p) => p.providerId).sort()).toEqual(refunds.map((r) => r.refundId).sort());
    expect(report.complete).toBe(false);
  });

  it("calls a receipt unmatchable when its result content is withheld and only other fields stay in clear", async () => {
    const { g, made, with: w } = await gatewayWith((cfg) => (cfg.capture = { "stripe.refund": { result: { mode: "digest", clear: ["isError"] } } }), [{ customer_id: "cust_123", amount: 300 }]);
    const report = await checkCompleteness(w([]));
    expect(report.unmatchable).toEqual([{ receiptId: made[0]!.receiptId, reason: expect.stringMatching(/result content is withheld/) }]);
    expect(report.complete).toBe(false);
    rmSync(g.dir, { recursive: true, force: true });
  });

  it("calls a receipt unmatchable when its result text is not JSON", async () => {
    const req = createRequire(import.meta.url);
    const sdk = (p: string) => JSON.stringify(req.resolve(`@modelcontextprotocol/sdk/${p}`));
    // answers the facts lookup in JSON and the refund in plain text
    const upstream = `const {Server}=require(${sdk("server/index.js")});const {StdioServerTransport}=require(${sdk("server/stdio.js")});const t=require(${sdk("types.js")});
      const s=new Server({name:"plain",version:"0"},{capabilities:{tools:{}}});
      s.setRequestHandler(t.ListToolsRequestSchema,async()=>({tools:["customer.lookup","stripe.refund"].map((name)=>({name,inputSchema:{type:"object"}}))}));
      s.setRequestHandler(t.CallToolRequestSchema,async({params})=>({content:[{type:"text",text:params.name==="customer.lookup"?JSON.stringify({verified:true}):"refunded"}]}));
      s.connect(new StdioServerTransport());`;
    const { g, made, with: w } = await gatewayWith((cfg) => (cfg.upstream = { command: process.execPath, args: ["-e", upstream] }), [{ customer_id: "cust_123", amount: 300 }]);
    expect(made[0]!.text).toBe("refunded");
    const report = await checkCompleteness(w([]));
    expect(report.unmatchable).toEqual([{ receiptId: made[0]!.receiptId, reason: "the result's text is not JSON" }]);
    expect(report.complete).toBe(false);
    rmSync(g.dir, { recursive: true, force: true });
  });

  it("puts a receipt or authorization file that cannot be read in unverified, and never matches it", async () => {
    const copy = mkdtempSync(join(tmpdir(), "completeness-malformed-"));
    for (const name of readdirSync(fx.receiptsDir).filter((n) => n.endsWith(".json"))) writeFileSync(join(copy, name), readFileSync(join(fx.receiptsDir, name)));
    writeFileSync(join(copy, `${refunds[0]!.receiptId}.json`), "not json");
    writeFileSync(join(copy, "orphan.authorization.json"), "{}");
    const report = await checkCompleteness({ ...opts(theProvider()), receiptsDir: copy });
    expect(report.unverified.map((u) => u.file).sort()).toEqual([`${refunds[0]!.receiptId}.json`, "orphan.authorization.json"]);
    expect(report.unverified.every((u) => u.failing.length === 1)).toBe(true);
    expect(report.matched.map((m) => m.receiptId)).toEqual([refunds[1]!.receiptId]);
    expect(report.providerOnly.map((p) => p.providerId)).toEqual([refunds[0]!.refundId]);
    expect(report.complete).toBe(false);
    rmSync(copy, { recursive: true, force: true });
  });

  it("calls an amount withheld under a capture rule unmatchable, instead of skipping the comparison", async () => {
    const { g, made, with: w } = await gatewayWith((cfg) => (cfg.capture = { "stripe.refund": { args: { mode: "digest", clear: ["customer_id"] }, result: { mode: "clear" } } }), [{ customer_id: "cust_123", amount: 300 }]);
    const { refund_id } = JSON.parse(made[0]!.text) as { refund_id: string };
    const report = await checkCompleteness(w([{ id: refund_id, created: Math.floor(Date.now() / 1000), amount: 999 }]));
    expect(report.matched.map((m) => m.providerId)).toEqual([refund_id]);
    expect(report.unmatchable).toEqual([{ receiptId: made[0]!.receiptId, reason: expect.stringMatching(/"amount" is withheld/) }]);
    expect(report.mismatches).toEqual([]);
    expect(report.complete).toBe(false);
    rmSync(g.dir, { recursive: true, force: true });
  });

  it("calls a receipt without the beneficiary argument unmatchable", async () => {
    const report = await checkCompleteness(opts(theProvider(), { beneficiary: { charge: "charge" } }));
    expect(report.unmatchable.map((u) => u.receiptId).sort()).toEqual(refunds.map((r) => r.receiptId).sort());
    expect(report.unmatchable.every((u) => /beneficiary argument "charge" is missing/.test(u.reason))).toBe(true);
    expect(report.complete).toBe(false);
  });

  it("stops on a Stripe object without an id instead of skipping it", async () => {
    const f = (async () => Response.json({ object: "list", data: [{ object: "refund", created: Math.floor(Date.now() / 1000), amount: 100 }], has_more: false })) as typeof fetch;
    await expect(checkCompleteness({ ...opts([]), source: stripeSource({ secretKey: KEY, object: "refunds", fetch: f }) })).rejects.toThrow(/without an id/);
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
    expect(run(["--provider", "github", "--key-env", "K"], { K: KEY }).stderr).toMatch(/--provider github needs --repo/);
    expect(run(["--provider", "stripe", "--repo", "acme/shop", "--key-env", "K"], { K: KEY }).stderr).toMatch(/--repo is for --provider github/);
    expect(run(["--provider", "github", "--repo", "acme/shop", "--key-env", "COMPLETENESS_TEST_KEY"]).stderr).toMatch(/COMPLETENESS_TEST_KEY is not set/);
    expect(run(["--provider", "github", "--repo", "acme/shop", "--key-env", "K", "--object", "refunds"], { K: KEY }).stderr).toMatch(/--object is one of pushes, merges, releases/);
  });
});

/** Answers the activity and releases lists the way GitHub does: an array, one entry a page, the next page in a Link header. */
function githubStub(lists: { activity?: Record<string, unknown>[]; releases?: Record<string, unknown>[] }, nextOrigin = "https://api.github.com") {
  const calls: URL[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    calls.push(url);
    if ((init?.headers as Record<string, string> | undefined)?.authorization !== `Bearer ${KEY}`) return new Response("unauthorised", { status: 401 });
    const list = lists[url.pathname.split("/").pop() as "activity" | "releases"] ?? [];
    const page = Number(url.searchParams.get("page") ?? 1);
    const headers = page < list.length ? { link: `<${nextOrigin}${url.pathname}?page=${page + 1}>; rel="next"` } : undefined;
    return Response.json(list.slice(page - 1, page), headers ? { headers } : {});
  }) as typeof fetch;
  return { f, calls };
}

describe("completeness against GitHub", () => {
  const sha = (c: string) => c.repeat(40);
  let fx: SdkFixture;
  let sinceMs: number;
  let untilMs: number;
  let now: string;
  const receipts: Record<string, string> = {};
  const opts = (object: "pushes" | "merges" | "releases", tool: string, stub: ReturnType<typeof githubStub>, extra: Partial<CompletenessOptions> = {}) => ({
    receiptsDir: fx.receiptsDir,
    verify: { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile },
    source: githubSource({ token: KEY, repo: "acme/shop", object, fetch: stub.f }),
    tools: [tool],
    sinceMs,
    untilMs,
    ...extra,
  });
  const entry = (activity_type: string, after: string, timestamp = now, ref = "refs/heads/main") => ({ activity_type, ref, before: sha("9"), after, timestamp });

  beforeAll(async () => {
    fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "completeness-github-")), "permit(principal, action, resource);");
    sinceMs = Date.now() - 60_000;
    const issuer = createSdkIssuer(loadSdkConfig(fx.configFile));
    const record = async (tool: string, args: Record<string, unknown>, result: unknown) => {
      const ev = { tool, args };
      receipts[tool] = receiptIdOf(await issuer.record(ev, { status: "executed", result: { content: [{ type: "text", text: JSON.stringify(result) }] } }, issuer.decide(ev)));
    };
    await record("github.merge", { pull_number: 7 }, { sha: sha("a"), merged: true });
    await record("github.push", { branch: "main" }, { object: { sha: sha("b") } });
    await record("github.release", { tag_name: "v1.0.0" }, { id: 4242, tag_name: "v1.0.0" });
    now = new Date().toISOString();
    untilMs = Date.now() + 60_000;
  });
  afterAll(() => rmSync(fx.dir, { recursive: true, force: true }));

  it("matches a merge by the commit the branch moved to, reads every page, and stops at the first entry older than the window", async () => {
    const old = new Date(sinceMs - 3600_000).toISOString();
    const stub = githubStub({ activity: [entry("branch_deletion", sha("0")), entry("push", sha("b")), entry("pr_merge", sha("a")), entry("pr_merge", sha("c"), old), entry("pr_merge", sha("d"), old)] });
    const report = await checkCompleteness(opts("merges", "github.merge", stub, { idPath: "sha" }));
    expect(report.matched).toEqual([{ receiptId: receipts["github.merge"], providerId: sha("a") }]);
    expect(report.complete).toBe(true);
    expect(report.provider).toBe("github merges in acme/shop");
    expect(stub.calls[0]!.pathname).toBe("/repos/acme/shop/activity");
    // five entries, one a page: the fourth is older than the window, so the fifth page is never asked for
    expect(stub.calls).toHaveLength(4);
  });

  it("reports a push made with another token as an action with no receipt, force pushes included", async () => {
    const stub = githubStub({ activity: [entry("force_push", sha("e")), entry("push", sha("b")), entry("pr_merge", sha("a"))] });
    const report = await checkCompleteness(opts("pushes", "github.push", stub, { idPath: "object.sha" }));
    expect(report.matched.map((m) => m.providerId)).toEqual([sha("b")]);
    expect(report.providerOnly.map((x) => x.providerId)).toEqual([sha("e")]);
    expect(report.complete).toBe(false);
  });

  it("reports a push that creates a branch: GitHub lists it only as a branch creation", async () => {
    const stub = githubStub({ activity: [entry("branch_creation", sha("f"), now, "refs/heads/outside"), entry("push", sha("b"))] });
    const report = await checkCompleteness(opts("pushes", "github.push", stub, { idPath: "object.sha" }));
    expect(report.providerOnly.map((x) => x.providerId)).toEqual([sha("f")]);
    expect(report.complete).toBe(false);
  });

  it("reports a second move to a commit that has a receipt, and reads a push that GitHub records twice as one", async () => {
    const twice = await checkCompleteness(opts("pushes", "github.push", githubStub({ activity: [entry("push", sha("b")), entry("push", sha("b"))] }), { idPath: "object.sha" }));
    expect(twice.matched).toHaveLength(1);
    expect(twice.complete).toBe(true);
    // the gated commit goes to a second branch with another token, and a later force push resets main to it
    const later = new Date(Date.parse(now) + 1000).toISOString();
    const stub = githubStub({ activity: [entry("force_push", sha("b"), later), entry("branch_creation", sha("b"), now, "refs/heads/release"), entry("push", sha("b"))] });
    const report = await checkCompleteness(opts("pushes", "github.push", stub, { idPath: "object.sha" }));
    expect(report.matched).toEqual([{ receiptId: receipts["github.push"], providerId: sha("b") }]);
    expect(report.providerOnly).toEqual([expect.objectContaining({ providerId: sha("b"), repeated: true }), expect.objectContaining({ providerId: sha("b"), repeated: true })]);
    expect(report.complete).toBe(false);
    expect(formatCompleteness(report)).toMatch(/the receipt for this id accounts for another action/);
  });

  it("matches a release by its numeric id, compares a beneficiary field, and reports a receipt whose release GitHub does not have", async () => {
    const release = (id: number, tag_name: string) => ({ id, tag_name, created_at: now, published_at: now });
    const moved = await checkCompleteness(opts("releases", "github.release", githubStub({ releases: [release(4242, "v9.9.9")] }), { beneficiary: { tag_name: "tag_name" } }));
    expect(moved.matched).toHaveLength(1);
    expect(moved.mismatches).toEqual([{ receiptId: receipts["github.release"], providerId: "4242", field: "tag_name", receipt: "v1.0.0", provider: "v9.9.9" }]);
    const gone = await checkCompleteness(opts("releases", "github.release", githubStub({ releases: [release(1, "v0.1.0")] })));
    expect(gone.receiptOnly.map((x) => x.providerId)).toEqual(["4242"]);
    expect(gone.providerOnly.map((x) => x.providerId)).toEqual(["1"]);
  });

  it("stops on a GitHub error, and never sends the token to a host that a Link header names", async () => {
    const wrong = githubSource({ token: "wrong", repo: "acme/shop", object: "releases", fetch: githubStub({}).f });
    await expect(checkCompleteness({ ...opts("releases", "github.release", githubStub({})), source: wrong })).rejects.toThrow(/HTTP 401/);
    const stub = githubStub({ releases: [{ id: 1, created_at: now }, { id: 2, created_at: now }] }, "https://evil.example");
    await expect(checkCompleteness(opts("releases", "github.release", stub))).rejects.toThrow(/another host/);
    expect(stub.calls).toHaveLength(1);
    expect(() => githubSource({ token: KEY, repo: "acme/shop/../../user", object: "pushes" })).toThrow(/owner\/name/);
  });
});
