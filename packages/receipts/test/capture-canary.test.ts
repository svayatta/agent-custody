// The canary: one secret in the withheld arguments of a call, an upstream that repeats it in every place a result can
// carry a value, and every path a call can take through the gateway and the SDK. Under one private rule, the secret
// must reach nothing the receipt leaves in clear: not the signed statement, not the authorization inside it, not the
// authorization file, not the log, not an exporter. The control runs the same calls with no rule and finds the secret,
// so that the check can fail. Every leak of the four review rounds on #123 would have failed this test.
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY, type Gateway } from "../src/gateway.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import { spanFor } from "../src/otel.ts";
import type { ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { hecEvent } from "../src/splunk.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildFixture, buildSdkFixture } from "../scripts/fixture.ts";

const CANARY = `CANARY_${randomBytes(8).toString("hex")}`;
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
/** the text with every base64 `payload` field decoded in place, applied until nothing is left encoded: the statement, the authorization and the upstream's envelope inside it, the grant */
const decodeAll = (text: string): string => {
  let out = text;
  for (let i = 0; i < 4; i++) {
    const next = out.replace(/"payload":\s*"([A-Za-z0-9+/=]+)"/g, (_m, b64: string) => `"payload":${JSON.stringify(Buffer.from(b64, "base64").toString())}`);
    if (next === out) break;
    out = next;
  }
  return out;
};
/** everything a receipt file says, decoded, nested payloads included */
const bundleText = (b: ReceiptBundle): string => decodeAll(JSON.stringify(b));
/** every file in the receipts directory and every log line, decoded */
const onDisk = (receiptsDir: string, logFile: string): string => decodeAll([...readdirSync(receiptsDir).map((f) => readFileSync(join(receiptsDir, f), "utf8")), readFileSync(logFile, "utf8")].join("\n"));
/** an exporter that keeps what the issuer hands it, and what the two real exporters would send of it */
const keepExports = () => {
  const seen: string[] = [];
  const spans: unknown[] = [];
  return {
    seen,
    spans,
    exporter: {
      where: "test",
      async exported(p: ReceiptPredicate, b: ReceiptBundle) {
        const span = spanFor(p, b, "agent-custody");
        spans.push(span);
        seen.push(JSON.stringify(p), JSON.stringify(span), JSON.stringify(hecEvent(p, b, { url: "https://splunk.example", tokenEnv: "X" })));
      },
    },
  };
};
/** the OTLP status of a span as exported: `message` is a string there, whatever the receipt holds */
const statusOf = (span: unknown) => (span as { resourceSpans: { scopeSpans: { spans: { status: { code: number; message?: unknown } }[] }[] }[] }).resourceSpans[0]!.scopeSpans[0]!.spans[0]!.status;
const withheldLog = (inner: LogSink): LogSink => ({
  kind: inner.kind,
  where: inner.where,
  async append(leaf) {
    const st = JSON.parse(Buffer.from((JSON.parse(leaf) as { payload: string }).payload, "base64").toString()) as { predicateType: string };
    if (st.predicateType.includes("/authorization/")) throw new Error("log is read-only for this tenant");
    return inner.append(leaf);
  },
});

/** every path through the gateway, each with the canary in a withheld argument */
async function everyGatewayPath(gw: Gateway, gwWithheld: Gateway): Promise<{ name: string; result: { _meta?: Record<string, unknown>; isError?: boolean } }[]> {
  const call = (name: string, args: Record<string, unknown>, through = gw, tool = "stripe.refund") => through.handleCall({ name: tool, arguments: args }).then((result) => ({ name, result }));
  return [
    // executed, with a provider delivery, pre-committed: the authorization is in play
    await call("executed", { customer_id: CANARY, account_ref: CANARY, amount: 2500 }),
    // the upstream answers isError
    await call("failed", { customer_id: CANARY, account_ref: CANARY, amount: 2500, reason: "error" }),
    // the upstream throws
    await call("thrown", { customer_id: CANARY, account_ref: CANARY, amount: 2500, reason: "throw" }),
    // the policy denies: over the limit, after the lookup ran
    await call("denied", { customer_id: CANARY, account_ref: CANARY, amount: 5_000_000 }),
    // the lookup answers isError, and the lookup throws: the answer lands in the policy errors and the denial reason
    await call("lookup isError", { customer_id: CANARY, account_ref: `cust_error_${CANARY}`, amount: 2500 }),
    await call("lookup throws", { customer_id: CANARY, account_ref: `cust_throw_${CANARY}`, amount: 2500 }),
    // out of the grant's scopes
    await call("out of scope", { customer_id: CANARY, amount: 2500 }, gw, "stripe.payout"),
    // the log refuses the authorization: withheld, nothing forwarded
    await call("withheld", { customer_id: CANARY, account_ref: CANARY, amount: 2500 }, gwWithheld),
  ];
}
const TOOLS: Record<string, string> = { "out of scope": "stripe.payout" };

describe("the canary", () => {
  it("under one private rule, a secret in the arguments reaches nothing in clear on any path through the gateway: statement, authorization, files, log, exporters", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "canary-gateway-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
    cfg.upstream.args.push("--webhook-secret", "whsec_canary");
    // two facts with the same name, one copying a renamed argument: the lookup argument is withheld by its source
    cfg.facts = [
      { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.payout"] },
      { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] },
    ];
    cfg.precommit = ["stripe.refund"];
    cfg.capture = { "*": { args: { mode: "digest", clear: ["amount"] } } };
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const exports = keepExports();
    const gw = await createGateway(loadConfig(fx.configFile), { exporter: exports.exporter });
    // the second gateway's log refuses authorizations; it keeps its own log file and receipts, as two writers of one log would not
    const withheldDir = join(fx.dir, "receipts-withheld");
    const withheldLogFile = join(fx.dir, "log-withheld.jsonl");
    writeFileSync(join(fx.dir, "gateway-withheld.json"), JSON.stringify({ ...cfg, receiptsDir: "receipts-withheld", logFile: "log-withheld.jsonl" }));
    const gwWithheld = await createGateway(loadConfig(join(fx.dir, "gateway-withheld.json")), { exporter: exports.exporter, log: withheldLog(fileLog(withheldLogFile, loadPrivateKey(join(fx.dir, "keys", "gateway.key")))) });
    try {
      const calls = await everyGatewayPath(gw, gwWithheld);
      const statuses: Record<string, string> = {};
      for (const { name, result } of calls) {
        const id = String(result._meta![RECEIPT_META_KEY]);
        const own = name === "withheld" ? { receiptsDir: withheldDir, logFile: withheldLogFile } : { receiptsDir: fx.receiptsDir, logFile: fx.logFile };
        const bundle = JSON.parse(readFileSync(join(own.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
        const p = decode(bundle).predicate;
        statuses[name] = p.execution.status;
        expect(bundleText(bundle), `${name}: the receipt carries the canary`).not.toContain(CANARY);
        const v = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], providerSecrets: { stripe: "whsec_canary" }, logFile: own.logFile });
        expect(v.ok, `${name}: ${formatReport(v)}`).toBe(true);
        expect(p.tool.name).toBe(TOOLS[name] ?? "stripe.refund");
      }
      expect(statuses).toEqual({ executed: "executed", failed: "failed", thrown: "error", denied: "denied", "lookup isError": "denied", "lookup throws": "denied", "out of scope": "denied", withheld: "withheld" });
      expect(onDisk(fx.receiptsDir, fx.logFile), "a file on disk carries the canary").not.toContain(CANARY);
      expect(onDisk(withheldDir, withheldLogFile), "a file on disk carries the canary").not.toContain(CANARY);
      expect(exports.seen.join("\n"), "an export carries the canary").not.toContain(CANARY);
      expect(exports.seen.length).toBe(calls.length * 3);
      // the OTLP status message is a string, a fixed one where the error is a commitment
      for (const span of exports.spans) expect(["string", "undefined"]).toContain(typeof statusOf(span).message);
      expect(exports.spans.map((s) => statusOf(s).message)).toContain("the upstream reported an error (withheld under the capture rule)");
      // the upstream's signed payload carried the id as an extra claim: the envelope is withheld with the result
      const failed = calls.find((c) => c.name === "failed")!;
      const failedBundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(failed.result._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
      expect((decode(failedBundle).predicate.capture?.withheld ?? []).map((w) => w.join("."))).toContain("execution.upstream.envelope");
      // the agent got everything: the real answers, the real errors (a policy denial names the policy, not the arguments)
      expect(calls.filter((c) => (c.result as { content: { text: string }[] }).content[0]!.text.includes(CANARY)).map((c) => c.name)).toEqual(["executed", "failed", "thrown", "lookup isError", "lookup throws"]);
    } finally {
      await gw.close();
      await gwWithheld.close();
    }
  });

  it("the control: the same calls with no rule carry the canary in the statement, the files, the log, and the exports", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "canary-control-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
    cfg.upstream.args.push("--webhook-secret", "whsec_canary");
    cfg.facts = [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] }];
    cfg.precommit = ["stripe.refund"];
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const exports = keepExports();
    const gw = await createGateway(loadConfig(fx.configFile), { exporter: exports.exporter });
    try {
      const calls = await everyGatewayPath(gw, gw);
      const carrying = calls.filter(({ result }) => {
        const id = String(result._meta![RECEIPT_META_KEY]);
        return bundleText(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle).includes(CANARY);
      });
      expect(carrying.map((c) => c.name)).toEqual(calls.map((c) => c.name));
      expect(onDisk(fx.receiptsDir, fx.logFile)).toContain(CANARY);
      expect(exports.seen.join("\n")).toContain(CANARY);
    } finally {
      await gw.close();
    }
  });

  it("under one private rule, a secret reaches nothing in clear through the SDK: record on every outcome, and wrap with a tool that throws, which is the path every adapter takes", async () => {
    const fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "canary-sdk-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "digest", clear: ["amount"] } } };
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
    const ev = { tool: "stripe.refund", args: { customer_id: CANARY, amount: 900 } };
    const bundles = [
      await sdk.record(ev, { status: "executed", result: { content: [{ type: "text", text: `refunded ${CANARY}` }], structuredContent: { id: CANARY }, _meta: { trace: CANARY } } }),
      await sdk.record(ev, { status: "failed", result: { content: [{ type: "text", text: `refused ${CANARY}` }], isError: true } }),
      await sdk.record(ev, { status: "error", error: `declined for ${CANARY}` }),
      await sdk.record(ev, { status: "denied", reason: `no permit for ${CANARY}` }, { decision: "deny", reasons: [], errors: [`lookup failed for ${CANARY}`], policyDigest: "d" }),
      await sdk.record({ tool: "stripe.refund", args: { customer_id: CANARY, amount: 900 } }, { status: "executed", result: `plain string with ${CANARY}` }),
    ];
    const wrapped = sdk.wrap("stripe.refund", async (a: { customer_id: string; amount: number }) => {
      throw new Error(`card declined for ${a.customer_id}`);
    });
    await expect(wrapped({ customer_id: CANARY, amount: 900 })).rejects.toThrow(CANARY);
    for (const b of bundles) {
      expect(bundleText(b)).not.toContain(CANARY);
      const v = verifyBundle(b, { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile });
      expect(v.ok, formatReport(v)).toBe(true);
      const span = spanFor(decode(b).predicate, b, "agent-custody");
      expect(JSON.stringify(span)).not.toContain(CANARY);
      expect(["string", "undefined"]).toContain(typeof statusOf(span).message);
    }
    expect(onDisk(fx.receiptsDir, fx.logFile)).not.toContain(CANARY);
    // and the control
    const clear = createSdkIssuer(loadSdkConfig(buildSdkFixture(mkdtempSync(join(tmpdir(), "canary-sdk-control-"))).configFile));
    expect(bundleText(await clear.record(ev, { status: "error", error: `declined for ${CANARY}` }))).toContain(CANARY);
  });
});
