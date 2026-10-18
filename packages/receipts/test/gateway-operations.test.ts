import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { financialFixture } from "../scripts/financial-fixture.ts";
import { loadConfig } from "../src/config.ts";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.ts";
import { createGatewayHost, RECEIPT_META_KEY, RETRY_RECEIPT_META_KEY } from "../src/gateway.ts";
import { spanFor } from "../src/otel.ts";
import { hecEvent } from "../src/splunk.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import { OPERATION_META_KEY, OperationStore, processStamp } from "../src/operations.ts";
import type { ReceiptBundle, ReceiptPredicate } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { decode } from "./helpers.ts";

const fixture = () => financialFixture(mkdtempSync(join(tmpdir(), "financial-gateway-")));
const grant = (fx: Awaited<ReturnType<typeof fixture>>) => JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8"));
const call = (id = randomUUID(), amount = 60, extra = {}) => ({ name: "stripe.refund", arguments: { amount, currency: "GBP", ...extra }, _meta: { [OPERATION_META_KEY]: id } });
const bundleFor = (fx: Awaited<ReturnType<typeof fixture>>, result: { _meta?: Record<string, unknown> }) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(result._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
const check = (fx: Awaited<ReturnType<typeof fixture>>, bundle: ReceiptBundle) => {
  const verified = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
  expect(verified.ok, formatReport(verified)).toBe(true);
};
const storeFor = (fx: Awaited<ReturnType<typeof fixture>>) => new OperationStore(loadConfig(fx.configFile).operations!.database);
const readRecord = (fx: Awaited<ReturnType<typeof fixture>>, id: string) => { const store = storeFor(fx); try { return store.get(id)!; } finally { store.close(); } };
/** Rewrite fields of a stored record, as a restart or a PID reuse would leave them. The store has no API for this. */
const patchRecord = (fx: Awaited<ReturnType<typeof fixture>>, id: string, patch: Record<string, unknown>) => {
  const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as { DatabaseSync: new (path: string) => { prepare(sql: string): { get(...a: unknown[]): unknown; run(...a: unknown[]): unknown }; close(): void } };
  const db = new DatabaseSync(loadConfig(fx.configFile).operations!.database);
  try {
    const row = db.prepare("SELECT json FROM operations WHERE id = ?").get(id) as { json: string };
    db.prepare("UPDATE operations SET json = ? WHERE id = ?").run(JSON.stringify({ ...JSON.parse(row.json), ...patch }), id);
  } finally { db.close(); }
};
/** A real gateway process that dies by SIGKILL: when the log takes the authorization ("authorize"), or when the provider has the call ("forward"). */
async function killedGateway(fx: Awaited<ReturnType<typeof fixture>>, params: ReturnType<typeof call>, mode: "authorize" | "forward"): Promise<void> {
  const url = (file: string) => JSON.stringify(pathToFileURL(resolve(import.meta.dirname, file)).href);
  const log = mode === "authorize" ? "{ ...inner, async append() { process.kill(process.pid, 'SIGKILL'); await new Promise(() => {}); } }" : "inner";
  const source = `import {createGateway} from ${url("../src/gateway.ts")}; import {loadConfig} from ${url("../src/config.ts")}; import {fileLog} from ${url("../src/log-sink.ts")}; import {loadPrivateKey} from ${url("../src/crypto.ts")};
    const inner = fileLog(${JSON.stringify(fx.logFile)}, loadPrivateKey(${JSON.stringify(join(fx.dir, "keys/gateway.key"))}));
    const g = await createGateway(loadConfig(${JSON.stringify(fx.configFile)}), { log: ${log} }); await g.handleCall(${JSON.stringify(params)}); await g.close();`;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", source], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  if (mode === "forward") {
    fx.api.drop = true;
    fx.api.onAccept = () => child.kill("SIGKILL");
  }
  const exit = await new Promise<NodeJS.Signals | null>((resolve, reject) => { child.once("error", reject); child.once("exit", (_code, signal) => resolve(signal)); });
  fx.api.onAccept = undefined;
  fx.api.drop = false;
  expect(exit, stderr).toBe("SIGKILL");
}

describe("financial operations through the gateway", () => {
  it("a dropped response is unknown, survives restart, never forwards a retry, and reconciles from the provider record", async () => {
    const fx = await fixture();
    let host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      fx.api.drop = true;
      const params = call();
      const first = await host.open(grant(fx)).handleCall(params);
      expect(first.isError).toBe(true);
      expect(decode(bundleFor(fx, first)).predicate.operation?.status).toBe("unknown");
      check(fx, bundleFor(fx, first));
      const key = [...fx.records.keys()][0]!;
      expect(key).toMatch(/^[0-9a-f]{64}$/);
      await host.close();
      host = await createGatewayHost(loadConfig(fx.configFile));
      const retry = await host.open(grant(fx)).handleCall(params);
      expect(retry._meta?.[RECEIPT_META_KEY]).toBe(first._meta?.[RECEIPT_META_KEY]);
      expect(fx.api.posts).toBe(1);
      expect(fx.records.size).toBe(1);
      const denied = await host.open(grant(fx)).handleCall(call());
      expect(denied.isError).toBe(true);
      expect(fx.api.posts).toBe(1);
      await expect(host.reconcile(params._meta[OPERATION_META_KEY])).rejects.toThrow(/pending or unknown/);
      fx.records.get(key)!.status = "succeeded";
      const reconciled = await host.reconcile(params._meta[OPERATION_META_KEY]);
      expect(decode(reconciled).predicate.operation?.status).toBe("confirmed");
      check(fx, reconciled);
      expect(await host.reconcile(params._meta[OPERATION_META_KEY])).toEqual(reconciled);
      const after = await host.open(grant(fx)).handleCall(params);
      expect(after._meta?.[RECEIPT_META_KEY]).toBe(decode(reconciled).predicate.receiptId);
      expect(fx.api.posts).toBe(1);
    } finally { await host.close(); await fx.close(); }
  });

  it("SIGKILL after provider acceptance leaves an authorization that can be reconciled after restart", async () => {
    const fx = await fixture();
    const params = call();
    const gatewayUrl = pathToFileURL(resolve(import.meta.dirname, "../src/gateway.ts")).href;
    const configUrl = pathToFileURL(resolve(import.meta.dirname, "../src/config.ts")).href;
    const source = `import {createGateway} from ${JSON.stringify(gatewayUrl)}; import {loadConfig} from ${JSON.stringify(configUrl)}; const g=await createGateway(loadConfig(${JSON.stringify(fx.configFile)})); await g.handleCall(${JSON.stringify(params)}); await g.close();`;
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", source], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    fx.api.drop = true;
    fx.api.onAccept = () => child.kill("SIGKILL");
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    let host: Awaited<ReturnType<typeof createGatewayHost>> | undefined;
    try {
      const exit = await exited;
      expect(exit.signal, stderr).toBe("SIGKILL");
      const store = storeFor(fx);
      const record = store.get(params._meta[OPERATION_META_KEY])!;
      store.close();
      expect(record.status).toBe("submitted");
      expect(record.original).toBeDefined();
      host = await createGatewayHost(loadConfig(fx.configFile));
      const retry = await host.open(grant(fx)).handleCall(params);
      expect((retry._meta?.[OPERATION_META_KEY] as { status: string }).status).toBe("unknown");
      expect(retry._meta?.["agent-custody/authorization"]).toBeDefined();
      expect(fx.api.posts).toBe(1);
      fx.records.get(record.idempotencyKey)!.status = "succeeded";
      const closed = await host.reconcile(record.id);
      check(fx, closed);
      expect(decode(closed).predicate.reconciliation?.original).toEqual(record.original);
    } finally { child.kill("SIGKILL"); await host?.close(); await fx.close(); }
  });

  it("concurrent sessions share reservations and a confirmed outcome continues to count against the daily budget", async () => {
    const fx = await fixture();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const sessions = [host.open(grant(fx)), host.open(grant(fx))];
      const results = await Promise.all(sessions.map((session) => session.handleCall(call())));
      expect(results.filter((r) => !r.isError)).toHaveLength(1);
      expect(fx.api.posts).toBe(1);
      for (const result of results) check(fx, bundleFor(fx, result));
      const accepted = results.find((r) => !r.isError)!;
      const id = (accepted._meta?.[OPERATION_META_KEY] as { id: string }).id;
      fx.records.values().next().value!.status = "succeeded";
      check(fx, await host.reconcile(id));
      expect((await sessions[0]!.handleCall(call())).isError).toBe(true);
      expect(fx.api.posts).toBe(1);
    } finally { await host.close(); await fx.close(); }
  });

  it("a failed provider record releases budget only after its reconciliation receipt reaches the log", async () => {
    const fx = await fixture();
    fx.config.capture = { "*": { args: { mode: "digest" }, result: { mode: "digest" } } };
    writeFileSync(fx.configFile, JSON.stringify(fx.config));
    const key = loadPrivateKey(join(fx.dir, "keys/gateway.key"));
    const inner = fileLog(fx.logFile, key);
    let refusedEnvelope: unknown;
    const rejectReconciliation: LogSink = { ...inner, async append(leaf) {
      const p = JSON.parse(Buffer.from(JSON.parse(leaf).payload, "base64").toString()).predicate;
      if (p.reconciliation) { refusedEnvelope = JSON.parse(leaf); throw new Error("log unavailable"); }
      return inner.append(leaf);
    } };
    let host = await createGatewayHost(loadConfig(fx.configFile), { log: rejectReconciliation });
    try {
      const params = call();
      const initial = await host.open(grant(fx)).handleCall(params);
      fx.records.values().next().value!.status = "failed";
      await expect(host.reconcile(params._meta[OPERATION_META_KEY])).rejects.toThrow(/log unavailable/);
      const retry = await host.open(grant(fx)).handleCall(params);
      expect(retry._meta?.[RECEIPT_META_KEY]).toBe(initial._meta?.[RECEIPT_META_KEY]);
      expect((await host.open(grant(fx)).handleCall(call())).isError).toBe(true);
      expect(fx.api.posts).toBe(1);
      await host.close();
      host = await createGatewayHost(loadConfig(fx.configFile));
      const closed = await host.reconcile(params._meta[OPERATION_META_KEY]);
      expect(closed.envelope).toEqual(refusedEnvelope);
      check(fx, closed);
      expect(decode(closed).predicate.operation?.status).toBe("failed");
      expect((await host.open(grant(fx)).handleCall(call())).isError).toBeFalsy();
      expect(fx.api.posts).toBe(2);
    } finally { await host.close(); await fx.close(); }
  });

  it("cannot reconcile underneath a live submitted forward, or close an unrelated provider record", async () => {
    const fx = await fixture();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const params = call();
      let interleaved: Promise<unknown> | undefined;
      fx.api.onAccept = () => {
        interleaved = host.reconcile(params._meta[OPERATION_META_KEY]).catch((e: Error) => e.message);
      };
      await host.open(grant(fx)).handleCall(params);
      expect(await interleaved).toMatch(/live process/);
      fx.records.values().next().value!.status = "failed";
      fx.records.values().next().value!.idempotencyKey = "f".repeat(64);
      await expect(host.reconcile(params._meta[OPERATION_META_KEY])).rejects.toThrow(/does not bind/);
      expect((await host.open(grant(fx)).handleCall(call())).isError).toBe(true);
      expect(fx.api.posts).toBe(1);
    } finally { await host.close(); await fx.close(); }
  });

  it("observe mode precommits a recorded policy deny and its financial receipts still verify", async () => {
    const fx = await fixture();
    fx.config.mode = "observe";
    writeFileSync(fx.configFile, JSON.stringify(fx.config));
    writeFileSync(join(fx.dir, "policy.cedar"), 'forbid(principal, action, resource);');
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const params = call();
      const result = await host.open(grant(fx)).handleCall(params);
      check(fx, bundleFor(fx, result));
      expect(fx.api.posts).toBe(1);
      fx.records.values().next().value!.status = "succeeded";
      check(fx, await host.reconcile(params._meta[OPERATION_META_KEY]));
    } finally { await host.close(); await fx.close(); }
  });

  it("binds the reconciliation upstream as well as the payment destination", async () => {
    const fx = await fixture();
    const rest = fx.config.upstream.rest;
    fx.config.upstreams = [
      { name: "writer", rest: { ...rest, tools: [rest.tools[0]] } },
      { name: "reader", rest: { ...rest, tools: [rest.tools[1]] } },
    ];
    delete fx.config.upstream;
    writeFileSync(fx.configFile, JSON.stringify(fx.config));
    let host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const params = call();
      await host.open(grant(fx)).handleCall(params);
      await host.close();
      fx.config.upstreams[1].rest.baseUrl += "/another-provider";
      writeFileSync(fx.configFile, JSON.stringify(fx.config));
      host = await createGatewayHost(loadConfig(fx.configFile));
      await expect(host.reconcile(params._meta[OPERATION_META_KEY])).rejects.toThrow(/provider or gateway identity changed/);
    } finally { await host.close(); await fx.close(); }
  });

  it("the plain Node CLI reconciles the existing operation and prints a verifiable receipt path", async () => {
    const fx = await fixture();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const params = call();
      await host.open(grant(fx)).handleCall(params);
      await host.close();
      fx.records.values().next().value!.status = "succeeded";
      const child = spawn(process.execPath, [resolve(import.meta.dirname, "../src/cli.ts"), "reconcile", "--config", fx.configFile, "--operation", params._meta[OPERATION_META_KEY]], { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      const exit = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("exit", resolve); });
      expect(exit, stderr).toBe(0);
      const result = JSON.parse(stdout);
      expect(result).toMatchObject({ operation: params._meta[OPERATION_META_KEY], status: "confirmed" });
      check(fx, JSON.parse(readFileSync(result.receipt, "utf8")));
    } finally { await fx.close(); }
  });

  it("rejects operation rebinding and malformed money, and never trusts HTTP errors as financial failure", async () => {
    const fx = await fixture();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const session = host.open(grant(fx));
      const params = call();
      fx.api.responseStatus = 500;
      const result = await session.handleCall(params);
      expect(decode(bundleFor(fx, result)).predicate.operation?.status).toBe("unknown");
      for (const invalid of [call(params._meta[OPERATION_META_KEY], 59), call(randomUUID(), 0), call(randomUUID(), -1), call(randomUUID(), 1.5), call(randomUUID(), 1, { currency: "USD" }), { ...call(), _meta: {} }]) {
        expect((await session.handleCall(invalid)).isError).toBe(true);
      }
      expect(fx.api.posts).toBe(1);
    } finally { await host.close(); await fx.close(); }
  });

  it("precommit failure withholds financial tools even in observe mode and releases the unused reservation", async () => {
    const fx = await fixture();
    fx.config.mode = "observe";
    writeFileSync(fx.configFile, JSON.stringify(fx.config));
    const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys/gateway.key")));
    const log: LogSink = { ...inner, async append(leaf) {
      if (JSON.parse(Buffer.from(JSON.parse(leaf).payload, "base64").toString()).predicateType.includes("authorization")) throw new Error("no authorization");
      return inner.append(leaf);
    } };
    const host = await createGatewayHost(loadConfig(fx.configFile), { log });
    try {
      for (let i = 0; i < 2; i++) {
        const result = await host.open(grant(fx)).handleCall(call());
        expect(result.isError).toBe(true);
        expect(decode(bundleFor(fx, result)).predicate.execution.status).toBe("withheld");
        check(fx, bundleFor(fx, result));
      }
      expect(fx.api.posts).toBe(0);
    } finally { await host.close(); await fx.close(); }
  });

  it("exports a reconciliation as a provider read, never as a second allowed call of the payment tool", async () => {
    const fx = await fixture();
    const seen: { p: ReceiptPredicate; b: ReceiptBundle }[] = [];
    const host = await createGatewayHost(loadConfig(fx.configFile), { exporter: { where: "test", async exported(p, b) { seen.push({ p, b }); } } });
    try {
      const params = call();
      await host.open(grant(fx)).handleCall(params);
      fx.records.values().next().value!.status = "failed";
      await host.reconcile(params._meta[OPERATION_META_KEY]);
      expect(seen).toHaveLength(2);
      const [call1, call2] = seen.map(({ p, b }) => ({ span: (spanFor(p, b, "test") as any).resourceSpans[0].scopeSpans[0].spans[0], event: (hecEvent(p, b, { url: "https://splunk.example", tokenEnv: "X" }) as any).event }));
      const attr = (span: any, key: string) => span.attributes.find((a: any) => a.key === key)?.value;
      expect(attr(call1!.span, "agent_custody.execution.status")).toEqual({ stringValue: "executed" });
      expect(attr(call1!.span, "agent_custody.policy.decision")).toEqual({ stringValue: "allow" });
      expect(attr(call2!.span, "agent_custody.reconciliation")).toEqual({ boolValue: true });
      expect(attr(call2!.span, "agent_custody.execution.status")).toEqual({ stringValue: "reconciled" });
      expect(attr(call2!.span, "agent_custody.operation.status")).toEqual({ stringValue: "failed" });
      expect(attr(call2!.span, "agent_custody.policy.decision")).toBeUndefined();
      expect(attr(call2!.span, "agent_custody.policy.digest")).toBeUndefined();
      expect(call2!.span.name).toBe("stripe.refund reconciliation");
      expect(call2!.span.status.code).toBe(2);
      expect(call2!.event).toMatchObject({ status: "reconciled", reconciliation: true, operation_status: "failed", policy_decision: null, policy_digest: null, policy_reasons: [], reconciliation_lookup_tool: "refund.lookup" });
      expect(call1!.event).toMatchObject({ status: "executed", reconciliation: false, policy_decision: "allow" });
    } finally { await host.close(); await fx.close(); }
  });

  it("gives an allowed retry a receipt of its own, answers it from the stored outcome, and never forwards it", async () => {
    const fx = await fixture();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const session = host.open(grant(fx));
      const params = call();
      const first = await session.handleCall(params);
      const leaves = () => readFileSync(fx.logFile, "utf8").trim().split("\n").length;
      const before = leaves();
      const retry = await session.handleCall(params);
      expect(leaves()).toBe(before + 1);
      expect(fx.api.posts).toBe(1);
      expect(retry.content).toEqual(first.content);
      expect(retry._meta?.[RECEIPT_META_KEY]).toBe(first._meta?.[RECEIPT_META_KEY]);
      const receipt = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(retry._meta?.[RETRY_RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
      const p = decode(receipt).predicate;
      expect(p.execution).toMatchObject({ status: "withheld" });
      expect(p.operation?.originalReceiptId).toBe(first._meta?.[RECEIPT_META_KEY]);
      expect(p.receiptId).not.toBe(first._meta?.[RECEIPT_META_KEY]);
      check(fx, receipt);
    } finally { await host.close(); await fx.close(); }
  });

  it("closes a call that provably never went out with a receipt, and frees its budget", async () => {
    const fx = await fixture();
    const params = call();
    const id = params._meta[OPERATION_META_KEY];
    await killedGateway(fx, params, "authorize");
    const record = readRecord(fx, id);
    expect(record).toMatchObject({ status: "submitted" });
    expect(record.original).toBeUndefined();
    expect(record.unsent).toBeDefined();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      // the amount stays reserved until recovery closes the call
      expect((await host.open(grant(fx)).handleCall(call())).isError).toBe(true);
      const closed = await host.reconcile(id);
      check(fx, closed);
      const p = decode(closed).predicate;
      expect(p).toMatchObject({ receiptId: record.originalReceiptId, execution: { status: "withheld" }, operation: { status: "failed" } });
      expect(p.reconciliation).toBeUndefined();
      expect(await host.reconcile(id)).toEqual(closed);
      // a retry is told that the call was not sent, not to reconcile again
      const retry = await host.open(grant(fx)).handleCall(params);
      expect(JSON.stringify(retry.content)).toMatch(/not sent.*new operation id/);
      expect(readRecord(fx, id)).toMatchObject({ status: "failed" });
      expect(readRecord(fx, id).unsent).toBeUndefined();
      expect((await host.open(grant(fx)).handleCall(call())).isError).toBeFalsy();
      expect(fx.api.posts).toBe(1);
    } finally { await host.close(); await fx.close(); }
  });

  it("never forwards a call that recovery closed as not sent, even when the liveness answer was wrong", async () => {
    const fx = await fixture();
    const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys/gateway.key")));
    let release!: () => void;
    let held!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const isHeld = new Promise<void>((resolve) => { held = resolve; });
    let first = true;
    // the first append is the authorization: a slow log holds it while the operator runs reconcile
    const log: LogSink = { ...inner, async append(leaf) {
      if (first) { first = false; held(); await gate; }
      return inner.append(leaf);
    } };
    const host = await createGatewayHost(loadConfig(fx.configFile), { log });
    try {
      const params = call();
      const id = params._meta[OPERATION_META_KEY];
      const pending = host.open(grant(fx)).handleCall(params);
      await isHeld;
      // a wrong answer: the live creator (this process) looks like another process that took its PID
      patchRecord(fx, id, { ownerStart: `${processStamp(process.pid)!.split(":")[0]}:another start` });
      const closed = await host.reconcile(id);
      expect(decode(closed).predicate).toMatchObject({ execution: { status: "withheld" }, operation: { status: "failed" } });
      release();
      const result = await pending;
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.content)).toMatch(/closed/);
      expect(fx.api.posts).toBe(0);
      expect((await host.open(grant(fx)).handleCall(call())).isError).toBeFalsy();
      expect(fx.api.posts).toBe(1);
    } finally { release(); await host.close(); await fx.close(); }
  });

  it("does not take a later process with the creator's PID for the creator", async () => {
    const fx = await fixture();
    const params = call();
    const id = params._meta[OPERATION_META_KEY];
    await killedGateway(fx, params, "forward");
    const record = readRecord(fx, id);
    expect(record.ownerStart).toBeDefined();
    // This test process stands for the new PID 1 of a restarted container: alive, the creator's PID, another start time.
    patchRecord(fx, id, { ownerPid: process.pid });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      fx.records.get(record.idempotencyKey)!.status = "succeeded";
      check(fx, await host.reconcile(id));
    } finally { await host.close(); await fx.close(); }
  });
});
