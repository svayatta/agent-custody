import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs, { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { financialFixture } from "../scripts/financial-fixture.ts";
import { loadConfig } from "../src/config.ts";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.ts";
import { APPROVAL_META_KEY } from "../src/approval.ts";
import { createGateway, createGatewayHost, RECEIPT_META_KEY, RETRY_RECEIPT_META_KEY } from "../src/gateway.ts";
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
      const text = formatReport(verifyBundle(reconciled, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile }));
      expect(text).toMatch(/policy\s+-\s+\(none evaluated: a provider read/);
      expect(text).toMatch(/execution\s+observed\s+provider read, executed/);
      expect(text).not.toMatch(/policy\s+observed\s+allow/);
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

  it.each([
    ["no status", undefined, "pending"],
    ["a confirmed status", "succeeded", "pending"],
    ["a failed status", "failed", "unknown"],
    ["a status that the rule does not name", "reversed", "unknown"],
  ])("holds the reservation when the first provider answer carries %s", async (_name, status, expected) => {
    const fx = await fixture();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const session = host.open(grant(fx));
      fx.api.onAccept = () => { fx.records.values().next().value!.status = status as string; };
      const result = await session.handleCall(call());
      fx.api.onAccept = undefined;
      expect(result.isError).toBeFalsy();
      expect(decode(bundleFor(fx, result)).predicate.operation?.status).toBe(expected);
      check(fx, bundleFor(fx, result));
      // only the reconciliation read releases the amount, also after a first answer that says "failed"
      expect((await session.handleCall(call())).isError).toBe(true);
      expect(fx.api.posts).toBe(1);
    } finally { await host.close(); await fx.close(); }
  });

  it("refuses to reconcile an operation it does not hold, and one whose stored original it did not sign", async () => {
    const fx = await fixture();
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      await expect(host.reconcile(randomUUID())).rejects.toThrow(/operation not found/);
      const params = call();
      const id = params._meta[OPERATION_META_KEY];
      await host.open(grant(fx)).handleCall(params);
      const original = readRecord(fx, id).original as ReceiptBundle;
      patchRecord(fx, id, { original: { ...original, envelope: { ...original.envelope, payload: Buffer.from("{}").toString("base64") } } });
      fx.records.values().next().value!.status = "failed";
      await expect(host.reconcile(id)).rejects.toThrow(/stored original operation signature is invalid/);
      // the provider says "failed", but nothing is released on a record the gateway cannot authenticate
      expect(readRecord(fx, id).status).toBe("pending");
      expect((await host.open(grant(fx)).handleCall(call())).isError).toBe(true);
      expect(fx.api.posts).toBe(1);
    } finally { await host.close(); await fx.close(); }
  });

  it("refuses to close a call of a dead creator that has no authorization and no record of the call", async () => {
    const fx = await fixture();
    const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys/gateway.key")));
    let release!: () => void;
    let held!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const isHeld = new Promise<void>((resolve) => { held = resolve; });
    let first = true;
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
      // a record from before the store kept the unsent call, whose creator looks dead
      patchRecord(fx, id, { ownerStart: `${processStamp(process.pid)!.split(":")[0]}:another start`, unsent: undefined });
      await expect(host.reconcile(id)).rejects.toThrow(/no committed authorization and no record of the call/);
      expect(readRecord(fx, id).reconciliation).toBeUndefined();
      release();
      expect((await pending).isError).toBeFalsy();
      expect(fx.api.posts).toBe(1);
    } finally { release(); await host.close(); await fx.close(); }
  });

  it.each([
    ["the log takes the authorization", /grant has expired before the call was forwarded/],
    ["the revocation list is read before the forward", /grant is outside its validity window before the call was forwarded/],
  ])("withholds a refund whose grant expires while %s, and frees its budget", async (stage, reason) => {
    const fx = await fixture();
    fx.config.revokedGrants = "revoked.json";
    writeFileSync(fx.configFile, JSON.stringify(fx.config));
    writeFileSync(join(fx.dir, "revoked.json"), "[]");
    const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys/gateway.key")));
    let authorized = false;
    let expire = () => {};
    const log: LogSink = { ...inner, async append(leaf) {
      const result = await inner.append(leaf);
      if (!authorized && stage.startsWith("the log")) expire();
      authorized = true;
      return result;
    } };
    const statSync = fs.statSync;
    const restore = () => { vi.useRealTimers(); vi.restoreAllMocks(); syncBuiltinESMExports(); };
    const host = await createGatewayHost(loadConfig(fx.configFile), { log });
    try {
      const session = host.open(grant(fx));
      // The clock moves inside an awaited or blocking step of the call. The test does not wait for real time.
      expire = () => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(Date.parse(session.delegation.expiresAt) + 1000); };
      if (stage.startsWith("the revocation")) {
        vi.spyOn(fs, "statSync").mockImplementation(((path: fs.PathLike, options?: fs.StatSyncOptions) => {
          const stat = statSync(path, options);
          if (authorized && String(path).endsWith("revoked.json")) expire();
          return stat;
        }) as typeof fs.statSync);
        syncBuiltinESMExports();
      }
      const params = call();
      const result = await session.handleCall(params);
      restore();
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.content)).toMatch(reason);
      expect(decode(bundleFor(fx, result)).predicate).toMatchObject({ execution: { status: "withheld" }, operation: { status: "failed" } });
      check(fx, bundleFor(fx, result));
      expect(fx.api.posts).toBe(0);
      await expect(host.reconcile(params._meta[OPERATION_META_KEY])).rejects.toThrow(/never forwarded and needs no provider reconciliation/);
      expect((await session.handleCall(call())).isError).toBeFalsy();
      expect(fx.api.posts).toBe(1);
    } finally { restore(); await host.close(); await fx.close(); }
  });
});

describe("gateway guards around a call and at start", () => {
  const rewrite = (fx: Awaited<ReturnType<typeof fixture>>, edit: (config: any) => void) => { edit(fx.config); writeFileSync(fx.configFile, JSON.stringify(fx.config)); };
  const permitAll = (fx: Awaited<ReturnType<typeof fixture>>) => writeFileSync(join(fx.dir, "policy.cedar"), "permit(principal, action, resource);");
  const text = (result: { content: unknown }) => JSON.stringify(result.content);

  it("refuses to start with a financial operation on an A2A upstream, or with a REST reconciliation read that is not a GET", async () => {
    const agent = createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ name: "payer", url: `http://${req.headers.host}` })); });
    await new Promise<void>((resolve) => agent.listen(0, "127.0.0.1", resolve));
    const a2a = await fixture();
    const post = await fixture();
    try {
      rewrite(a2a, (c) => {
        c.upstreams = [{ name: "provider", rest: c.upstream.rest }, { name: "agent", a2a: { url: `http://127.0.0.1:${(agent.address() as { port: number }).port}` } }];
        delete c.upstream;
        c.operations.tools[0].tool = "a2a.send";
      });
      await expect(createGatewayHost(loadConfig(a2a.configFile))).rejects.toThrow(/operation tool a2a\.send needs an MCP or REST upstream/);
      rewrite(post, (c) => { c.upstream.rest.tools[1].method = "POST"; });
      await expect(createGatewayHost(loadConfig(post.configFile))).rejects.toThrow(/operation stripe\.refund: REST reconciliation must use GET/);
    } finally { agent.closeAllConnections(); agent.close(); await a2a.close(); await post.close(); }
  });

  it("refuses to reconcile on a gateway that has no financial operations", async () => {
    const fx = await fixture();
    rewrite(fx, (c) => { delete c.operations; });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      await expect(host.reconcile(randomUUID())).rejects.toThrow(/gateway has no financial operations configured/);
    } finally { await host.close(); await fx.close(); }
  });

  it("a single-grant gateway does not start under a grant that the trusted keys did not sign", async () => {
    const fx = await fixture();
    rewrite(fx, (c) => { c.trustedPrincipalKeys = ["keys/gateway.pub"]; });
    try {
      await expect(createGateway(loadConfig(fx.configFile))).rejects.toThrow(/delegation grant rejected/);
    } finally { await fx.close(); }
  });

  it("a revocation file that is not a JSON array denies each call of a running session and opens no new session", async () => {
    const fx = await fixture();
    rewrite(fx, (c) => { c.revokedGrants = "revoked.json"; });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const session = host.open(grant(fx));
      writeFileSync(join(fx.dir, "revoked.json"), '{"revoked":[]}');
      const result = await session.handleCall(call());
      expect(result.isError).toBe(true);
      expect(text(result)).toMatch(/cannot be checked against the revocation list \(.*expected a JSON array of grant digests\)/);
      expect(decode(bundleFor(fx, result)).predicate.execution.status).toBe("denied");
      expect(fx.api.posts).toBe(0);
      expect(() => host.open(grant(fx))).toThrow(/expected a JSON array of grant digests/);
    } finally { await host.close(); await fx.close(); }
  });

  it("records an upstream error for a tool that the grant and the policy allow and no upstream offers", async () => {
    const fx = await fixture();
    permitAll(fx);
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const result = await host.open(grant(fx)).handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
      expect(result.isError).toBe(true);
      expect(text(result)).toMatch(/Upstream error: no upstream offers tool \\"customer\.lookup\\"/);
      expect(decode(bundleFor(fx, result)).predicate.execution.status).toBe("error");
      check(fx, bundleFor(fx, result));
    } finally { await host.close(); await fx.close(); }
  });

  it("denies a call whose approval cannot be copied, and does not throw", async () => {
    const fx = await fixture();
    rewrite(fx, (c) => { c.approvals = { trustedKeys: ["keys/principal.pub"], usedDir: "used-approvals", tools: [{ tool: "stripe.refund" }] }; });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const params = call();
      const result = await host.open(grant(fx)).handleCall({ ...params, _meta: { ...params._meta, [APPROVAL_META_KEY]: () => {} } });
      expect(result.isError).toBe(true);
      expect(text(result)).toMatch(/Denied by policy: approval rejected/);
      expect(decode(bundleFor(fx, result)).predicate).toMatchObject({ execution: { status: "denied" }, approval: { status: "denied" } });
      expect(fx.api.posts).toBe(0);
    } finally { await host.close(); await fx.close(); }
  });

  it("observe mode forwards a precommitted call that is not financial when the log refuses the authorization, and prints that", async () => {
    const fx = await fixture();
    rewrite(fx, (c) => { delete c.operations; c.mode = "observe"; c.precommit = ["stripe.refund"]; });
    const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys/gateway.key")));
    const log: LogSink = { ...inner, async append(leaf) {
      if (JSON.parse(Buffer.from(JSON.parse(leaf).payload, "base64").toString()).predicateType.includes("authorization")) throw new Error("no authorization");
      return inner.append(leaf);
    } };
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const host = await createGatewayHost(loadConfig(fx.configFile), { log });
    try {
      const result = await host.open(grant(fx)).handleCall(call());
      // without an operation rule the call carries no idempotency key: this answer shows that the provider got the call
      expect(text(result)).toMatch(/missing idempotency key/);
      const receiptId = String(result._meta?.[RECEIPT_META_KEY]);
      expect(errors.mock.calls.map(String).join("\n")).toMatch(new RegExp(`observe mode\\): the log did not commit the authorization for stripe\\.refund, receipt ${receiptId}; the call was forwarded without it: no authorization`));
      const bundle = bundleFor(fx, result);
      expect(decode(bundle).predicate.authorization).toBeUndefined();
      expect(decode(bundle).predicate.execution.status).toBe("failed");
      check(fx, bundle);
    } finally { errors.mockRestore(); await host.close(); await fx.close(); }
  });

  it("puts a changed policy in force when the change cannot be recorded, and prints that", async () => {
    const fx = await fixture();
    // a directory in the place of the reload record: the append fails
    mkdirSync(join(fx.receiptsDir, "policy-reloads.jsonl"), { recursive: true });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      writeFileSync(join(fx.dir, "policy.cedar"), "forbid(principal, action, resource);");
      const result = await host.open(grant(fx)).handleCall(call());
      expect(result.isError).toBe(true);
      expect(text(result)).toMatch(/Denied by policy/);
      expect(fx.api.posts).toBe(0);
      expect(errors.mock.calls.map(String).join("\n")).toMatch(/cannot record the policy change in .*policy-reloads\.jsonl/);
    } finally { errors.mockRestore(); await host.close(); await fx.close(); }
  });
});
