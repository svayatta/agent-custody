// A log outage after an ordinary call must not lose the receipt or tell the agent that the call failed: the signed
// receipt waits in the outbox and is appended when the log is back.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { checkConfig } from "../src/check.ts";
import { loadConfig } from "../src/config.ts";
import { dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, type Envelope } from "../src/crypto.ts";
import { createGatewayHost, LOG_PENDING_META_KEY, RECEIPT_META_KEY } from "../src/gateway.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import { pathKey } from "../src/capture.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { financialFixture } from "../scripts/financial-fixture.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { OPERATION_META_KEY } from "../src/operations.ts";

const REFUND = { name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } };
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const decodeEnvelope = (env: Envelope) => JSON.parse(Buffer.from(env.payload, "base64").toString()) as ReceiptStatement;

/** A gateway whose log can be taken down, that counts the leaves the log took. */
async function outage(prefix: string, edit?: (config: Record<string, any>) => void) {
  const dir = mkdtempSync(join(tmpdir(), `agent-custody-outbox-${prefix}-`));
  const f = buildFixture(dir);
  if (edit) {
    const raw = JSON.parse(readFileSync(f.configFile, "utf8"));
    edit(raw);
    writeFileSync(f.configFile, JSON.stringify(raw));
  }
  const inner = fileLog(f.logFile, loadPrivateKey(join(dir, "keys", "gateway.key")));
  const state = { down: true, delayMs: 0, appended: [] as string[] };
  const log: LogSink = {
    kind: inner.kind,
    where: inner.where,
    async append(leaf) {
      if (state.down) throw new Error("log unreachable");
      if (state.delayMs) await sleep(state.delayMs);
      const entry = await inner.append(leaf);
      state.appended.push(decodeEnvelope(JSON.parse(leaf) as Envelope).predicate.receiptId);
      return entry;
    },
  };
  const cfg = loadConfig(f.configFile);
  const open = async (more: { autoFlush?: boolean } = {}) => createGatewayHost(cfg, { log, ...more });
  const host = await open();
  const gw = host.open(JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope);
  const outbox = join(f.receiptsDir, "outbox");
  const pendingCall = async () => String((await gw.handleCall(REFUND))._meta?.[RECEIPT_META_KEY]);
  return { f, cfg, state, host, gw, open, outbox, pendingCall, keys: { issuerKeys: [loadPublicKey(f.gatewayPub)], principalKeys: [loadPublicKey(f.principalPub)], logFile: f.logFile } };
}

describe("the receipt outbox", () => {
  it("keeps the receipt of a call made while the log is down, returns the real result, and appends it later", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agent-custody-outbox-"));
    const f = buildFixture(dir);
    const inner = fileLog(f.logFile, loadPrivateKey(join(dir, "keys", "gateway.key")));
    let down = false;
    const log: LogSink = { kind: inner.kind, where: inner.where, append: (leaf) => down ? Promise.reject(new Error("log unreachable")) : inner.append(leaf) };
    const cfg = loadConfig(f.configFile);
    const host = await createGatewayHost(cfg, { log });
    const gw = host.open(JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope);
    try {
      down = true;
      const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
      expect(res.isError).toBeFalsy();
      expect(res._meta?.[LOG_PENDING_META_KEY]).toBe(true);
      const id = String(res._meta?.[RECEIPT_META_KEY]);
      expect(existsSync(join(f.receiptsDir, `${id}.json`))).toBe(false);
      expect(existsSync(join(f.receiptsDir, "outbox", `${id}.json`))).toBe(true);
      expect(host.pendingReceipts()).toBe(1);
      expect(await host.flushOutbox()).toEqual({ sent: 0, pending: 1, setAside: 0, foreign: 0, error: "log unreachable" });
      // the same signed receipt under another name is not appended under that name
      writeFileSync(join(f.receiptsDir, "outbox", "forged.json"), readFileSync(join(f.receiptsDir, "outbox", `${id}.json`)));

      down = false;
      expect(await host.flushOutbox()).toEqual({ sent: 1, pending: 0, setAside: 1, foreign: 0 });
      expect(readdirSync(join(f.receiptsDir, "outbox"))).toEqual(["forged.json.bad"]);
      expect(existsSync(join(f.receiptsDir, "forged.json"))).toBe(false);
      const bundle = JSON.parse(readFileSync(join(f.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
      const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement;
      expect(st.predicate.execution.status).toBe("executed");
      const r = verifyBundle(bundle, { issuerKeys: [loadPublicKey(f.gatewayPub)], principalKeys: [loadPublicKey(f.principalPub)], logFile: f.logFile });
      expect(r.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual([]);
    } finally {
      await host.close();
    }
  });

  it("a precommit tool is still withheld while the log is down, and its receipt waits in the outbox", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agent-custody-outbox-pre-"));
    const f = buildFixture(dir);
    const raw = JSON.parse(readFileSync(f.configFile, "utf8"));
    raw.precommit = ["stripe.refund"];
    writeFileSync(f.configFile, JSON.stringify(raw));
    const log: LogSink = { kind: "file", where: f.logFile, append: () => Promise.reject(new Error("log unreachable")) };
    const cfg = loadConfig(f.configFile);
    const host = await createGatewayHost(cfg, { log });
    const gw = host.open(JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope);
    try {
      const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
      expect(res.isError).toBe(true);
      expect((res.content[0] as { text: string }).text).toMatch(/^Not executed: the log did not commit the authorization/);
      expect(res._meta?.[LOG_PENDING_META_KEY]).toBe(true);
      expect(host.pendingReceipts()).toBe(1);
    } finally {
      await host.close();
    }
  });

  it("requirePrecommit refuses a remote log with an empty precommit", () => {
    const f = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-outbox-strict-")));
    const raw = JSON.parse(readFileSync(f.configFile, "utf8"));
    delete raw.logFile;
    raw.log = { url: "http://127.0.0.1:9/" };
    raw.requirePrecommit = true;
    writeFileSync(f.configFile, JSON.stringify(raw));
    expect(() => loadConfig(f.configFile)).toThrow(/requirePrecommit is set and precommit is empty/);
    raw.precommit = ["*"];
    raw.log.keys = [f.gatewayPub];
    writeFileSync(f.configFile, JSON.stringify(raw));
    expect(loadConfig(f.configFile).requirePrecommit).toBe(true);
  });
});

describe("the outbox flush", () => {
  it("appends in the order of the calls, not in the order of the random receipt ids", async () => {
    const o = await outage("order");
    try {
      const ids: string[] = [];
      for (let i = 0; i < 6; i++) {
        ids.push(await o.pendingCall());
        await sleep(5);
      }
      o.state.down = false;
      expect(await o.host.flushOutbox()).toMatchObject({ sent: 6, pending: 0 });
      expect(o.state.appended).toEqual(ids);
    } finally {
      await o.host.close();
    }
  });

  it("does not store an undefined original for a financial operation whose receipt the log refuses, and keeps no outbox entry for it", async () => {
    const fx = await financialFixture(mkdtempSync(join(tmpdir(), "agent-custody-outbox-fin-")));
    const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys", "gateway.key")));
    // the authorization is committed, the receipt is not
    const log: LogSink = { ...inner, async append(leaf) {
      if (!decodeEnvelope(JSON.parse(leaf) as Envelope).predicateType.includes("authorization")) throw new Error("receipt refused");
      return inner.append(leaf);
    } };
    const host = await createGatewayHost(loadConfig(fx.configFile), { log });
    try {
      const params = { name: "stripe.refund", arguments: { amount: 60, currency: "GBP" }, _meta: { [OPERATION_META_KEY]: "11111111-1111-4111-8111-111111111111" } };
      await expect(host.open(JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope).handleCall(params)).rejects.toThrow(/receipt refused/);
      expect(host.pendingReceipts()).toBe(0);
      expect(existsSync(join(fx.receiptsDir, "outbox"))).toBe(false);
    } finally {
      await host.close();
      await fx.close();
    }
  });

  it("does not append an entry that another key signed, and does not call it forged", async () => {
    const o = await outage("foreign");
    try {
      const id = await o.pendingCall();
      const own = JSON.parse(readFileSync(join(o.outbox, `${id}.json`), "utf8")) as { envelope: Envelope };
      const statement = decodeEnvelope(own.envelope);
      writeFileSync(join(o.outbox, `${id}.json`), JSON.stringify({ envelope: dsseSign(RECEIPT_TYPE, statement, generateKeyPair()) }));
      o.state.down = false;
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        expect(await o.host.flushOutbox()).toEqual({ sent: 0, pending: 1, setAside: 0, foreign: 1 });
        expect(error.mock.calls.flat().join("\n")).toMatch(/signed by a key other than/);
        expect(error.mock.calls.flat().join("\n")).not.toMatch(/forged/);
      } finally {
        error.mockRestore();
      }
      expect(readdirSync(o.outbox)).toEqual([`${id}.json`]);
      expect(o.state.appended).toEqual([]);
    } finally {
      await o.host.close();
    }
  });

  it("sets aside an entry that carries this key's id but a signature that does not verify", async () => {
    const o = await outage("tampered");
    try {
      const id = await o.pendingCall();
      const file = join(o.outbox, `${id}.json`);
      const entry = JSON.parse(readFileSync(file, "utf8")) as { envelope: Envelope };
      entry.envelope.payload = Buffer.from(JSON.stringify({ ...decodeEnvelope(entry.envelope), extra: 1 })).toString("base64");
      writeFileSync(file, JSON.stringify(entry));
      o.state.down = false;
      expect(await o.host.flushOutbox()).toEqual({ sent: 0, pending: 0, setAside: 1, foreign: 0 });
      expect(readdirSync(o.outbox)).toEqual([`${id}.json.bad`]);
      expect(o.state.appended).toEqual([]);
    } finally {
      await o.host.close();
    }
  });

  it("removes an entry whose bundle exists without appending it again", async () => {
    const o = await outage("bundle");
    try {
      const id = await o.pendingCall();
      writeFileSync(join(o.f.receiptsDir, `${id}.json`), "{}");
      o.state.down = false;
      expect(await o.host.flushOutbox()).toEqual({ sent: 1, pending: 0, setAside: 0, foreign: 0 });
      expect(o.state.appended).toEqual([]);
      expect(readdirSync(o.outbox)).toEqual([]);
    } finally {
      await o.host.close();
    }
  });

  it("keeps the salts of a receipt that waits in the outbox, so a flushed receipt can still be disclosed", async () => {
    const o = await outage("salts", (c) => { c.capture = { "*": { args: { mode: "digest", clear: ["amount"] } } }; });
    try {
      const id = await o.pendingCall();
      o.state.down = false;
      expect(await o.host.flushOutbox()).toMatchObject({ sent: 1, pending: 0 });
      const bundle = JSON.parse(readFileSync(join(o.f.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
      const { salts } = JSON.parse(readFileSync(join(o.f.receiptsDir, "salts", `${id}.json`), "utf8")) as { salts: Record<string, string> };
      const at = pathKey(["request", "args", "$rest"]);
      expect(salts[at]).toBeTruthy();
      const disclose = (value: unknown) => ({ receiptId: id, request: { args: { $rest: { $custody: "disclosed", salt: salts[at], value } } } });
      expect(verifyBundle(bundle, { ...o.keys, disclosed: disclose({ customer_id: "cust_123" }) }).ok).toBe(true);
      expect(verifyBundle(bundle, { ...o.keys, disclosed: disclose({ customer_id: "cust_999" }) }).ok).toBe(false);
    } finally {
      await o.host.close();
    }
  });

  it("does not append the leaf again after a failure that follows the append, and says so on stderr", async () => {
    const o = await outage("post-append");
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const id = await o.pendingCall();
      o.state.down = false;
      // a directory at the temporary name makes the bundle write fail after the log took the leaf
      mkdirSync(join(o.f.receiptsDir, `${id}.json.tmp`));
      const first = await o.host.flushOutbox();
      expect(first).toMatchObject({ sent: 0, pending: 1 });
      expect(first.error).toMatch(/EISDIR|directory/);
      expect(error.mock.calls.flat().join("\n")).toMatch(/EISDIR|directory/);
      expect(await o.host.flushOutbox()).toMatchObject({ sent: 0, pending: 1 });
      expect(o.state.appended).toEqual([id]);
      // a restarted gateway reads the recorded answer from the entry
      await o.host.close();
      const again = await o.open();
      rmSync(join(o.f.receiptsDir, `${id}.json.tmp`), { recursive: true });
      expect(await again.flushOutbox()).toEqual({ sent: 1, pending: 0, setAside: 0, foreign: 0 });
      await again.close();
      expect(o.state.appended).toEqual([id]);
      const r = verifyBundle(JSON.parse(readFileSync(join(o.f.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle, o.keys);
      expect(r.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual([]);
    } finally {
      error.mockRestore();
      await o.host.close();
    }
  });

  it("two gateways on one receipts directory append a receipt once", async () => {
    const o = await outage("two");
    const other = await o.open();
    try {
      const ids = [await o.pendingCall(), await o.pendingCall()];
      o.state.down = false;
      o.state.delayMs = 30;
      const results = await Promise.all([o.host.flushOutbox(), other.flushOutbox()]);
      expect(results.reduce((n, r) => n + r.sent, 0)).toBe(2);
      expect([...o.state.appended].sort()).toEqual([...ids].sort());
      expect(readdirSync(o.outbox)).toEqual([]);
    } finally {
      await other.close();
      await o.host.close();
    }
  });

  it("does nothing while another process holds the lock, and breaks a lock whose owner is gone", async () => {
    const o = await outage("lock");
    try {
      const id = await o.pendingCall();
      o.state.down = false;
      const lock = join(o.outbox, ".lock");
      writeFileSync(lock, JSON.stringify({ token: "x", pid: process.pid, host: hostname() }));
      expect(await o.host.flushOutbox()).toEqual({ sent: 0, pending: 1, setAside: 0, foreign: 0 });
      expect(o.state.appended).toEqual([]);
      const gone = spawnSync(process.execPath, ["-e", "0"]).pid!;
      writeFileSync(lock, JSON.stringify({ token: "x", pid: gone, host: hostname() }));
      expect(await o.host.flushOutbox()).toMatchObject({ sent: 1, pending: 0 });
      expect(o.state.appended).toEqual([id]);
      expect(existsSync(lock)).toBe(false);
    } finally {
      await o.host.close();
    }
  });

  it("flushes at start only when the host serves, and close waits for the flush that runs", async () => {
    const quiet = await outage("quiet");
    const id = await quiet.pendingCall();
    quiet.state.down = false;
    await quiet.host.close();
    const idle = await quiet.open();
    await idle.close();
    expect(existsSync(join(quiet.outbox, `${id}.json`))).toBe(true);
    expect(quiet.state.appended).toEqual([]);
    quiet.state.delayMs = 50;
    const serving = await quiet.open({ autoFlush: true });
    await serving.close();
    expect(quiet.state.appended).toEqual([id]);
    expect(existsSync(join(quiet.f.receiptsDir, `${id}.json`))).toBe(true);
    expect(readdirSync(quiet.outbox)).toEqual([]);
  });

  it("check --connect with a scratch key leaves the outbox and the log as they are", async () => {
    const o = await outage("check");
    const id = await o.pendingCall();
    await o.host.close();
    o.state.down = false;
    rmSync(join(o.f.dir, "keys", "gateway.key"));
    const before = existsSync(o.f.logFile) ? readFileSync(o.f.logFile, "utf8") : "";
    const r = await checkConfig(o.f.configFile, { connect: true });
    expect(r.find((x) => x.check === "upstreams")?.level).toBe("ok");
    expect(readdirSync(o.outbox)).toEqual([`${id}.json`]);
    expect(existsSync(o.f.logFile) ? readFileSync(o.f.logFile, "utf8") : "").toBe(before);
  });
});
