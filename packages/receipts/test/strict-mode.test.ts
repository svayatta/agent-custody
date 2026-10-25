// Strict mode exists so that an operator cannot keep a call off the record: no call goes out before its authorization
// is in a log someone else runs, nothing waits in an outbox the operator could empty, and every receipt says so, so a
// verifier can insist on it. Each refusal is pinned here; reverting any one of them fails a test below.
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { checkConfig } from "../src/check.ts";
import { GatewayConfigSchema, loadConfig } from "../src/config.ts";
import { dsseSign, loadPrivateKey, loadPublicKey, type Envelope } from "../src/crypto.ts";
import { createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";

const REFUND = { name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } };
const OVER_LIMIT = { name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5_000_000 } };
const LOOKUP = { name: "customer.lookup", arguments: { customer_id: "cust_123" } };
const decode = (env: Envelope) => JSON.parse(Buffer.from(env.payload, "base64").toString()) as ReceiptStatement;
const STRICT_LOG = (gatewayPub: string) => ({ url: "https://log.invalid", hashOnly: true, keys: [gatewayPub] });

/** A strict gateway in front of a log reached as if over HTTP, backed by a file so receipts verify; `refuse` turns away the next appends. */
async function strictGateway(prefix: string, edit?: (config: Record<string, any>) => void) {
  const dir = mkdtempSync(join(tmpdir(), `agent-custody-strict-${prefix}-`));
  const f = buildFixture(dir);
  const raw = JSON.parse(readFileSync(f.configFile, "utf8"));
  delete raw.logFile;
  raw.log = STRICT_LOG(f.gatewayPub);
  raw.strict = true;
  edit?.(raw);
  writeFileSync(f.configFile, JSON.stringify(raw));
  const inner = fileLog(f.logFile, loadPrivateKey(join(dir, "keys", "gateway.key")));
  const state = { refuse: 0 };
  const log: LogSink = {
    kind: "http",
    where: "https://log.invalid",
    append: (leaf) => state.refuse > 0 ? (state.refuse--, Promise.reject(new Error("log unreachable"))) : inner.append(leaf),
  };
  const cfg = loadConfig(f.configFile);
  const host = await createGatewayHost(cfg, { log });
  const gw = host.open(JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope);
  const bundle = (id: string) => JSON.parse(readFileSync(join(f.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
  const keys = { issuerKeys: [loadPublicKey(f.gatewayPub)], principalKeys: [loadPublicKey(f.principalPub)], logFile: f.logFile };
  return { f, cfg, log, state, host, gw, bundle, keys };
}

describe("strict mode", () => {
  it("refuses to start with a local log, with a remote log that is not hash-only, or with a remote log whose keys are not pinned", () => {
    const f = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-strict-config-")));
    const base = JSON.parse(readFileSync(f.configFile, "utf8"));
    const parse = (edit: (c: Record<string, any>) => void) => {
      const c = structuredClone(base);
      edit(c);
      return () => GatewayConfigSchema.parse(c);
    };
    expect(parse((c) => { c.strict = true; })).toThrow(/strict mode needs a remote log/);
    expect(parse((c) => { c.strict = true; delete c.logFile; c.log = { ...STRICT_LOG(f.gatewayPub), hashOnly: false }; })).toThrow(/strict mode needs log.hashOnly/);
    expect(parse((c) => { c.strict = true; delete c.logFile; c.log = { url: "https://log.invalid", hashOnly: true }; })).toThrow(/strict mode needs log.keys/);
    expect(parse((c) => { c.strict = true; delete c.logFile; c.log = STRICT_LOG(f.gatewayPub); })).not.toThrow();
    // the same local log without strict is an ordinary config
    expect(parse(() => {})).not.toThrow();
  });

  it("refuses to start when it is handed a config the schema never saw, or a log that is a file", async () => {
    const f = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-strict-host-")));
    const cfg = loadConfig(f.configFile);
    await expect(createGatewayHost({ ...cfg, strict: true })).rejects.toThrow(/strict mode needs a remote log/);
    const { logFile: _local, ...remote } = cfg;
    const file = fileLog(f.logFile, loadPrivateKey(join(f.dir, "keys", "gateway.key")));
    await expect(createGatewayHost({ ...remote, strict: true, log: STRICT_LOG(f.gatewayPub) }, { log: file })).rejects.toThrow(/strict mode needs a remote log, and .* is a file/);
    const http: LogSink = { kind: "http", where: "https://log.invalid", append: (leaf) => file.append(leaf) };
    await expect(createGatewayHost({ ...remote, strict: true, log: { ...STRICT_LOG(f.gatewayPub), hashOnly: false } }, { log: http })).rejects.toThrow(/strict mode needs log.hashOnly/);
  });

  it("precommits every tool, a read included, and marks the receipt and its authorization as strict", async () => {
    const s = await strictGateway("read");
    try {
      expect(s.cfg.precommit).toEqual([]);
      const res = await s.gw.handleCall(LOOKUP);
      expect(res.isError).toBeFalsy();
      const b = s.bundle(String(res._meta?.[RECEIPT_META_KEY]));
      const p = decode(b.envelope).predicate;
      expect(p.execution.status).toBe("executed");
      expect(p.authorization).toBeDefined();
      expect(p.issuer.strict).toBe(true);
      expect(decode(p.authorization!.envelope).predicate.issuer.strict).toBe(true);
      const r = verifyBundle(b, { ...s.keys, requireStrict: true });
      expect(r.checks.filter((c) => !c.ok)).toEqual([]);
      expect(r.checks.map((c) => c.name)).toEqual(expect.arrayContaining(["strict mode in force", "strict: call precommitted before forwarding", "authorization logged before execution"]));
    } finally {
      await s.host.close();
    }
  });

  it("withholds a call whose authorization the log will not take, in observe mode as well", async () => {
    for (const mode of ["enforce", "observe"] as const) {
      const s = await strictGateway(`withheld-${mode}`, (c) => { c.mode = mode; });
      try {
        s.state.refuse = 1;
        const res = await s.gw.handleCall(REFUND);
        expect(res.isError, mode).toBe(true);
        expect((res.content[0] as { text: string }).text).toMatch(/Not executed: the log did not commit the authorization/);
        const p = decode(s.bundle(String(res._meta?.[RECEIPT_META_KEY])).envelope).predicate;
        expect(p.execution.status, mode).toBe("withheld");
        expect(p.issuer.strict).toBe(true);
      } finally {
        await s.host.close();
      }
    }
  });

  it("in observe mode precommits a call the policy would deny, since it is forwarded", async () => {
    const s = await strictGateway("observe-deny", (c) => { c.mode = "observe"; });
    try {
      const res = await s.gw.handleCall(OVER_LIMIT);
      const p = decode(s.bundle(String(res._meta?.[RECEIPT_META_KEY])).envelope).predicate;
      expect(p.policy?.decision).toBe("deny");
      expect(p.policy?.enforced).toBe(false);
      expect(p.execution.status).not.toBe("withheld");
      expect(p.authorization).toBeDefined();
    } finally {
      await s.host.close();
    }
  });

  it("keeps no outbox: a receipt the log refuses after the forward is not kept, and the logged authorization is the evidence", async () => {
    const s = await strictGateway("no-outbox");
    try {
      const before = readdirSync(s.f.receiptsDir).filter((n) => n.endsWith(".authorization.json"));
      // the authorization goes in; the receipt that follows is refused
      let n = 0;
      const append = s.log.append;
      (s.log as { append: LogSink["append"] }).append = (leaf) => (++n === 2 ? Promise.reject(new Error("log unreachable")) : append(leaf));
      await expect(s.gw.handleCall(LOOKUP)).rejects.toThrow(/log unreachable/);
      expect(s.host.pendingReceipts()).toBe(0);
      expect(existsSync(join(s.f.receiptsDir, "outbox"))).toBe(false);
      const after = readdirSync(s.f.receiptsDir).filter((n) => n.endsWith(".authorization.json"));
      expect(after.length).toBe(before.length + 1);
    } finally {
      await s.host.close();
    }
  });

  it("appends receipts left in the outbox from before strict mode once, at start, and runs no outbox timer", async () => {
    const s = await strictGateway("leftover");
    await s.host.close();
    // a receipt from the same gateway before strict was turned on, kept while its log was down
    const { strict: _strict, ...plain } = s.cfg;
    const down: LogSink = { kind: "http", where: "https://log.invalid", append: () => Promise.reject(new Error("log unreachable")) };
    const before = await createGatewayHost(plain, { log: down });
    const res = await before.open(JSON.parse(readFileSync(s.cfg.grantFile!, "utf8")) as Envelope).handleCall(LOOKUP);
    await before.close();
    const id = String(res._meta?.[RECEIPT_META_KEY]);
    expect(readdirSync(join(s.f.receiptsDir, "outbox"))).toEqual([`${id}.json`]);

    const interval = vi.spyOn(globalThis, "setInterval");
    try {
      const serving = await createGatewayHost(s.cfg, { log: s.log, autoFlush: true });
      await serving.close();
      expect(interval.mock.calls.some(([, ms]) => ms === 30_000)).toBe(false);
    } finally {
      interval.mockRestore();
    }
    expect(readdirSync(join(s.f.receiptsDir, "outbox"))).toEqual([]);
    expect(decode(s.bundle(id).envelope).predicate.issuer.strict).toBeUndefined();
  });

  it("a verifier that requires strict refuses an ordinary receipt, and a strict receipt whose authorization was removed", async () => {
    const f = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-strict-verify-")));
    const host = await createGatewayHost(loadConfig(f.configFile));
    const res = await host.open(JSON.parse(readFileSync(join(f.dir, "grant.json"), "utf8")) as Envelope).handleCall(LOOKUP);
    await host.close();
    const ordinary = JSON.parse(readFileSync(join(f.receiptsDir, `${String(res._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
    const keys = { issuerKeys: [loadPublicKey(f.gatewayPub)], principalKeys: [loadPublicKey(f.principalPub)], logFile: f.logFile };
    expect(verifyBundle(ordinary, keys).ok).toBe(true);
    const required = verifyBundle(ordinary, { ...keys, requireStrict: true });
    expect(required.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual(["strict mode in force", "strict: call precommitted before forwarding"]);

    const s = await strictGateway("stripped");
    try {
      const b = s.bundle(String((await s.gw.handleCall(LOOKUP))._meta?.[RECEIPT_META_KEY]));
      const st = decode(b.envelope);
      delete st.predicate.authorization;
      const stripped = { ...b, envelope: dsseSign(RECEIPT_TYPE, st, loadPrivateKey(join(s.f.dir, "keys", "gateway.key"))) };
      const failing = verifyBundle(stripped, { ...s.keys, requireStrict: true }).checks.filter((c) => !c.ok).map((c) => c.name);
      expect(failing).toContain("strict: call precommitted before forwarding");
      expect(failing).not.toContain("strict mode in force");
    } finally {
      await s.host.close();
    }
  });

  it("check says what strict mode would refuse, and drops the empty-precommit warning once strict is on", async () => {
    const f = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-strict-check-")));
    const off = await checkConfig(f.configFile);
    expect(off.find((x) => x.check === "strict")?.message).toMatch(/strict mode is off; turned on, it would refuse: strict mode needs a remote log/);

    const raw = JSON.parse(readFileSync(f.configFile, "utf8"));
    delete raw.logFile;
    raw.log = { url: "https://log.invalid" };
    writeFileSync(f.configFile, JSON.stringify(raw));
    const remote = await checkConfig(f.configFile);
    expect(remote.find((x) => x.check === "strict")?.message).toMatch(/would refuse: strict mode needs log.hashOnly.*; strict mode needs log.keys/);
    expect(remote.some((x) => x.check === "precommit" && x.level === "warn")).toBe(true);

    raw.log = STRICT_LOG(f.gatewayPub);
    raw.strict = true;
    writeFileSync(f.configFile, JSON.stringify(raw));
    const on = await checkConfig(f.configFile);
    expect(on.find((x) => x.check === "strict")).toMatchObject({ level: "ok", message: expect.stringMatching(/^strict mode: every call is precommitted/) });
    expect(on.some((x) => x.check === "precommit")).toBe(false);
    expect(on.filter((x) => x.level === "error")).toEqual([]);

    raw.log.hashOnly = false;
    writeFileSync(f.configFile, JSON.stringify(raw));
    expect((await checkConfig(f.configFile)).filter((x) => x.level === "error").map((x) => x.message)).toEqual([expect.stringMatching(/^strict: strict mode needs log.hashOnly/)]);
  });
});
