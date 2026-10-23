// A log outage after an ordinary call must not lose the receipt or tell the agent that the call failed: the signed
// receipt waits in the outbox and is appended when the log is back.
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { loadPrivateKey, loadPublicKey, type Envelope } from "../src/crypto.ts";
import { createGatewayHost, LOG_PENDING_META_KEY, RECEIPT_META_KEY } from "../src/gateway.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";

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
      expect(await host.flushOutbox()).toEqual({ sent: 0, pending: 1, setAside: 0, error: "log unreachable" });
      // the same signed receipt under another name is not appended under that name
      writeFileSync(join(f.receiptsDir, "outbox", "forged.json"), readFileSync(join(f.receiptsDir, "outbox", `${id}.json`)));

      down = false;
      expect(await host.flushOutbox()).toEqual({ sent: 1, pending: 0, setAside: 1 });
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
