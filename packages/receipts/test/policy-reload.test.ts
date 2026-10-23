// The Cedar policy is re-read whenever its file changes and applies from the next call, with no restart and no dropped
// session. A policy that does not parse, or a file that cannot be read, is refused and the policy in force stays. Every
// change and every refusal is recorded with both digests.
import { chmodSync, mkdtempSync, readFileSync, renameSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey, type Envelope } from "../src/crypto.ts";
import { createGateway, createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import { grantHeader, serveHttp } from "../src/gateway-http.ts";
import { policyDigest } from "../src/policy.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture, POLICY, type Fixture } from "../scripts/fixture.ts";

const TIGHT = POLICY.replace("context.args.amount <= 100000", "context.args.amount <= 1000");
const refund = { name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5000 } };

/** replaces the file by rename, as an editor or the console does, so a reader never sees half of it */
const writePolicy = (fx: Fixture, text: string) => {
  const path = join(fx.dir, "policy.cedar");
  writeFileSync(`${path}.tmp`, text);
  renameSync(`${path}.tmp`, path);
};
const receiptOf = async (fx: Fixture, result: { _meta?: Record<string, unknown> }) => {
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(result._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  const v = await verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
  expect(v.ok, v.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")).toBe(true);
  return (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
};
const reloads = (fx: Fixture) => readFileSync(join(fx.receiptsDir, "policy-reloads.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
const quietly = async <T>(fn: () => Promise<T>): Promise<T> => {
  const error = console.error;
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.error = error;
  }
};

describe("policy reload", () => {
  it("a tightened policy applies from the next call of a running session, and the receipts name the policy that decided each call", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-")));
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      const before = await gw.handleCall(refund);
      expect(before.isError).toBeFalsy();
      const allowed = await receiptOf(fx, before);
      expect(allowed.policy!.decision).toBe("allow");
      expect(allowed.policy!.policyDigest).toBe(policyDigest(POLICY));

      await quietly(async () => writePolicy(fx, TIGHT));
      const after = await quietly(() => gw.handleCall(refund));
      expect(after.isError).toBe(true);
      const denied = await receiptOf(fx, after);
      expect(denied.policy!.decision).toBe("deny");
      expect(denied.policy!.policyDigest).toBe(policyDigest(TIGHT));
      expect(denied.execution.status).toBe("denied");

      expect(reloads(fx)).toEqual([expect.objectContaining({ event: "reloaded", from: policyDigest(POLICY), to: policyDigest(TIGHT) })]);
      expect(Date.parse(String(reloads(fx)[0]!.at))).not.toBeNaN();
    } finally {
      await gw.close();
    }
  });

  it("a policy that does not parse is refused: the policy in force stays, never an allow-all, and the refusal is recorded", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-bad-")));
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const session = host.open(JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope);
    try {
      await quietly(async () => writePolicy(fx, TIGHT));
      expect(await quietly(async () => host.policyDigest())).toBe(policyDigest(TIGHT));

      const broken = "permit(principal, action, resource) when { context.args.amount <= };";
      writePolicy(fx, broken);
      const errors: string[] = [];
      const error = console.error;
      console.error = (...a: unknown[]) => { errors.push(a.join(" ")); };
      let result;
      try {
        result = await session.handleCall(refund);
      } finally {
        console.error = error;
      }
      expect(errors.join("\n")).toMatch(/POLICY NOT RELOADED/);
      expect(result.isError).toBe(true);
      expect((await receiptOf(fx, result)).policy!.policyDigest).toBe(policyDigest(TIGHT));
      expect(host.policyDigest()).toBe(policyDigest(TIGHT));
      expect(reloads(fx).at(-1)).toEqual(expect.objectContaining({ event: "refused", from: policyDigest(TIGHT), to: policyDigest(broken) }));

      // a removed file is refused the same way, and a valid file after it is applied
      await quietly(async () => {
        rmSync(join(fx.dir, "policy.cedar"));
        expect(host.policyDigest()).toBe(policyDigest(TIGHT));
        writePolicy(fx, POLICY);
        expect(host.policyDigest()).toBe(policyDigest(POLICY));
      });
      expect(reloads(fx).map((r) => r.event)).toEqual(["reloaded", "refused", "refused", "reloaded"]);
      expect((await receiptOf(fx, await session.handleCall(refund))).policy!.decision).toBe("allow");
    } finally {
      await session.close();
      await host.close();
    }
  });

  it.skipIf(process.getuid?.() === 0)("a tightened policy that was unreadable is applied once it can be read, though its metadata did not change", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-mode-")));
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const session = host.open(JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope);
    const path = join(fx.dir, "policy.cedar");
    try {
      await quietly(async () => {
        writeFileSync(`${path}.tmp`, TIGHT);
        chmodSync(`${path}.tmp`, 0o000);
        renameSync(`${path}.tmp`, path);
        expect(host.policyDigest()).toBe(policyDigest(POLICY));
        expect(host.policyDigest()).toBe(policyDigest(POLICY));
        chmodSync(path, 0o644);
      });
      const result = await quietly(() => session.handleCall(refund));
      expect(result.isError).toBe(true);
      expect((await receiptOf(fx, result)).policy!.policyDigest).toBe(policyDigest(TIGHT));
      expect(reloads(fx).map((r) => r.event)).toEqual(["refused", "reloaded"]);
    } finally {
      await session.close();
      await host.close();
    }
  });

  it("a call already under way finishes under the policy it started with; the next call takes the new one", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-inflight-")));
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      // the policy is taken before the first await of the call, so writing a new one while it runs cannot change it
      const running = quietly(() => gw.handleCall(refund));
      await quietly(async () => writePolicy(fx, TIGHT));
      const first = await running;
      expect(first.isError).toBeFalsy();
      const p = await receiptOf(fx, first);
      expect(p.policy!.decision).toBe("allow");
      expect(p.policy!.policyDigest).toBe(policyDigest(POLICY));
      const next = await quietly(() => gw.handleCall(refund));
      expect((await receiptOf(fx, next)).policy!.policyDigest).toBe(policyDigest(TIGHT));
      expect(next.isError).toBe(true);
    } finally {
      await gw.close();
    }
  });

  it("an edit in place that keeps the size and the modification time is still applied", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-inplace-")));
    const path = join(fx.dir, "policy.cedar");
    // the same length as the policy it replaces, so only the bytes, the change time, and nothing a program can set differ
    const same = POLICY.replace("context.args.amount <= 100000", "context.args.amount <= 1000  ");
    expect(same.length).toBe(POLICY.length);
    const past = new Date(Date.now() - 60_000);
    utimesSync(path, past, past);
    // every file counts as settled, so the edit is caught by its key alone and not by the re-read of a recent file
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockImplementation(() => now + 10_000);
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      expect(host.policyDigest()).toBe(policyDigest(POLICY));
      writeFileSync(path, same);
      utimesSync(path, past, past);
      expect(await quietly(async () => host.policyDigest())).toBe(policyDigest(same));
    } finally {
      clock.mockRestore();
      await host.close();
    }
  });

  it("a reloaded policy with no permit rule is applied, since it denies every call, and the record says so", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-nopermit-")));
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const deny = "// nothing is permitted\n";
      const errors: string[] = [];
      const error = console.error;
      console.error = (...a: unknown[]) => { errors.push(a.join(" ")); };
      try {
        writePolicy(fx, deny);
        expect(host.policyDigest()).toBe(policyDigest(deny));
      } finally {
        console.error = error;
      }
      expect(errors.join("\n")).toMatch(/WARNING: no permit rule/);
      expect(reloads(fx).at(-1)).toEqual(expect.objectContaining({ event: "reloaded", to: policyDigest(deny), warnings: ["no permit rule: every call is denied"] }));
    } finally {
      await host.close();
    }
  });

  it("observe mode records the reloaded policy's decision without enforcing it", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-observe-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8")) as Record<string, unknown>;
    writeFileSync(fx.configFile, JSON.stringify({ ...cfg, mode: "observe" }));
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      await quietly(async () => writePolicy(fx, TIGHT));
      const result = await quietly(() => gw.handleCall(refund));
      expect(result.isError).toBeFalsy();
      const p = await receiptOf(fx, result);
      expect(p.policy).toEqual(expect.objectContaining({ decision: "deny", enforced: false, policyDigest: policyDigest(TIGHT) }));
      expect(p.execution.status).toBe("executed");
    } finally {
      await gw.close();
    }
  });

  it("over HTTP, an open session gets the new policy on its next request without reconnecting", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-http-")));
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const running = await serveHttp(host, { port: 0, log: () => {} });
    const grant = JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope;
    const client = new Client({ name: "agent", version: "0" });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: `Bearer ${grantHeader(grant)}` } } }));
      expect((await client.callTool(refund)).isError).toBeFalsy();
      await quietly(async () => writePolicy(fx, TIGHT));
      const denied = await quietly(() => client.callTool(refund));
      expect(denied.isError).toBe(true);
      expect((await receiptOf(fx, denied as { _meta?: Record<string, unknown> })).policy!.policyDigest).toBe(policyDigest(TIGHT));
      expect(running.sessions()).toHaveLength(1);
    } finally {
      await client.close().catch(() => {});
      await running.close();
      await host.close();
    }
  });
});
