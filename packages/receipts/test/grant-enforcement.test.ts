// The grant is enforced on every call, in every mode (issue #97): a session whose grant expires keeps no authority,
// a tool outside the scopes is never forwarded even in observe mode, a revoked grant stops at the next call, and an
// HTTP session under an expired or revoked grant is closed rather than resumed.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey, publicKeyToPem, type Envelope } from "../src/crypto.ts";
import { createDelegation, decodeDelegation, delegateFrom } from "../src/delegation.ts";
import { createGateway, createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import { grantHeader, serveHttp } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture, type Fixture } from "../scripts/fixture.ts";

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** waits until the grant has expired, however long startup took under load */
const untilExpired = (expiresAt: string) => sleep(Math.max(0, Date.parse(expiresAt) - Date.now() + 300));
const text = (r: { content: { type: string; text?: string }[] }) => (r.content[0] as { text: string }).text;
const receiptOf = async (fx: Fixture, id: string) => {
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
  const v = await verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
  expect(v.ok, v.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")).toBe(true);
  return decode(bundle).predicate;
};
const withConfig = (fx: Fixture, edit: (cfg: Record<string, unknown>) => void) => {
  const cfg = JSON.parse(readFileSync(fx.configFile, "utf8")) as Record<string, unknown>;
  edit(cfg);
  writeFileSync(fx.configFile, JSON.stringify(cfg));
};

describe("the grant on every call", () => {
  it("a session whose grant expires refuses its next call with a denial receipt, and the verifier accepts the receipt", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "grant-expiry-")), 8000);
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      const ok = await gw.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
      expect(ok.isError).toBeFalsy();
      expect(gw.grantProblem()).toBeNull();
      await untilExpired(gw.delegation.expiresAt);
      expect(gw.grantProblem()).toBe("has expired");
      const no = await gw.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
      expect(no.isError).toBe(true);
      expect(text(no)).toMatch(/delegation grant has expired/);
      const p = await receiptOf(fx, String(no._meta![RECEIPT_META_KEY]));
      expect(p.execution.status).toBe("denied");
      expect(p.policy!.errors).toEqual(["delegation grant has expired"]);
    } finally {
      await gw.close();
    }
  }, 25_000);

  it("observe mode suspends the policy, not the grant: a tool outside the scopes is denied and never forwarded", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "grant-observe-")));
    withConfig(fx, (cfg) => {
      cfg.mode = "observe";
    });
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      // the policy's deny is recorded, not enforced: the over-limit refund is forwarded
      const over = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5_000_000 } });
      expect(over.isError).toBeFalsy();
      // the grant's deny is enforced: payout is not in the scopes, so nothing is forwarded, observe mode or not
      const out = await gw.handleCall({ name: "stripe.payout", arguments: { amount: 100 } });
      expect(out.isError).toBe(true);
      expect(text(out)).toMatch(/not in the delegation scopes/);
      const p = await receiptOf(fx, String(out._meta![RECEIPT_META_KEY]));
      expect(p.execution.status).toBe("denied");
      expect(p.policy!.enforced).toBeUndefined();
      const o = await receiptOf(fx, String(over._meta![RECEIPT_META_KEY]));
      expect(o.policy!.enforced).toBe(false);
      expect(o.execution.status).toBe("executed");
    } finally {
      await gw.close();
    }
  });

  it("a revoked grant stops at the next call of a running session, opens no new session, and the revocation is written to the file the gateway re-reads", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "grant-revoke-")));
    withConfig(fx, (cfg) => {
      cfg.revokedGrants = "revoked.json";
    });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const grant = JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope;
    try {
      const session = host.open(grant);
      expect((await session.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } })).isError).toBeFalsy();
      host.revoke(session.grantDigest);
      expect(JSON.parse(readFileSync(join(fx.dir, "revoked.json"), "utf8"))).toEqual([session.grantDigest]);
      const no = await session.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
      expect(no.isError).toBe(true);
      expect(text(no)).toMatch(/delegation grant has been revoked/);
      expect(() => host.open(grant)).toThrow(/has been revoked/);
      expect(host.revoked()).toEqual([session.grantDigest]);
      const other = host.open(createDelegation(loadPrivateKey(join(fx.dir, "keys", "principal.key")), { version: "0.1", principal: "user_456", agent: "billing-agent", scopes: ["customer.lookup"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString(), agentKey: publicKeyToPem(generateKeyPair().publicKey) }));
      expect((await other.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } })).isError).toBeFalsy();
    } finally {
      await host.close();
    }
  });

  it("a revoked grant stays revoked when the agent repacks its envelope, and every grant delegated from it is revoked too", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "grant-revoke-bypass-")));
    withConfig(fx, (cfg) => {
      cfg.revokedGrants = "revoked.json";
    });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const agent = generateKeyPair();
    const now = Date.now();
    const root = createDelegation(loadPrivateKey(join(fx.dir, "keys", "principal.key")), {
      version: "0.1",
      principal: "user_456",
      agent: "support-agent",
      scopes: ["customer.lookup", "stripe.refund"],
      issuedAt: new Date(now - 1000).toISOString(),
      expiresAt: new Date(now + 3_600_000).toISOString(),
      agentKey: publicKeyToPem(agent.publicKey),
    });
    const child = delegateFrom(root, agent, { agent: "lookup-only", scopes: ["customer.lookup"] });
    try {
      const childSession = host.open(child);
      host.revoke(host.open(root).grantDigest);
      // extra signatures or fields leave the signed payload, and so the digest, unchanged
      expect(() => host.open({ ...root, signatures: [...root.signatures, { keyid: "x", sig: "AA==" }] })).toThrow(/has been revoked/);
      expect(() => host.open({ ...root, note: 1 } as Envelope)).toThrow(/has been revoked/);
      // a child delegated before the revocation, or minted after it, falls with its parent
      expect(childSession.grantProblem()).toBe("has been revoked");
      expect(() => host.open(delegateFrom(root, agent, { agent: "fresh", scopes: ["customer.lookup"] }))).toThrow(/has been revoked/);
    } finally {
      await host.close();
    }
  });

  it("a revocation list that cannot be read denies every call with a receipt, and the gateway keeps running", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "grant-revoke-bad-")));
    withConfig(fx, (cfg) => {
      cfg.revokedGrants = "revoked.json";
    });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const session = host.open(JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope);
      writeFileSync(join(fx.dir, "revoked.json"), '["abc');
      const no = await session.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
      expect(no.isError).toBe(true);
      expect(text(no)).toMatch(/cannot be checked against the revocation list/);
      expect((await receiptOf(fx, String(no._meta![RECEIPT_META_KEY]))).execution.status).toBe("denied");
    } finally {
      await host.close();
    }
  });

  it("agent-custody revoke writes the file, and a host that was already running picks it up on the next call", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "grant-revoke-cli-")));
    withConfig(fx, (cfg) => {
      cfg.revokedGrants = "revoked.json";
    });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const grant = JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope;
    try {
      const session = host.open(grant);
      expect((await session.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } })).isError).toBeFalsy();
      const cli = spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "revoke", "--config", fx.configFile, "--grant", join(fx.dir, "grant.json")], { encoding: "utf8" });
      expect(cli.status, cli.stderr).toBe(0);
      expect(cli.stdout).toMatch(/revoked support-agent's grant from user_456/);
      expect(JSON.parse(readFileSync(join(fx.dir, "revoked.json"), "utf8"))).toEqual([session.grantDigest]);
      const no = await session.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
      expect(no.isError).toBe(true);
      expect(text(no)).toMatch(/has been revoked/);
    } finally {
      await host.close();
    }
  });

  it("over HTTP, a session under a grant that expired is closed and the request refused with 403; the session id resumes nothing", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "grant-http-")), 8000);
    const host = await createGatewayHost(loadConfig(fx.configFile));
    const running = await serveHttp(host, { port: 0, log: () => {} });
    const grant = JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope;
    const client = new Client({ name: "agent", version: "0" });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: `Bearer ${grantHeader(grant)}` } } }));
      expect((await client.listTools()).tools.length).toBeGreaterThan(0);
      expect(running.sessions()).toHaveLength(1);
      await untilExpired(decodeDelegation(grant)!.expiresAt);
      await expect(client.callTool({ name: "customer.lookup", arguments: { customer_id: "cust_123" } })).rejects.toThrow(/403|has expired/);
      expect(running.sessions()).toHaveLength(0);
    } finally {
      await client.close().catch(() => {});
      await running.close();
      await host.close();
    }
  }, 25_000);
});
