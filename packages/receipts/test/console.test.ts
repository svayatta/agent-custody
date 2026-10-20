// The console: a separate admin service for the person who runs a gateway. Each test is a thing an operator relies on:
// that nothing is shown or changed without the token, that the receipts shown are verified and a tampered one says so,
// that a policy change is validated, replayed against recorded calls, and recorded before and after it is saved, that a
// revoked grant is refused by the gateway, and that nothing the console shows can run as script in the page.
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createGateway, createGatewayHost, type Gateway } from "../src/gateway.ts";
import { loadConfig } from "../src/config.ts";
import { serveConsole, type RunningConsole } from "../src/console.ts";
import { CONSOLE_CSP, CONSOLE_HTML, CONSOLE_SCRIPT } from "../src/console-page.ts";
import { grantDigest } from "../src/delegation.ts";
import { buildFixture } from "../scripts/fixture.ts";

const TOKEN = "console-test-token";
let fx: ReturnType<typeof buildFixture>;
let con: RunningConsole;
let gw: Gateway;
let ids: { allowed: string; denied: string };
const call = async (path: string, init: { method?: string; body?: unknown; token?: string | null } = {}) => {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (init.token !== null) headers.authorization = `Bearer ${init.token ?? TOKEN}`;
  const r = await fetch(new URL(path, con.url), { method: init.method ?? "GET", headers, ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }) });
  return { status: r.status, body: (await r.json()) as any };
};

beforeAll(async () => {
  fx = buildFixture(join(mkdtempSync(join(tmpdir(), "console-")), "fx"));
  const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
  cfg.revokedGrants = "revoked.json";
  writeFileSync(fx.configFile, JSON.stringify(cfg));
  gw = await createGateway(loadConfig(fx.configFile));
  const meta = (r: { _meta?: Record<string, unknown> }) => String(r._meta?.["agent-custody/receipt"]);
  await gw.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
  const allowed = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
  const denied = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 9_999_999 } });
  ids = { allowed: meta(allowed), denied: meta(denied) };
  await gw.close();
  con = await serveConsole({ configFile: fx.configFile, token: TOKEN, port: 0, log: () => {} });
});

afterAll(async () => {
  await con.close();
});

describe("the console", () => {
  it("answers /healthz without a token and nothing else: every API route needs the bearer token", async () => {
    expect((await call("/healthz", { token: null })).status).toBe(200);
    for (const path of ["/api/overview", "/api/policy", "/api/receipts", "/api/audit", "/api/revocations"]) expect((await call(path, { token: null })).status, path).toBe(401);
    expect((await call("/api/overview", { token: "wrong" })).status).toBe(401);
  });

  it("locks an address out for a minute after five wrong tokens", async () => {
    // a fresh console, so this test's misses are its own
    const other = await serveConsole({ configFile: fx.configFile, token: TOKEN, port: 0, log: () => {} });
    try {
      let last = 0;
      for (let i = 0; i < 6; i++) last = (await fetch(new URL("/api/audit", other.url), { headers: { authorization: "Bearer nope" } })).status;
      expect(last).toBe(429);
      expect((await fetch(new URL("/api/audit", other.url), { headers: { authorization: `Bearer ${TOKEN}` } })).status).toBe(429);
    } finally {
      await other.close();
    }
  });

  it("the overview says what the gateway is configured with, who it trusts, and runs the config check", async () => {
    const { body } = await call("/api/overview");
    expect(body.upstreams[0].kind).toBe("mcp-stdio");
    expect(body.mode).toBe("enforce");
    expect(body.principals).toHaveLength(1);
    expect(body.receiptCount).toBeGreaterThanOrEqual(3);
    expect(body.facts[0].tool).toBe("customer.lookup");
    expect(body.findings.some((f: { level: string }) => f.level === "error")).toBe(false);
  });

  it("the check route runs the same check as the command, and --connect lists the tools the upstream offers", async () => {
    const { body } = await call("/api/check", { method: "POST", body: { connect: true } });
    expect(body.findings.find((f: { check: string }) => f.check === "upstreams").message).toContain("stripe.refund");
  });

  it("receipts are listed with their decision and outcome, and each verifies; a denied call shows as denied", async () => {
    const { body } = await call("/api/receipts");
    const byId = new Map(body.receipts.map((r: { id: string }) => [r.id, r]));
    const ok = byId.get(ids.allowed) as any;
    const no = byId.get(ids.denied) as any;
    expect([ok.tool, ok.decision, ok.status, ok.verified]).toEqual(["stripe.refund", "allow", "executed", true]);
    expect([no.decision, no.status, no.verified]).toEqual(["deny", "denied", true]);
    const one = await call(`/api/receipts/${ids.denied}`);
    expect(one.body.statement.policy.decision).toBe("deny");
  });

  it("a receipt edited on disk is reported as not verifying, and names the failed check", async () => {
    const file = join(fx.receiptsDir, `${ids.allowed}.json`);
    const original = readFileSync(file, "utf8");
    try {
      const b = JSON.parse(original);
      b.envelope.payload = Buffer.from(Buffer.from(b.envelope.payload, "base64").toString().replace("2500", "1")).toString("base64");
      writeFileSync(file, JSON.stringify(b));
      const { body } = await call("/api/receipts");
      const r = body.receipts.find((x: { id: string }) => x.id === ids.allowed);
      expect(r.verified).toBe(false);
      expect(r.failing.length).toBeGreaterThan(0);
    } finally {
      writeFileSync(file, original);
    }
  });

  it("a receipt id must be a UUID, so a path cannot be read through it", async () => {
    expect((await call("/api/receipts/..%2F..%2Fgateway.json")).status).toBe(400);
    expect((await call("/api/receipts/00000000-0000-0000-0000-000000000000")).status).toBe(404);
  });

  it("a policy that does not parse is reported with Cedar's message and cannot be saved", async () => {
    const v = await call("/api/policy/validate", { method: "POST", body: { text: "permit(principal" } });
    expect(v.body.ok).toBe(false);
    expect(v.body.errors[0]).toContain("failed to parse");
    const current = await call("/api/policy");
    const save = await call("/api/policy", { method: "PUT", body: { text: "permit(principal", expectDigest: current.body.digest } });
    expect(save.status).toBe(400);
    expect(readFileSync(join(fx.dir, "policy.cedar"), "utf8")).toBe(current.body.text);
  });

  it("a permit that only appears in a comment is reported as no permit rule", async () => {
    const v = await call("/api/policy/validate", { method: "POST", body: { text: '// permit(principal, action, resource);\nforbid(principal, action == Action::"stripe.refund", resource);\n' } });
    expect([v.body.ok, v.body.hasPermit]).toEqual([true, false]);
  });

  it("replays recorded calls against a proposed policy and says which decisions would change", async () => {
    const stricter = 'permit(principal, action == Action::"customer.lookup", resource);\n';
    const { body } = await call("/api/policy/simulate", { method: "POST", body: { text: stricter } });
    expect(body.replayed).toBeGreaterThanOrEqual(3);
    expect(body.report.changes.some((c: { receiptId: string; from: string; to: string }) => c.receiptId === ids.allowed && c.from === "allow" && c.to === "deny")).toBe(true);
    expect(body.report.changes.some((c: { receiptId: string }) => c.receiptId === ids.denied)).toBe(false);
  });

  it("saving a policy keeps the previous version, records who changed what, and refuses a stale edit", async () => {
    const before = await call("/api/policy");
    const next = `${before.body.text}\n// reviewed\n`;
    const saved = await call("/api/policy", { method: "PUT", body: { text: next, expectDigest: before.body.digest } });
    expect(saved.status).toBe(200);
    expect(readFileSync(join(fx.dir, "policy.cedar"), "utf8")).toBe(next);
    expect(saved.body.note).toContain("restart");
    const history = readdirSync(join(fx.dir, "console", "policy-history"));
    expect(history).toHaveLength(1);
    expect(readFileSync(join(fx.dir, "console", "policy-history", history[0]!), "utf8")).toBe(before.body.text);
    const audit = (await call("/api/audit")).body.entries[0];
    expect([audit.action, audit.from, audit.to]).toEqual(["policy.save", before.body.digest, saved.body.digest]);
    const stale = await call("/api/policy", { method: "PUT", body: { text: next + "// again\n", expectDigest: before.body.digest } });
    expect(stale.status).toBe(409);
  });

  it("a policy with no permit is refused unless the operator confirms it", async () => {
    const cur = await call("/api/policy");
    const text = '// nothing allowed\nforbid(principal, action == Action::"stripe.refund", resource);\n';
    expect((await call("/api/policy", { method: "PUT", body: { text, expectDigest: cur.body.digest } })).status).toBe(400);
    const ok = await call("/api/policy", { method: "PUT", body: { text, expectDigest: cur.body.digest, allowNoPermit: true } });
    expect(ok.status).toBe(200);
    // put the permitting policy back for the tests that follow
    await call("/api/policy", { method: "PUT", body: { text: cur.body.text, expectDigest: ok.body.digest } });
  });

  it("inspects a grant, revokes it, and the gateway then refuses it", async () => {
    const grantText = readFileSync(join(fx.dir, "grant.json"), "utf8");
    const seen = await call("/api/grants/inspect", { method: "POST", body: { grant: grantText } });
    expect([seen.body.status, seen.body.agent, seen.body.scopes]).toEqual(["valid", "support-agent", ["customer.lookup", "stripe.refund"]]);
    const revoked = await call("/api/grants/revoke", { method: "POST", body: { grant: grantText } });
    expect(revoked.status).toBe(200);
    expect(JSON.parse(readFileSync(join(fx.dir, "revoked.json"), "utf8"))).toEqual([grantDigest(JSON.parse(grantText))]);
    expect((await call("/api/grants/inspect", { method: "POST", body: { grant: grantText } })).body.status).toBe("revoked");
    expect((await call("/api/revocations")).body.digests).toHaveLength(1);
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      expect(() => host.open(JSON.parse(grantText))).toThrow(/revoked/);
    } finally {
      await host.close();
    }
    expect((await call("/api/audit")).body.entries.some((e: { action: string }) => e.action === "grant.revoke")).toBe(true);
  });

  it("a grant signed by a key the gateway does not trust is reported invalid, and something that is not a grant is refused", async () => {
    const stranger = buildFixture(join(mkdtempSync(join(tmpdir(), "console-other-")), "fx"));
    const forged = readFileSync(join(stranger.dir, "grant.json"), "utf8");
    expect((await call("/api/grants/inspect", { method: "POST", body: { grant: forged } })).body.status).toBe("invalid");
    expect((await call("/api/grants/inspect", { method: "POST", body: { grant: { hello: "world" } } })).status).toBe(400);
  });

  it("refuses a request body over a megabyte", async () => {
    const r = await call("/api/policy/validate", { method: "POST", body: { text: "x".repeat(1_100_000) } });
    expect(r.status).toBe(413);
  });
});

describe("the console page", () => {
  it("is served with a content-security-policy that allows exactly its own script and style, by hash", async () => {
    const r = await fetch(con.url);
    expect(r.status).toBe(200);
    const csp = r.headers.get("content-security-policy")!;
    expect(csp).toBe(CONSOLE_CSP);
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).toMatch(/script-src 'sha256-[A-Za-z0-9+/=]+'/);
    expect(await r.text()).toBe(CONSOLE_HTML);
  });

  it("its script compiles, and writes no data as markup", () => {
    expect(() => new vm.Script(CONSOLE_SCRIPT)).not.toThrow();
    expect(CONSOLE_SCRIPT).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
    expect(CONSOLE_SCRIPT).not.toMatch(/setAttribute\('style'|style: '/);
  });
});
