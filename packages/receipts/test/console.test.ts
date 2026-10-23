// The console: a separate admin service for the person who runs a gateway. Each test is a thing an operator relies on:
// that nothing is shown or changed without the token, that the receipts shown are verified and a tampered one says so,
// that a policy change is validated, replayed against recorded calls, and recorded before and after it is saved, that a
// revoked grant is refused by the gateway, and that nothing the console shows can run as script in the page.
import { mkdtempSync, readFileSync, readdirSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
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
    expect(v.body.ok).toBe(true);
    expect(v.body.issues.join(" ")).toContain("no permit rule");
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
    expect(saved.body.note).toContain("next call");
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
    const ok = await call("/api/policy", { method: "PUT", body: { text, expectDigest: cur.body.digest, confirm: true } });
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

describe("the console, under the review's cases", () => {
  it("an unconditioned permit with no action is a thing to confirm, because a replay of past calls cannot show it", async () => {
    const cur = await call("/api/policy");
    const broad = "permit(principal, action, resource);\n";
    const v = await call("/api/policy/validate", { method: "POST", body: { text: broad } });
    expect(v.body.issues.join(" ")).toContain("every tool in a grant's scopes");
    // the recorded history would not change: nothing it recorded was outside what the old policy allowed
    const replay = await call("/api/policy/simulate", { method: "POST", body: { text: broad } });
    expect(replay.body.report.changes.every((c: { to: string }) => c.to === "allow")).toBe(true);
    const refused = await call("/api/policy", { method: "PUT", body: { text: broad, expectDigest: cur.body.digest } });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toContain("confirm before saving");
    expect(readFileSync(join(fx.dir, "policy.cedar"), "utf8")).toBe(cur.body.text);
    // a permit that names an action, or has a condition, is not asked about
    const fine = await call("/api/policy/validate", { method: "POST", body: { text: 'permit(principal, action == Action::"customer.lookup", resource);\n' } });
    expect(fine.body.issues).toEqual([]);
    const conditioned = await call("/api/policy/validate", { method: "POST", body: { text: "permit(principal, action, resource) when { context.args has amount };\n" } });
    expect(conditioned.body.issues).toEqual([]);
  });

  it("two saves that loaded the same digest cannot both win: one saves, the other is refused, and history holds the version that was replaced", async () => {
    const cur = await call("/api/policy");
    const a = `${cur.body.text}\n// edit A\n`;
    const b = `${cur.body.text}\n// edit B\n`;
    const before = readdirSync(join(fx.dir, "console", "policy-history")).length;
    const [ra, rb] = await Promise.all([
      call("/api/policy", { method: "PUT", body: { text: a, expectDigest: cur.body.digest } }),
      call("/api/policy", { method: "PUT", body: { text: b, expectDigest: cur.body.digest } }),
    ]);
    expect([ra.status, rb.status].sort()).toEqual([200, 409]);
    const winner = ra.status === 200 ? a : b;
    expect(readFileSync(join(fx.dir, "policy.cedar"), "utf8")).toBe(winner);
    const history = readdirSync(join(fx.dir, "console", "policy-history"));
    expect(history.length).toBe(before + 1);
    const newest = history.sort().at(-1)!;
    expect(readFileSync(join(fx.dir, "console", "policy-history", newest), "utf8")).toBe(cur.body.text);
    // put the original back for the tests that follow
    const now = await call("/api/policy");
    await call("/api/policy", { method: "PUT", body: { text: cur.body.text, expectDigest: now.body.digest } });
  });

  it("a save waits for another console that holds the lock on the same state directory, and a stale lock does not block it forever", async () => {
    const lock = join(fx.dir, "console", "policy.lock");
    const cur = await call("/api/policy");
    // another console process is saving: its lock file is there, so this save has to wait
    writeFileSync(lock, "");
    let done = false;
    const pending = call("/api/policy", { method: "PUT", body: { text: `${cur.body.text}\n// waited\n`, expectDigest: cur.body.digest } }).then((r) => { done = true; return r; });
    await new Promise((r) => setTimeout(r, 400));
    expect(done).toBe(false);
    unlinkSync(lock);
    expect((await pending).status).toBe(200);
    // a lock left by a process that died is old enough to be taken over
    const now = await call("/api/policy");
    writeFileSync(lock, "");
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock, old, old);
    expect((await call("/api/policy", { method: "PUT", body: { text: cur.body.text, expectDigest: now.body.digest } })).status).toBe(200);
  });

  it("the console does not hold the gateway's credentials, so it does not call a healthy gateway unable to start, and does not try to start its upstreams", async () => {
    const other = buildFixture(join(mkdtempSync(join(tmpdir(), "console-creds-")), "fx"));
    const cfg = JSON.parse(readFileSync(other.configFile, "utf8"));
    cfg.upstream = { rest: { baseUrl: "https://api.example.com", headerEnv: { authorization: "CONSOLE_TEST_UPSTREAM_TOKEN_UNSET" }, tools: [{ name: "customer.lookup", method: "GET", path: "/c/{id}" }] } };
    writeFileSync(other.configFile, JSON.stringify(cfg));
    const c = await serveConsole({ configFile: other.configFile, token: TOKEN, port: 0, log: () => {} });
    try {
      const get = async (path: string, body?: unknown) => (await fetch(new URL(path, c.url), { method: body === undefined ? "GET" : "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })).json() as Promise<any>;
      const overview = await get("/api/overview");
      expect(overview.findings.some((f: { level: string }) => f.level === "error")).toBe(false);
      expect(overview.findings.find((f: { check: string }) => f.check === "environment").message).toContain("does not hold the gateway's credentials");
      const connected = await get("/api/check", { connect: true });
      expect(connected.findings.some((f: { level: string }) => f.level === "error")).toBe(false);
      expect(connected.findings.find((f: { check: string }) => f.check === "upstreams").message).toContain("docker compose exec gateway");
    } finally {
      await c.close();
    }
  });

  it("a connect check that does not finish is stopped when its time is up, the upstream it started is closed, and the next one can run", async () => {
    const hang = buildFixture(join(mkdtempSync(join(tmpdir(), "console-hang-")), "fx"));
    const marker = join(hang.dir, "child.pid");
    const script = join(hang.dir, "hang.js");
    // an MCP server that never answers the handshake, and says where it is so the test can see it die
    writeFileSync(script, `require("node:fs").writeFileSync(${JSON.stringify(marker)}, String(process.pid)); setInterval(() => {}, 1e6);`);
    const cfg = JSON.parse(readFileSync(hang.configFile, "utf8"));
    cfg.upstream = { command: process.execPath, args: [script] };
    writeFileSync(hang.configFile, JSON.stringify(cfg));
    const c = await serveConsole({ configFile: hang.configFile, token: TOKEN, port: 0, checkTimeoutMs: 600, log: () => {} });
    try {
      const post = () => fetch(new URL("/api/check", c.url), { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify({ connect: true }) });
      const first = await post();
      expect(first.status).toBe(504);
      const pid = Number(readFileSync(marker, "utf8"));
      // the upstream it started is gone, not left running behind a rejected request
      let alive = true;
      for (let i = 0; i < 50 && alive; i++) {
        try { process.kill(pid, 0); await new Promise((r) => setTimeout(r, 100)); } catch { alive = false; }
      }
      expect(alive).toBe(false);
      expect((await post()).status).toBe(504);
    } finally {
      await c.close();
    }
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
