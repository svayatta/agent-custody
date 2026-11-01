// The door in front of a stand-in shop: an unknown arrival reads the catalogue and is refused a refund; a verified agent
// refunds within the policy and is refused above it, below zero, and at zero; a grant signed by a stranger, an expired
// grant, and a grant for other routes leave the arrival claimed; a declared name alone is claimed and never reaches the
// Cedar principal; a request that can change something is committed to the log before it is relayed, and not relayed
// when the log refuses; a redirect to the origin's own address comes back through the door; the policy decides before
// the body limit; observe mode relays and records; the origin down is an error receipt. Every receipt the door writes
// verifies with public keys, the right principal and agent provenance, and the arrival fact the policy decided on.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkDoorConfig, isDoorConfig } from "../src/check.ts";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, sha256Hex } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { AGENT_HEADER, ARRIVAL_FACT, CLASS_HEADER, RECEIPT_HEADER, createDoorHost, matchRoute, serveDoor, type Arrival, type DoorHost, type RunningDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { LogSink } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";

let origin: Origin;
let fx: DoorFixture;
let host: DoorHost;
let door: RunningDoor;

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const receipt = (id: string | null) => JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
const verified = (bundle: ReceiptBundle) => verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
const grantFor = (agent: string, scopes: string[], key = fx.principalKey, ttlMs = 3600_000) => createDelegation(key, { version: "0.1", principal: "shop-owner", agent, scopes, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + ttlMs).toISOString() });
const call = async (method: string, path: string, init: { headers?: Record<string, string>; body?: unknown } = {}) => {
  const res = await fetch(`${door.url}${path}`, { method, headers: { ...(init.body !== undefined ? { "content-type": "application/json" } : {}), ...(init.headers ?? {}) }, ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}) });
  const text = await res.text();
  const id = res.headers.get(RECEIPT_HEADER);
  const bundle = receipt(id);
  const st = decode(bundle);
  return { res, text, id, bundle, st, p: st.predicate, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival };
};

beforeAll(async () => {
  origin = await startOrigin();
  fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-")), origin.url);
  host = await createDoorHost(loadDoorConfig(fx.configFile));
  door = await serveDoor(host, { port: 0, log: () => {} });
}, 60_000);

afterAll(async () => {
  await door?.close();
  await host?.close();
  await origin?.close();
});

describe("routes", () => {
  const routes = [{ name: "catalogue", methods: ["GET" as const], path: "/catalogue/*" }, { name: "refund", methods: ["POST" as const], path: "/refunds" }, { name: "api", path: "/api/*" }];
  it("the first matching route wins: exact, prefix, method, and the unmatched name otherwise", () => {
    expect(matchRoute(routes, "other", "GET", "/catalogue/shoes")).toBe("catalogue");
    expect(matchRoute(routes, "other", "GET", "/catalogue")).toBe("catalogue");
    expect(matchRoute(routes, "other", "POST", "/catalogue/shoes")).toBe("other");
    expect(matchRoute(routes, "other", "POST", "/refunds")).toBe("refund");
    expect(matchRoute(routes, "other", "POST", "/refunds/1")).toBe("other");
    expect(matchRoute(routes, "other", "DELETE", "/api/orders/1")).toBe("api");
    expect(matchRoute(routes, "other", "GET", "/")).toBe("other");
  });
});

describe("the door", () => {
  it("an unknown arrival reads the catalogue: relayed, receipted as door/unknown with a claimed principal, and the receipt verifies", async () => {
    const r = await call("GET", "/catalogue/shoes?size=9&size=10&colour=red");
    expect(r.res.status).toBe(200);
    expect(r.res.headers.get(CLASS_HEADER)).toBe("unknown");
    expect(r.res.headers.get("x-origin")).toBe("shop");
    expect(JSON.parse(r.text)).toMatchObject({ ok: true, method: "GET", path: "/catalogue/shoes?size=9&size=10&colour=red" });
    expect(r.p.issuer).toMatchObject({ kind: "door", framework: "http" });
    expect(r.p.principal).toEqual({ id: null, provenance: "claimed" });
    expect(r.p.agent).toEqual({ id: "unknown", provenance: "claimed" });
    expect(r.p.delegation).toBeUndefined();
    expect(r.p.tool).toEqual({ name: "catalogue", provenance: "observed" });
    expect(r.p.request.args).toMatchObject({ method: "GET", path: "/catalogue/shoes", query: { size: ["9", "10"], colour: "red" }, bodyBytes: 0 });
    expect(r.arrival).toMatchObject({ class: "unknown", subject: "unknown", grant: "absent", signature: false, route: "catalogue" });
    expect(r.p.policy).toMatchObject({ decision: "allow", provenance: "observed" });
    expect(r.p.execution).toMatchObject({ status: "executed", provenance: "observed" });
    const v = verified(r.bundle);
    expect(v.checks.filter((c) => !c.ok)).toEqual([]);
    expect(v.checks.map((c) => c.name)).toContain("door receipt carries a policy decision");
    expect(v.checks.map((c) => c.name)).toContain("principal is claimed, not attested");
    // what the origin saw: the arrival's address and the receipt id travel with the relayed request
    const seen = origin.seen.at(-1)!;
    expect(seen.headers[RECEIPT_HEADER]).toBe(r.id);
    expect(seen.headers[CLASS_HEADER]).toBe("unknown");
    expect(seen.headers["x-forwarded-for"]).toBe("127.0.0.1");
  });

  it("an unknown arrival asking for a refund is refused with 403 and a denied receipt that verifies; nothing reached the origin", async () => {
    const before = origin.seen.length;
    const r = await call("POST", "/refunds", { body: { order: "o_1", amount: 1000 } });
    expect(r.res.status).toBe(403);
    expect(JSON.parse(r.text)).toMatchObject({ error: "refused by the door's policy", receipt: r.id });
    expect(r.p.execution).toMatchObject({ status: "denied" });
    expect(r.p.request.args).toMatchObject({ body: { order: "o_1", amount: 1000 }, bodyDigest: sha256Hex(JSON.stringify({ order: "o_1", amount: 1000 })) });
    expect(verified(r.bundle).ok).toBe(true);
    expect(origin.seen.length).toBe(before);
  });

  it("a verified agent refunds within the policy: the grant is the passport, the principal and agent are attested, and the grant does not reach the origin", async () => {
    const grant = grantFor("shopping-agent", ["refund", "api"]);
    const r = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grant)}` }, body: { order: "o_2", amount: 4500 } });
    expect(r.res.status).toBe(200);
    expect(r.res.headers.get(CLASS_HEADER)).toBe("verified");
    expect(r.p.principal).toMatchObject({ id: "shop-owner", provenance: "attested" });
    expect(r.p.agent).toEqual({ id: "shopping-agent", provenance: "attested" });
    expect(r.p.delegation).toMatchObject({ provenance: "attested" });
    expect(r.arrival).toMatchObject({ class: "verified", subject: "shopping-agent", grant: "verified" });
    const v = verified(r.bundle);
    expect(v.checks.filter((c) => !c.ok)).toEqual([]);
    expect(v.checks.map((c) => c.name)).toContain("delegation binds principal and agent");
    expect(v.checks.map((c) => c.name)).toContain("executed tool within delegated scope");
    expect(origin.seen.at(-1)!.headers.authorization).toBeUndefined();
    expect(JSON.parse(origin.seen.at(-1)!.body)).toEqual({ order: "o_2", amount: 4500 });
  });

  it("the same verified agent is refused above the limit, at zero, and below zero: a bound has two ends", async () => {
    const grant = grantFor("shopping-agent", ["refund"]);
    for (const amount of [9000, 0, -1, -5000]) {
      const r = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grant)}` }, body: { order: "o_3", amount } });
      expect(r.res.status, `amount ${amount}`).toBe(403);
      expect(r.arrival.class).toBe("verified");
      expect(r.p.execution).toMatchObject({ status: "denied" });
      expect(r.p.authorization).toBeUndefined();
      expect(verified(r.bundle).ok).toBe(true);
    }
  });

  it("a request that can change something is committed to the log before it is relayed; a read is not", async () => {
    const refund = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"]))}` }, body: { order: "o_7", amount: 100 } });
    expect(refund.res.status).toBe(200);
    expect(refund.p.authorization).toBeDefined();
    const v = verified(refund.bundle);
    expect(v.checks.filter((c) => !c.ok)).toEqual([]);
    expect(v.checks.map((c) => c.name)).toEqual(expect.arrayContaining(["authorization names this call", "authorization log inclusion proof", "authorization logged before execution"]));
    expect(refund.p.authorization!.inclusion.leafIndex).toBeLessThan(refund.bundle.inclusion.leafIndex);
    // the committed statement is on disk in its own right, as evidence should the receipt never be written
    const committed = JSON.parse(readFileSync(join(fx.receiptsDir, `${refund.id}.authorization.json`), "utf8")) as ReceiptBundle;
    expect(decode(committed).predicate.receiptId).toBe(refund.id);
    const read = await call("GET", "/catalogue/socks");
    expect(read.p.authorization).toBeUndefined();
  });

  it("a route named in precommit is committed whatever the method", async () => {
    const pre = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-precommit-")), origin.url, { precommit: ["catalogue"] });
    const h = await createDoorHost(loadDoorConfig(pre.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/catalogue/socks`);
      expect(res.status).toBe(200);
      const bundle = JSON.parse(readFileSync(join(pre.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(bundle).predicate.authorization).toBeDefined();
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(pre.doorPub)], principalKeys: [] }).ok).toBe(true);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("when the log will not commit the request, it is not relayed: 503 and a withheld receipt in the outbox; observe mode relays and says so", async () => {
    const refusing: LogSink = { kind: "file", where: "refusing", append: async () => { throw new Error("the log is full"); } };
    const dir = mkdtempSync(join(tmpdir(), "agent-custody-door-refused-"));
    const fxr = buildDoorFixture(dir, origin.url);
    const h = await createDoorHost(loadDoorConfig(fxr.configFile), { log: refusing });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const before = origin.seen.length;
    try {
      const res = await fetch(`${d.url}/refunds`, { method: "POST", headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"], fxr.principalKey))}`, "content-type": "application/json" }, body: JSON.stringify({ order: "o_8", amount: 100 }) });
      expect(res.status).toBe(503);
      expect(res.headers.get("x-agent-custody-log-pending")).toBe("true");
      expect(origin.seen.length).toBe(before);
      const outbox = JSON.parse(readFileSync(join(fxr.receiptsDir, "outbox", `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as { envelope: ReceiptBundle["envelope"] };
      expect(decode({ envelope: outbox.envelope } as ReceiptBundle).predicate.execution).toMatchObject({ status: "withheld", reason: expect.stringContaining("the log did not commit") });
    } finally {
      await d.close();
      await h.close();
    }
    const errors: string[] = [];
    const quiet = console.error;
    console.error = (m: string) => { errors.push(String(m)); };
    const obs = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-refused-observe-")), origin.url, { mode: "observe" });
    const ho = await createDoorHost(loadDoorConfig(obs.configFile), { log: refusing });
    const dobs = await serveDoor(ho, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${dobs.url}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ order: "o_8b", amount: 100 }) });
      expect(res.status).toBe(200);
      expect(origin.seen.length).toBe(before + 1);
      expect(errors.some((e) => e.includes("observe mode") && e.includes("relayed without it"))).toBe(true);
    } finally {
      console.error = quiet;
      await dobs.close();
      await ho.close();
    }
  });

  it("a redirect to the origin's own address is rewritten to a path, so the client's next request passes the door too", async () => {
    const res = await fetch(`${door.url}/catalogue/redirect`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/catalogue/after?from=redirect");
    expect(decode(receipt(res.headers.get(RECEIPT_HEADER))).predicate.execution).toMatchObject({ status: "executed", result: { status: 302 } });
  });

  it("a grant from a stranger, an expired grant, and a grant for other routes leave the arrival claimed and refused, with the reason in the arrival fact", async () => {
    const stranger = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"], generateKeyPair()))}` }, body: { order: "o_4", amount: 100 } });
    expect(stranger.res.status).toBe(403);
    expect(stranger.arrival).toMatchObject({ class: "claimed", subject: "shopping-agent", grant: "invalid" });
    expect(stranger.p.principal).toEqual({ id: null, provenance: "claimed" });
    expect(stranger.p.agent).toEqual({ id: "shopping-agent", provenance: "claimed" });
    expect(verified(stranger.bundle).ok).toBe(true);

    const expired = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"], fx.principalKey, -1))}` }, body: { order: "o_5", amount: 100 } });
    expect(expired.arrival).toMatchObject({ class: "claimed", grant: "invalid" });
    expect(expired.arrival.grantError).toMatch(/window/);

    const elsewhere = await call("POST", "/refunds", { headers: { [`x-agent-custody-grant`]: grantHeader(grantFor("read-agent", ["api"])) }, body: { order: "o_6", amount: 100 } });
    expect(elsewhere.res.status).toBe(403);
    expect(elsewhere.arrival).toMatchObject({ class: "claimed", subject: "read-agent", grant: "out-of-scope" });
    expect(elsewhere.p.delegation).toBeUndefined();
    expect(verified(elsewhere.bundle).ok).toBe(true);
  });

  it("a declared name without a grant is claimed: it may read the catalogue and is refused the API", async () => {
    const read = await call("GET", "/catalogue/hats", { headers: { [AGENT_HEADER]: "crawler-7" } });
    expect(read.res.status).toBe(200);
    expect(read.arrival).toMatchObject({ class: "claimed", subject: "crawler-7", declared: "crawler-7", grant: "absent" });
    expect(read.p.agent).toEqual({ id: "crawler-7", provenance: "claimed" });
    const api = await call("GET", "/api/orders", { headers: { [AGENT_HEADER]: "crawler-7" } });
    expect(api.res.status).toBe(403);
    expect(verified(api.bundle).ok).toBe(true);
  });

  it("a permit that names an agent is satisfied by that agent's verified grant alone, never by a declared name or a rejected grant; `check` warns about the permit", async () => {
    const named = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-named-")), origin.url);
    writeFileSync(join(named.dir, "policy.cedar"), 'permit(principal == Agent::"crawler-7", action == Action::"api", resource);\n');
    const h = await createDoorHost(loadDoorConfig(named.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const declared = await fetch(`${d.url}/api/orders`, { headers: { [AGENT_HEADER]: "crawler-7" } });
      expect(declared.status).toBe(403);
      const forged = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-7", ["api"], generateKeyPair()))}` } });
      expect(forged.status).toBe(403);
      const elsewhere = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-7", ["refund"], named.principalKey))}` } });
      expect(elsewhere.status).toBe(403);
      const real = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-7", ["api"], named.principalKey))}` } });
      expect(real.status).toBe(200);
    } finally {
      await d.close();
      await h.close();
    }
    const warnings = checkDoorConfig(named.configFile).filter((f) => f.level === "warn" && f.check === "policy").map((f) => f.message);
    expect(warnings.some((m) => m.includes('Agent::"crawler-7"') && m.includes('arrival.class == "verified"'))).toBe(true);
    expect(checkDoorConfig(fx.configFile).filter((f) => f.level === "warn" && f.check === "policy")).toEqual([]);
  });

  it("an arrival at no configured route is the unmatched action and the policy refuses it", async () => {
    const r = await call("GET", "/admin");
    expect(r.res.status).toBe(403);
    expect(r.p.tool.name).toBe("other");
  });

  it("the origin answering 500 is a failed receipt; the status is relayed", async () => {
    const r = await call("GET", "/api/broken", { headers: { authorization: `Bearer ${grantHeader(grantFor("ops-agent", ["api"]))}` } });
    expect(r.res.status).toBe(500);
    expect(r.p.execution).toMatchObject({ status: "failed", result: { status: 500 } });
    expect(verified(r.bundle).ok).toBe(true);
  });

  it("the policy decides before the body limit: an oversized body on a refused route is denied, on an allowed route it is withheld with 413, and both receipts verify", async () => {
    const small = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-small-")), origin.url, { maxBodyBytes: 64 });
    const h = await createDoorHost(loadDoorConfig(small.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const check = (bundle: ReceiptBundle) => verifyBundle(bundle, { issuerKeys: [loadPublicKey(small.doorPub)], principalKeys: [loadPublicKey(small.principalPub)], logFile: small.logFile });
    const before = origin.seen.length;
    try {
      const big = JSON.stringify({ pad: "x".repeat(200) });
      const refused = await fetch(`${d.url}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: big });
      expect(refused.status).toBe(403);
      const denied = JSON.parse(readFileSync(join(small.receiptsDir, `${refused.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(denied).predicate.execution).toMatchObject({ status: "denied" });
      expect(decode(denied).predicate.request.args).toMatchObject({ bodyOversized: true });
      expect(decode(denied).predicate.request.args).not.toHaveProperty("bodyDigest");
      expect(check(denied).checks.filter((c) => !c.ok)).toEqual([]);

      const grant = grantHeader(grantFor("ops-agent", ["api"], small.principalKey));
      const allowed = await fetch(`${d.url}/api/orders`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${grant}` }, body: big });
      expect(allowed.status).toBe(413);
      const withheld = JSON.parse(readFileSync(join(small.receiptsDir, `${allowed.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(withheld).predicate.policy).toMatchObject({ decision: "allow" });
      expect(decode(withheld).predicate.execution).toMatchObject({ status: "withheld" });
      expect(decode(withheld).predicate.authorization).toBeUndefined();
      expect(check(withheld).checks.filter((c) => !c.ok)).toEqual([]);
      expect(origin.seen.length).toBe(before);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("the origin down is an error receipt and a 502", async () => {
    const dead = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-dead-")), "http://127.0.0.1:9", { origin: { url: "http://127.0.0.1:9", timeoutMs: 2000 } });
    const h = await createDoorHost(loadDoorConfig(dead.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/catalogue/x`);
      expect(res.status).toBe(502);
      const bundle = JSON.parse(readFileSync(join(dead.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(bundle).predicate.execution).toMatchObject({ status: "error" });
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(dead.doorPub)], principalKeys: [] }).ok).toBe(true);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("observe mode relays what the policy would refuse and marks the decision unenforced", async () => {
    const obs = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-observe-")), origin.url, { mode: "observe" });
    const h = await createDoorHost(loadDoorConfig(obs.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ order: "o_9", amount: 100 }) });
      expect(res.status).toBe(200);
      const bundle = JSON.parse(readFileSync(join(obs.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      const p = decode(bundle).predicate;
      expect(p.policy).toMatchObject({ decision: "deny", enforced: false });
      expect(p.execution.status).toBe("executed");
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(obs.doorPub)], principalKeys: [] }).ok).toBe(true);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("a policy change on disk applies to the next arrival; one that does not parse is refused and the policy in force stays", async () => {
    const before = host.policyDigest();
    const policyFile = join(fx.dir, "policy.cedar");
    const original = readFileSync(policyFile, "utf8");
    writeFileSync(policyFile, "permit(principal, action == Action::\"other\", resource);\n");
    const opened = await call("GET", "/admin");
    expect(opened.res.status).toBe(200);
    expect(host.policyDigest()).not.toBe(before);
    writeFileSync(policyFile, "permit(principal, action == Action::\"other\" resource;\n");
    const still = await call("GET", "/admin");
    expect(still.res.status).toBe(200);
    writeFileSync(policyFile, original);
    const closed = await call("GET", "/admin");
    expect(closed.res.status).toBe(403);
    expect(host.policyDigest()).toBe(before);
  });

  it("`check` recognises a door config and reports what the door would fail on", () => {
    expect(isDoorConfig(fx.configFile)).toBe(true);
    const good = checkDoorConfig(fx.configFile);
    expect(good.filter((f) => f.level === "error")).toEqual([]);
    expect(good.map((f) => f.check)).toEqual(expect.arrayContaining(["config", "key", "principal keys", "policy", "routes", "origin", "paths"]));
    const broken = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-check-")), origin.url, { routs: [], trustedPrincipalKeys: [], origin: { url: "http://shop.example", headerEnv: { "x-secret": "DOOR_TEST_UNSET_VARIABLE" } }, splunk: { url: "https://splunk.example:8088", tokenEnv: "DOOR_TEST_UNSET_SPLUNK" }, otel: { url: "https://otel.example", headersEnv: { authorization: "DOOR_TEST_UNSET_OTEL" } } });
    writeFileSync(join(broken.dir, "policy.cedar"), "permit(principal, action, resource");
    const findings = checkDoorConfig(broken.configFile);
    const messages = findings.filter((f) => f.level === "error").map((f) => `${f.check}: ${f.message}`);
    expect(messages.some((m) => m.startsWith("config: unknown key \"routs\"") && m.includes("routes"))).toBe(true);
    expect(messages.some((m) => m.startsWith("policy:"))).toBe(true);
    expect(messages.some((m) => m.startsWith("credentials:") && m.includes("DOOR_TEST_UNSET_VARIABLE"))).toBe(true);
    expect(messages.some((m) => m.startsWith("credentials:") && m.includes("DOOR_TEST_UNSET_SPLUNK"))).toBe(true);
    expect(messages.some((m) => m.startsWith("credentials:") && m.includes("DOOR_TEST_UNSET_OTEL"))).toBe(true);
    expect(good.map((f) => f.check)).toContain("precommit");
    expect(findings.filter((f) => f.level === "warn").map((f) => f.check)).toEqual(expect.arrayContaining(["principal keys", "origin"]));
  });

  it("the well-known endpoint names the key and the policy", async () => {
    const res = await fetch(`${door.url}/.well-known/agent-custody-door`);
    expect(await res.json()).toMatchObject({ keyid: host.keyid, policyDigest: host.policyDigest() });
  });
});
