// The door's decision runs wherever it is given a key, a policy, a revocation list, secrets, and an issuer. A Worker has
// no files: if the core read one, the edge door could not exist, and if its I/O changed what is decided, a receipt from
// the edge would not mean what a receipt from the Node door means. So these tests drive the core from memory alone.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DoorConfigSchema, type DoorConfig } from "../src/config.ts";
import { generateKeyPair, type KeyPair } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { ARRIVAL_FACT, createDoorCoreWith, createRateTracker, relayedAnswer, relayToOrigin, type Arrival, type DoorIO, type DoorRequest, type OriginTarget } from "../src/door-core.ts";
import { grantHeader } from "../src/grant-header.ts";
import { createIssuer } from "../src/issue.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";

const POLICY = `permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"refund", resource) when { context.facts.arrival.class == "verified" };`;

function setup(over: Partial<DoorIO> = {}, cfgOver: Record<string, unknown> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "door-core-"));
  const key = generateKeyPair();
  const principal = generateKeyPair();
  // the file fields are never read by the core: only nodeDoorIO reads them
  const cfg: DoorConfig = DoorConfigSchema.parse({ identity: { keyFile: "unread" }, policyFile: "unread", receiptsDir: join(dir, "receipts"), logFile: join(dir, "log.jsonl"), routes: [{ name: "catalogue", path: "/products/*", methods: ["GET"] }, { name: "refund", path: "/refunds", methods: ["POST"] }], ...cfgOver });
  const reached: string[] = [];
  const origin: typeof fetch = async (input) => { reached.push(String(input)); return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }); };
  const io: DoorIO = {
    key,
    trustedPrincipalKeys: [principal],
    readPolicy: () => ({ text: POLICY, key: "v1" }),
    policySource: "the test's policy",
    revoked: () => null,
    secret: () => undefined,
    issuer: (capture) => createIssuer(key, cfg.receiptsDir, cfg.logFile!, { capture }),
    fetch: origin,
    timers: false,
    ...over,
  };
  return { cfg, io, key, principal, reached, origin, dir };
}

const request = (method: string, url: string, headers: Record<string, string> = {}): DoorRequest => ({ method, url, headers: { host: "shop.example", ...headers }, socket: { remoteAddress: "203.0.113.9" } });
const target: OriginTarget = { url: new URL("https://origin.example"), headers: {}, timeoutMs: 5000, proto: "https" };
const grantFor = (principal: KeyPair, scopes: string[]) => grantHeader(createDelegation(principal, { version: "0.1", principal: "shop-owner", agent: "buyer-bot", scopes, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() }));
const statementOf = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

async function arrive(s: ReturnType<typeof setup>, req: DoorRequest, body = "") {
  const core = createDoorCoreWith(s.cfg, s.io, "test");
  const d = await core.decide(req, crypto.randomUUID(), async () => ({ body: Buffer.from(body) }));
  const relayed = await relayToOrigin(core, s.cfg, d, req, target, s.origin);
  const recorded = await core.record(d, relayed.execution);
  const answer = relayedAnswer(core, s.cfg, d, relayed, recorded!.logPending);
  core.close();
  return { d, answer, arrival: d.arrival };
}

describe("the door core over a DoorIO", () => {
  it("refuses an unknown arrival on a protected route without reaching the origin, and allows a verified one whose receipt verifies", async () => {
    const s = setup();
    const refused = await arrive(s, request("POST", "/refunds", { "content-type": "application/json" }), '{"order":"o-1"}');
    expect(refused.answer.status).toBe(403);
    expect(refused.arrival.class).toBe("unknown");
    expect(s.reached).toEqual([]);

    const allowed = await arrive(s, request("POST", "/refunds", { "content-type": "application/json", "x-agent-custody-grant": grantFor(s.principal, ["refund"]) }), '{"order":"o-1"}');
    expect(allowed.answer.status).toBe(200);
    expect(allowed.arrival).toMatchObject({ class: "verified", subject: "buyer-bot", grant: "verified" });
    expect(s.reached).toEqual(["https://origin.example/refunds"]);
    const bundle = JSON.parse(readFileSync(join(s.cfg.receiptsDir, `${allowed.d.receiptId}.json`), "utf8")) as ReceiptBundle;
    const result = verifyBundle(bundle, { issuerKeys: [s.key], principalKeys: [s.principal], logFile: s.cfg.logFile! });
    expect(result.ok).toBe(true);
    expect(statementOf(bundle).predicate).toMatchObject({ issuer: { kind: "door", framework: "test" }, principal: { id: "shop-owner", provenance: "attested" }, execution: { status: "executed" } });
    // a request that can change something was committed to the log before it went on
    expect(statementOf(bundle).predicate.authorization).toBeDefined();
  });

  it("takes the revocation verdict from the IO: a grant it revokes is claimed, and its route refused", async () => {
    const s = setup({ revoked: () => "the grant has been revoked" });
    const { answer, arrival } = await arrive(s, request("POST", "/refunds", { "x-agent-custody-grant": grantFor(s.principal, ["refund"]) }));
    expect(arrival).toMatchObject({ class: "claimed", grant: "revoked", grantError: "the grant has been revoked" } satisfies Partial<Arrival>);
    expect(answer.status).toBe(403);
    expect(s.reached).toEqual([]);
  });

  it("re-reads the policy through the IO: a new key takes effect, and a text that does not parse leaves the policy in force", async () => {
    let policy = { text: POLICY, key: "v1" };
    const s = setup({ readPolicy: () => policy });
    const core = createDoorCoreWith(s.cfg, s.io, "test");
    const before = core.policyDigest();
    policy = { text: `forbid(principal, action, resource);\npermit(principal, action == Action::"catalogue", resource);`, key: "v2" };
    const changed = core.policyDigest();
    expect(changed).not.toBe(before);
    policy = { text: "permit(principal, action", key: "v3" };
    expect(core.policyDigest()).toBe(changed);
    core.close();
  });

  it("names the policy by its source when it does not parse at start", () => {
    const s = setup({ readPolicy: () => ({ text: "permit(", key: "v1" }), policySource: "the DOOR_POLICY variable" });
    expect(() => createDoorCoreWith(s.cfg, s.io, "test")).toThrow(/policy the DOOR_POLICY variable does not parse/);
  });

  it("reads the secrets the config names from the IO, and refuses a config whose secret is missing", () => {
    const cfgOver = { challenge: { provider: "turnstile", siteKey: "0x4AAA", secretEnv: "TURNSTILE_SECRET", hostnames: ["shop.example"] } };
    const missing = setup({}, cfgOver);
    expect(() => createDoorCoreWith(missing.cfg, missing.io, "test")).toThrow(/TURNSTILE_SECRET is not set/);
    const asked: string[] = [];
    const given = setup({ secret: (name) => (asked.push(name), "the-secret") }, cfgOver);
    createDoorCoreWith(given.cfg, given.io, "test").close();
    expect(asked).toContain("TURNSTILE_SECRET");
  });

  it("records the arrival fact exactly as the Node door does, under the same name", async () => {
    const s = setup();
    const { d } = await arrive(s, request("GET", "/products/42"));
    expect(d.head.facts[ARRIVAL_FACT]?.value).toMatchObject({ class: "unknown", route: "catalogue", path: "/products/42", remote: "203.0.113.9" });
  });
});

describe("the rate tracker without a timer", () => {
  it("forgets a source whose last arrival is over a minute old, from the next arrival, with no timer running", () => {
    let now = 0;
    const rates = createRateTracker(() => now, { sweepTimer: false });
    rates.hit("a");
    rates.hit("b");
    expect(rates.size()).toBe(2);
    now = 61_000;
    expect(rates.hit("a")).toEqual({ burst: 1, minute: 1 });
    // b had no arrival in the last minute, so the sweep that ran from a's arrival dropped it
    expect(rates.size()).toBe(1);
    rates.close();
  });
});
