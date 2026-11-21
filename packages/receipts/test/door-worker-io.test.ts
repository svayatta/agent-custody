// What the Worker door builds its I/O from, tested in Node where a store can be made to fail on cue. The bucket is the
// only place a Worker's receipts live: if it cannot take a precommit's authorization the request must not go on, and a
// receipt whose log append failed must survive in the outbox until the log takes it.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { digestOf, generateKeyPair, publicKeyToPem } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { createDoorCoreWith, relayToOrigin, type DoorIO, type DoorRequest } from "../src/door-core.ts";
import { CLOUDFLARE_FACT, cloudflareFacts, pemKeys, r2Store, workerDoorConfig, type DoorWorkerEnv, type R2BucketLike } from "../src/door-worker.ts";
import { grantHeader } from "../src/grant-header.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import { createObjectIssuer, type ObjectStore } from "../src/object-issuer.ts";
import type { ReceiptBundle, ReceiptPredicate } from "../src/receipt.ts";
import { ReceiptPending } from "../src/receipt-pending.ts";
import { verifyBundle } from "../src/verify.ts";

const issuerKey = generateKeyPair();

function memoryStore(failPuts = () => false) {
  const objects = new Map<string, string>();
  const store: ObjectStore = {
    put: async (k, v) => { if (failPuts()) throw new Error("R2 is unavailable"); objects.set(k, v); },
    get: async (k) => objects.get(k) ?? null,
    list: async (p) => [...objects.keys()].filter((k) => k.startsWith(p)).sort(),
    delete: async (k) => void objects.delete(k),
  };
  return { store, objects };
}

const predicate = (receiptId: string, keyid = issuerKey.keyid, args: Record<string, unknown> = { method: "GET", path: "/p", query: { q: "secret" } }): ReceiptPredicate => ({
  receiptId,
  timestamp: new Date().toISOString(),
  issuer: { kind: "door", keyid, version: "0.1.0" },
  principal: { id: null, provenance: "claimed" },
  agent: { id: "unknown", provenance: "claimed" },
  session: { id: null, toolUseId: null, provenance: "claimed" },
  model: { id: null, provenance: "claimed" },
  tool: { name: "catalogue", provenance: "observed" },
  request: { args, argsDigest: digestOf(args), provenance: "claimed" },
  facts: {},
  policy: { decision: "allow", reasons: [], errors: [], policyDigest: "p", provenance: "observed" },
  execution: { status: "executed", result: { status: 200 }, resultDigest: digestOf({ status: 200 }), provenance: "observed" },
});

describe("the object issuer", () => {
  const key = issuerKey;
  const logFile = () => join(mkdtempSync(join(tmpdir(), "obj-issuer-")), "log.jsonl");

  it("stores a bundle only after the log took it, with the salts of its withheld values beside it, and the bundle verifies", async () => {
    const { store, objects } = memoryStore();
    const file = logFile();
    const issuer = createObjectIssuer(key, store, fileLog(file, key), { capture: { rules: { "*": { args: { mode: "digest", clear: ["method", "path"] } } } } });
    const id = crypto.randomUUID();
    const bundle = await issuer.issue(predicate(id));
    expect(JSON.parse(objects.get(`${id}.json`)!)).toEqual(bundle);
    expect(verifyBundle(bundle, { issuerKeys: [key], principalKeys: [], logFile: file }).ok).toBe(true);
    // the arguments outside `clear` (the query) were withheld, so their salt is kept for a later disclosure, in the store and never in the receipt
    expect(Object.keys(JSON.parse(objects.get(`salts/${id}.json`)!).salts)).toContain(JSON.stringify(["request", "args", "$rest"]));
    expect(objects.get(`${id}.json`)).not.toContain("secret");
  });

  it("keeps a receipt whose log append failed in the outbox, signed, and a flush appends it and writes the bundle", async () => {
    const { store, objects } = memoryStore();
    let down = true;
    const real = fileLog(logFile(), key);
    const sink: LogSink = { kind: "http", where: "test", append: async (leaf) => { if (down) throw new Error("log unreachable"); return real.append(leaf); } };
    const issuer = createObjectIssuer(key, store, sink);
    const id = crypto.randomUUID();
    await expect(issuer.issue(predicate(id), undefined, undefined, { deferLog: true })).rejects.toBeInstanceOf(ReceiptPending);
    expect(objects.has(`outbox/${id}.json`)).toBe(true);
    expect(objects.has(`${id}.json`)).toBe(false);
    expect(issuer.pending()).toBe(1);
    expect(await issuer.flushOutbox()).toMatchObject({ sent: 0, pending: 1, error: "log unreachable" });
    down = false;
    expect(await issuer.flushOutbox()).toMatchObject({ sent: 1, pending: 0 });
    expect(objects.has(`outbox/${id}.json`)).toBe(false);
    expect(verifyBundle(JSON.parse(objects.get(`${id}.json`)!) as ReceiptBundle, { issuerKeys: [key], principalKeys: [] }).ok).toBe(true);
  });

  it("without deferLog, a refused append rejects and stores nothing", async () => {
    const { store, objects } = memoryStore();
    const issuer = createObjectIssuer(key, store, { kind: "http", where: "test", append: async () => { throw new Error("refused"); } });
    await expect(issuer.issue(predicate(crypto.randomUUID()))).rejects.toThrow("refused");
    expect(objects.size).toBe(0);
  });

  it("sets aside an outbox entry it cannot trust, and leaves one signed by another key", async () => {
    const { store, objects } = memoryStore();
    const other = generateKeyPair();
    const otherIssuer = createObjectIssuer(other, store, { kind: "http", where: "t", append: async () => { throw new Error("down"); } });
    const foreignId = crypto.randomUUID();
    await otherIssuer.issue(predicate(foreignId, other.keyid), undefined, undefined, { deferLog: true }).catch(() => {});
    const damagedId = crypto.randomUUID();
    objects.set(`outbox/${damagedId}.json`, "{not json");
    const issuer = createObjectIssuer(key, store, fileLog(logFile(), key));
    expect(await issuer.flushOutbox()).toMatchObject({ sent: 0, setAside: 1, foreign: 1, pending: 1 });
    expect(objects.has(`outbox/${damagedId}.json.bad`)).toBe(true);
    expect(objects.has(`outbox/${foreignId}.json`)).toBe(true);
  });

  it("refuses a receipt id that is not one the door mints, before anything is signed or stored", async () => {
    const { store, objects } = memoryStore();
    const issuer = createObjectIssuer(key, store, fileLog(logFile(), key));
    await expect(issuer.issue(predicate("../escape"))).rejects.toThrow(/not a valid id/);
    expect(objects.size).toBe(0);
  });
});

describe("a precommit route when the bucket is unavailable", () => {
  it("is not relayed: the authorization cannot be stored, so the request does not go on", async () => {
    const key = generateKeyPair();
    const principal = generateKeyPair();
    const dir = mkdtempSync(join(tmpdir(), "worker-r2-down-"));
    const { store } = memoryStore(() => true);
    const env = baseEnv({ DOOR_CONFIG: JSON.stringify({ routes: [{ name: "orders", path: "/orders", methods: ["POST"] }], precommit: ["orders"] }) });
    const cfg = workerDoorConfig(env);
    const reached: string[] = [];
    const origin: typeof fetch = async (u) => { reached.push(String(u)); return new Response("ok"); };
    const io: DoorIO = {
      key,
      trustedPrincipalKeys: [principal],
      readPolicy: () => ({ text: `permit(principal, action == Action::"orders", resource);`, key: "v" }),
      policySource: "test",
      revoked: () => null,
      secret: () => undefined,
      issuer: (capture) => createObjectIssuer(key, store, fileLog(join(dir, "log.jsonl"), key), { capture }),
      fetch: origin,
      timers: false,
    };
    const core = createDoorCoreWith(cfg, io, "cloudflare-worker");
    const req: DoorRequest = { method: "POST", url: "/orders", headers: { host: "shop.test", "x-agent-custody-grant": grantHeader(createDelegation(principal, { version: "0.1", principal: "owner", agent: "bot", scopes: ["orders"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() })) }, socket: { remoteAddress: "203.0.113.1" } };
    const d = await core.decide(req, crypto.randomUUID(), async () => ({ body: Buffer.from("{}") }));
    expect(d.refused).toMatchObject({ status: 503, execution: { status: "withheld", reason: expect.stringMatching(/R2 is unavailable/) } });
    await relayToOrigin(core, cfg, d, req, { url: new URL("https://origin.test"), headers: {}, timeoutMs: 1000, proto: "https" }, origin);
    expect(reached).toEqual([]);
    core.close();
  });
});

function baseEnv(over: Partial<DoorWorkerEnv> = {}): DoorWorkerEnv {
  return {
    DOOR_CONFIG: JSON.stringify({ routes: [] }),
    DOOR_POLICY: "permit(principal, action, resource);",
    ORIGIN_URL: "https://origin.test",
    LOG_URL: "https://log.test/",
    LOG_KEYS: publicKeyToPem(generateKeyPair().publicKey),
    DOOR_KEY: "unused here",
    RECEIPTS: {} as R2BucketLike,
    ...over,
  };
}

describe("the Worker's config", () => {
  it("is checked by the door's own schema, with the origin and the log from their variables", () => {
    const cfg = workerDoorConfig(baseEnv({ DOOR_CONFIG: JSON.stringify({ routes: [{ name: "api", path: "/api/*" }], precommit: ["api"], origin: { timeoutMs: 5000 } }), LOG_ID: "acme" }));
    expect(cfg).toMatchObject({ origin: { url: "https://origin.test", timeoutMs: 5000 }, log: { url: "https://log.test/", logId: "acme" }, precommit: ["api"], maxBodyBytes: 1024 * 1024 });
  });

  it("refuses every field that names a file or a mode a Worker does not have, saying where it comes from instead", () => {
    const cases: [Record<string, unknown>, RegExp][] = [
      [{ policyFile: "p.cedar" }, /policyFile.*DOOR_POLICY variable/],
      [{ identity: { keyFile: "k" } }, /identity.*DOOR_KEY secret/],
      [{ trustedPrincipalKeys: ["a.pub"] }, /TRUSTED_PRINCIPAL_KEYS/],
      [{ revokedGrants: "r.json" }, /REVOKED_GRANTS/],
      [{ authz: true }, /authz/],
      [{ trustProxy: true }, /CF-Connecting-IP/],
      [{ origin: { url: "https://elsewhere" } }, /ORIGIN_URL/],
    ];
    for (const [extra, why] of cases) expect(() => workerDoorConfig(baseEnv({ DOOR_CONFIG: JSON.stringify({ routes: [], ...extra }) }))).toThrow(why);
  });

  it("names a missing binding", () => {
    expect(() => workerDoorConfig(baseEnv({ DOOR_POLICY: "" }))).toThrow(/needs DOOR_POLICY/);
    expect(() => workerDoorConfig({ ...baseEnv(), RECEIPTS: undefined as unknown as R2BucketLike })).toThrow(/RECEIPTS bucket/);
  });

  it("reads every public key in a variable", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(pemKeys(`${publicKeyToPem(a.publicKey)}\n${publicKeyToPem(b.publicKey)}`).map((k) => k.keyid)).toEqual([a.keyid, b.keyid]);
    expect(pemKeys("")).toEqual([]);
  });
});

describe("Cloudflare Bot Management", () => {
  it("enters only when the zone scored the request with the documented types, never from anything else in cf", () => {
    expect(cloudflareFacts(undefined)).toEqual({});
    expect(cloudflareFacts({})).toEqual({});
    expect(cloudflareFacts({ botManagement: { score: "99", verifiedBot: false } })).toEqual({});
    expect(cloudflareFacts({ botManagement: { score: 9.5, verifiedBot: false } })).toEqual({});
    expect(cloudflareFacts({ botManagement: { score: 12, verifiedBot: true } })).toEqual({ [CLOUDFLARE_FACT]: { tool: "cloudflare.botManagement", value: { score: 12, verifiedBot: true } } });
  });
});

describe("the R2 store", () => {
  it("follows the bucket's cursor to the end of a listing", async () => {
    const pages = [{ objects: [{ key: "outbox/a.json" }], truncated: true, cursor: "c1" }, { objects: [{ key: "outbox/b.json" }], truncated: false }];
    const seen: (string | undefined)[] = [];
    const bucket: R2BucketLike = { put: async () => undefined, get: async () => null, delete: async () => undefined, list: async (o) => { seen.push(o.cursor); return pages[seen.length - 1]!; } };
    expect(await r2Store(bucket).list("outbox/")).toEqual(["outbox/a.json", "outbox/b.json"]);
    expect(seen).toEqual([undefined, "c1"]);
  });
});
