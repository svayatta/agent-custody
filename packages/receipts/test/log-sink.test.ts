import { createServer } from "node:http";
// A remote log exists so the operator cannot rewrite history. These tests pin what that buys and what it costs.
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadSdkConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair, dsseSign, dsseVerify, publicKeyFromPem, publicKeyToPem } from "../src/crypto.ts";
import { MerkleLog } from "../src/log.ts";
import { createGateway, LOG_PENDING_META_KEY, RECEIPT_META_KEY } from "../src/gateway.ts";
import { loadConfig } from "../src/config.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { TREEHEAD_TYPE } from "../src/receipt.ts";
import { httpLog, serveLog, CheckpointPublisher, fileResolver, openLog, type RunningLog } from "../src/log-sink.ts";
import { fileBackend } from "../src/log-store.ts";
import { dirCheckpoints } from "../src/checkpoints.ts";
import { localSigner } from "../src/signer.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { auditExtends, verifyBundle } from "../src/verify.ts";

const failing = (r: ReturnType<typeof verifyBundle>) => r.checks.filter((c) => !c.ok).map((c) => c.name);
const failingAudit = (r: ReturnType<typeof auditExtends>) => r.checks.filter((c) => !c.ok).map((c) => c.name);

describe("HTTP log sink", () => {
  let dir: string;
  let log: RunningLog;
  let logPub: string;
  let appPub: string;
  let serverLogFile: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "log-sink-"));
    const logKey = writeKeyPair(generateKeyPair(), join(dir, "log-keys"), "log");
    logPub = logKey.pubFile;
    serverLogFile = join(dir, "server-log.jsonl");
    log = await serveLog(serverLogFile, loadPrivateKey(logKey.keyFile), { port: 0, tokens: ["s3cret"] });
    appPub = writeKeyPair(generateKeyPair(), join(dir, "keys"), "app").pubFile;
    process.env.TEST_LOG_TOKEN = "s3cret";
    writeFileSync(join(dir, "sdk.json"), JSON.stringify({ agentId: "bot", identity: { keyFile: "keys/app.key" }, receiptsDir: "receipts", log: { url: log.url, tokenEnv: "TEST_LOG_TOKEN" } }));
  });
  afterAll(async () => {
    await log.close();
    delete process.env.TEST_LOG_TOKEN;
  });

  it("tree heads are signed by the log's key, so a verifier needs that key and learns who runs the log", async () => {
    const issuer = createSdkIssuer(loadSdkConfig(join(dir, "sdk.json")));
    const bundle = await issuer.record({ tool: "crm.lookup", args: { id: "c1" } }, { status: "executed", result: { plan: "pro" } });
    const withLogKey = verifyBundle(bundle, { issuerKeys: [loadPublicKey(appPub)], principalKeys: [], logKeys: [loadPublicKey(logPub)], logFile: serverLogFile });
    expect(failing(withLogKey)).toEqual([]);
    expect(withLogKey.checks.find((c) => c.name === "tree head signature")?.detail).toMatch(/^log key /);
    const issuerOnly = verifyBundle(bundle, { issuerKeys: [loadPublicKey(appPub)], principalKeys: [] });
    expect(failing(issuerOnly)).toEqual(["tree head signature"]);
  });

  it("the log's own file and root endpoint agree with the tree head the issuer received", async () => {
    const issuer = createSdkIssuer(loadSdkConfig(join(dir, "sdk.json")));
    const bundle = await issuer.record({ tool: "crm.lookup", args: { id: "c2" } }, { status: "executed", result: null });
    const head = JSON.parse(Buffer.from(bundle.treeHead.payload, "base64").toString()) as { treeSize: number; rootHash: string };
    const remote = (await (await fetch(new URL(`root?size=${head.treeSize}`, log.url))).json()) as { rootHash: string };
    expect(remote.rootHash).toBe(head.rootHash);
    expect(readFileSync(serverLogFile, "utf8").trim().split("\n")).toHaveLength(head.treeSize);
  });

  it("an auditor holding two receipts asks the log for a consistency proof and learns nothing was rewritten between them", async () => {
    const issuer = createSdkIssuer(loadSdkConfig(join(dir, "sdk.json")));
    const older = await issuer.record({ tool: "t", args: { n: 1 } }, { status: "executed", result: null });
    await issuer.record({ tool: "t", args: { n: 2 } }, { status: "executed", result: null });
    const newer = await issuer.record({ tool: "t", args: { n: 3 } }, { status: "executed", result: null });
    const size = (b: typeof older) => (JSON.parse(Buffer.from(b.treeHead.payload, "base64").toString()) as { treeSize: number }).treeSize;
    const proof = (await (await fetch(new URL(`consistency?old=${size(older)}&new=${size(newer)}`, log.url))).json()) as { hashes: string[] };
    const keys = [loadPublicKey(logPub)];
    expect(auditExtends(older.treeHead, newer.treeHead, proof.hashes, keys).ok).toBe(true);
    // the same proof against a tree head signed by someone else, or the wrong way round, does not pass
    expect(failingAudit(auditExtends(older.treeHead, newer.treeHead, proof.hashes, [loadPublicKey(appPub)]))).toContain("older tree head signature");
    expect(failingAudit(auditExtends(newer.treeHead, older.treeHead, proof.hashes, keys))).toEqual(["older is not larger than newer"]);
    const head = (await (await fetch(new URL("head", log.url))).json()) as { treeHead: typeof older.treeHead };
    expect(auditExtends(newer.treeHead, head.treeHead, [], keys).ok).toBe(true);
  });

  it("a wrong token is refused and no receipt is written", async () => {
    process.env.TEST_LOG_TOKEN_WRONG = "wrong";
    const issuer = createSdkIssuer({ agentId: "bot", identity: { keyFile: join(dir, "keys", "app.key") }, receiptsDir: join(dir, "bad-receipts"), log: { url: log.url, tokenEnv: "TEST_LOG_TOKEN_WRONG" } });
    await expect(issuer.record({ tool: "t", args: {} }, { status: "executed", result: 1 })).rejects.toThrow(/401/);
  });

  it("the sink surfaces a malformed log reply instead of writing a bundle around it", async () => {
    const sink = httpLog("http://log.invalid/", { fetch: async () => new Response(JSON.stringify({ nonsense: true }), { status: 200 }) });
    await expect(sink.append("leaf")).rejects.toThrow(/malformed/);
  });

  it("an append whose answer does not verify is refused: a head signed by a stranger, a proof under a wrong root, a head for another log; a good answer passes with the keys fetched from the log itself", async () => {
    // a stand-in log that keeps a real Merkle log and answers however it is told to
    const stranger = generateKeyPair();
    const honest = generateKeyPair();
    const mlog = new MerkleLog(join(dir, "standin.jsonl"));
    let mode: "good" | "stranger" | "wrong-root" | "other-log" = "good";
    const standIn: typeof fetch = async (url) => {
      const u = String(url);
      if (u.endsWith("/.well-known/agent-custody-log.json")) return new Response(JSON.stringify({ keys: [{ keyid: honest.keyid, publicKeyPem: publicKeyToPem(honest.publicKey) }] }), { status: 200 });
      const e = mlog.append(`leaf-${mlog.size}`);
      const head = { treeSize: e.treeSize, rootHash: mode === "wrong-root" ? "00".repeat(32) : e.rootHash, timestamp: new Date().toISOString(), log: mode === "other-log" ? "someone-else" : "the-log" };
      return new Response(JSON.stringify({ inclusion: { leafIndex: e.leafIndex, treeSize: e.treeSize, hashes: e.hashes }, treeHead: dsseSign(TREEHEAD_TYPE, head, mode === "stranger" ? stranger : honest) }), { status: 200 });
    };
    // the stand-in appends its own leaf text, so a sink that hashes what it sent will only match when it sends the same
    const sinkFor = (opts: Record<string, unknown> = {}) => httpLog("http://standin.invalid/", { fetch: standIn, logId: "the-log", ...opts });
    mode = "stranger";
    await expect(sinkFor({ keys: [honest] }).append("leaf-0")).rejects.toThrow(/does not verify against its keys/);
    mode = "wrong-root";
    await expect(sinkFor({ keys: [honest] }).append("leaf-1")).rejects.toThrow(/does not place this leaf under the signed root/);
    mode = "other-log";
    await expect(sinkFor({ keys: [honest] }).append("leaf-2")).rejects.toThrow(/for log "someone-else", not "the-log"/);
    mode = "good";
    const entry = await sinkFor().append("leaf-3");
    expect(entry.inclusion.leafIndex).toBe(3);
    expect(dsseVerify(entry.treeHead, [honest]).ok).toBe(true);
  });

  it("a pre-committed call is withheld, not forwarded, when the log's answer does not verify", async () => {
    const stranger = generateKeyPair();
    const mlog = new MerkleLog(join(dir, "standin-gw.jsonl"));
    const bad = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (req.url?.endsWith("/.well-known/agent-custody-log.json")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ keys: [{ keyid: logKeyRef.keyid, publicKeyPem: publicKeyToPem(logKeyRef.publicKey) }] })); }
        const e = mlog.append(body);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ inclusion: { leafIndex: e.leafIndex, treeSize: e.treeSize, hashes: e.hashes }, treeHead: dsseSign(TREEHEAD_TYPE, { treeSize: e.treeSize, rootHash: e.rootHash, timestamp: new Date().toISOString() }, stranger) }));
      });
    });
    const logKeyRef = generateKeyPair();
    await new Promise<void>((r) => bad.listen(0, "127.0.0.1", r));
    const badUrl = `http://127.0.0.1:${(bad.address() as { port: number }).port}/`;
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "badlog-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    delete cfg.logFile;
    cfg.log = { url: badUrl };
    cfg.precommit = ["stripe.refund"];
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    // a key fetched from the log itself would vouch for whatever the log signs, so precommit needs the keys pinned
    expect(() => loadConfig(fx.configFile)).toThrow(/precommit with a remote log needs log\.keys/);
    cfg.log.keys = [writeKeyPair(logKeyRef, join(fx.dir, "keys"), "log").pubFile];
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      // the authorization is withheld, and the receipt that records the withholding cannot be logged either: nothing
      // was forwarded, no bundle was written as if the log had accepted it, and the receipt waits in the outbox
      const res = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
      expect(res.isError).toBe(true);
      expect((res.content[0] as { text: string }).text).toMatch(/^Not executed: .*does not verify against its keys/);
      expect(res._meta?.[LOG_PENDING_META_KEY]).toBe(true);
      expect(readdirSync(fx.receiptsDir)).toEqual(["outbox"]);
      expect(readdirSync(join(fx.receiptsDir, "outbox"))).toEqual([`${String(res._meta?.[RECEIPT_META_KEY])}.json`]);
      // the stand-in took both leaves, the authorization and then the receipt; the gateway believed neither answer
      expect(mlog.size).toBe(2);
    } finally {
      await gw.close();
      bad.close();
    }
  });

  it("config demands exactly one of logFile and log", () => {
    const both = join(dir, "both.json");
    writeFileSync(both, JSON.stringify({ agentId: "bot", identity: { keyFile: "keys/app.key" }, receiptsDir: "r", logFile: "l.jsonl", log: { url: "http://x/" } }));
    expect(() => loadSdkConfig(both)).toThrow(/exactly one of logFile or log/);
    const neither = join(dir, "neither.json");
    writeFileSync(neither, JSON.stringify({ agentId: "bot", identity: { keyFile: "keys/app.key" }, receiptsDir: "r" }));
    expect(() => loadSdkConfig(neither)).toThrow(/exactly one of logFile or log/);
  });

  it("a missing token variable fails at startup, not at the first receipt", () => {
    expect(() => createSdkIssuer({ agentId: "bot", identity: { keyFile: join(dir, "keys", "app.key") }, receiptsDir: join(dir, "r"), log: { url: log.url, tokenEnv: "NOT_SET_ANYWHERE" } })).toThrow(/NOT_SET_ANYWHERE/);
  });
});

describe("a log run for someone else: hash-only leaves, tenants, and log ids", () => {
  let dir: string;
  let log: RunningLog;
  let logKey: { keyFile: string; pubFile: string };
  let appPub: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "log-tenants-"));
    logKey = writeKeyPair(generateKeyPair(), join(dir, "log-keys"), "log");
    appPub = writeKeyPair(generateKeyPair(), join(dir, "keys"), "app").pubFile;
    log = await serveLog(join(dir, "default.jsonl"), loadPrivateKey(logKey.keyFile), {
      port: 0,
      logId: "default",
      tenants: { acme: { file: join(dir, "acme.jsonl"), tokens: ["acme-token"] }, globex: { file: join(dir, "globex.jsonl"), tokens: ["globex-token"], logId: "globex-eu" } },
    });
    process.env.TEST_ACME_TOKEN = "acme-token";
  });
  afterAll(async () => {
    await log.close();
    delete process.env.TEST_ACME_TOKEN;
  });

  it("with hashOnly the log never sees the receipt: the file holds hashes, and the receipt still verifies against the log's head", async () => {
    writeFileSync(join(dir, "sdk.json"), JSON.stringify({ agentId: "bot", identity: { keyFile: "keys/app.key" }, receiptsDir: "receipts", log: { url: new URL("t/acme/", log.url).toString(), tokenEnv: "TEST_ACME_TOKEN", hashOnly: true } }));
    const issuer = createSdkIssuer(loadSdkConfig(join(dir, "sdk.json")));
    const bundle = await issuer.record({ tool: "crm.lookup", args: { ssn: "SSN-111-22-3333" } }, { status: "executed", result: { plan: "pro" } });
    const file = readFileSync(join(dir, "acme.jsonl"), "utf8");
    expect(file).not.toContain("SSN-111-22-3333");
    expect(file).not.toContain("payloadType");
    expect(JSON.parse(file.trim().split("\n")[0]!)).toEqual({ hash: expect.stringMatching(/^[0-9a-f]{64}$/) });
    const keys = { issuerKeys: [loadPublicKey(appPub)], principalKeys: [], logKeys: [loadPublicKey(logKey.pubFile)] };
    expect(failing(verifyBundle(bundle, { ...keys, logFile: join(dir, "acme.jsonl") }))).toEqual([]);
    // the tree head names the tenant's log; a verifier told which log to expect checks it
    expect(failing(verifyBundle(bundle, { ...keys, logId: "acme" }))).toEqual([]);
    const wrong = verifyBundle(bundle, { ...keys, logId: "globex-eu" });
    expect(failing(wrong)).toEqual(["tree head names the expected log"]);
    expect(wrong.checks.find((c) => c.name === "tree head names the expected log")?.detail).toBe("log acme");
  });

  it("tenants are separate logs with separate tokens and ids, and the default log stays at the root paths", async () => {
    const post = (path: string, token: string | null, body: unknown) => fetch(new URL(path, log.url), { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
    expect((await post("t/globex/append", "acme-token", { leaf: "x" })).status).toBe(401);
    const g = await post("t/globex/append", "globex-token", { leafHash: "ab".repeat(32) });
    expect(g.status).toBe(200);
    const head = JSON.parse(Buffer.from(((await g.json()) as { treeHead: { payload: string } }).treeHead.payload, "base64").toString()) as { log?: string; treeSize: number };
    expect(head).toMatchObject({ log: "globex-eu", treeSize: 1 });
    expect((await post("t/nobody/append", null, { leaf: "x" })).status).toBe(404);
    expect((await post("t/acme/append", "acme-token", { leafHash: "not-hex" })).status).toBe(400);
    const d = await post("append", null, { leaf: "open default log" });
    expect(d.status).toBe(200);
    const dhead = JSON.parse(Buffer.from(((await d.json()) as { treeHead: { payload: string } }).treeHead.payload, "base64").toString()) as { log?: string };
    expect(dhead.log).toBe("default");
    const roots = await Promise.all(["t/acme/root", "t/globex/root", "root"].map(async (p) => ((await (await fetch(new URL(p, log.url))).json()) as { treeSize: number }).treeSize));
    expect(roots).toEqual([1, 1, 1]);
  });

  it("audit refuses to compare heads from different logs, and checks the expected log when told one", async () => {
    const issuer = createSdkIssuer(loadSdkConfig(join(dir, "sdk.json")));
    const older = await issuer.record({ tool: "t", args: { n: 1 } }, { status: "executed", result: null });
    const newer = await issuer.record({ tool: "t", args: { n: 2 } }, { status: "executed", result: null });
    const proof = (await (await fetch(new URL(`t/acme/consistency?old=${older.inclusion.treeSize}&new=${newer.inclusion.treeSize}`, log.url))).json()) as { hashes: string[] };
    const keys = [loadPublicKey(logKey.pubFile)];
    expect(failingAudit(auditExtends(older.treeHead, newer.treeHead, proof.hashes, keys))).toEqual([]);
    expect(failingAudit(auditExtends(older.treeHead, newer.treeHead, proof.hashes, keys, "acme"))).toEqual([]);
    expect(failingAudit(auditExtends(older.treeHead, newer.treeHead, proof.hashes, keys, "globex-eu"))).toEqual(["both tree heads name the expected log"]);
    const globexHead = ((await (await fetch(new URL("t/globex/head", log.url))).json()) as { treeHead: import("../src/crypto.ts").Envelope }).treeHead;
    expect(failingAudit(auditExtends(older.treeHead, globexHead, [], keys))).toContain("both tree heads name the same log");
  });
});

describe("HTTP log sink retries", () => {
  // A stand-in log that appends exactly the leaf the sink sent, and signs a head for it.
  const answer = (mlog: MerkleLog, key: ReturnType<typeof generateKeyPair>, leaf: string) => {
    const e = mlog.append(leaf);
    const head = { treeSize: e.treeSize, rootHash: e.rootHash, timestamp: new Date().toISOString(), log: "the-log" };
    return new Response(JSON.stringify({ inclusion: { leafIndex: e.leafIndex, treeSize: e.treeSize, hashes: e.hashes }, treeHead: dsseSign(TREEHEAD_TYPE, head, key) }), { status: 200 });
  };

  it("retries a 429 and an unreachable log, then takes the good answer; gives up after the last failure", async () => {
    const dir = mkdtempSync(join(tmpdir(), "log-retry-"));
    const honest = generateKeyPair();
    const mlog = new MerkleLog(join(dir, "retry.jsonl"));
    let calls = 0;
    const flaky: typeof fetch = async (_url, init) => {
      calls++;
      if (calls === 1) return new Response("slow down", { status: 429, headers: { "retry-after": "0" } });
      return answer(mlog, honest, (JSON.parse(String((init as { body?: unknown }).body)) as { leaf: string }).leaf);
    };
    const entry = await httpLog("http://retry.invalid/", { fetch: flaky, keys: [honest], logId: "the-log" }).append("leaf-0");
    expect(entry.inclusion.leafIndex).toBe(0);
    expect(calls).toBe(2);
    let tries = 0;
    const down: typeof fetch = async (_url, init) => {
      tries++;
      if (tries <= 2) throw new Error("connection refused");
      return answer(mlog, honest, (JSON.parse(String((init as { body?: unknown }).body)) as { leaf: string }).leaf);
    };
    const second = await httpLog("http://down.invalid/", { fetch: down, keys: [honest], logId: "the-log" }).append("leaf-0");
    expect(second.inclusion.leafIndex).toBe(1);
    expect(tries).toBe(3);
    let dead = 0;
    const deadFetch: typeof fetch = async () => {
      dead++;
      throw new Error("down");
    };
    await expect(httpLog("http://dead.invalid/", { fetch: deadFetch, keys: [honest] }).append("leaf")).rejects.toThrow(/unreachable/);
    expect(dead).toBe(3);
  });

  it("refuses a log whose keys cannot be fetched, and a head whose size does not match its proof", async () => {
    const dir = mkdtempSync(join(tmpdir(), "log-keys-"));
    const honest = generateKeyPair();
    const mlog = new MerkleLog(join(dir, "keys.jsonl"));
    const noKeys: typeof fetch = async (url, init) => {
      if (String(url).endsWith("/.well-known/agent-custody-log.json")) return new Response("no keys here", { status: 500 });
      return answer(mlog, honest, (JSON.parse(String((init as { body?: unknown }).body)) as { leaf: string }).leaf);
    };
    await expect(httpLog("http://nokeys.invalid/", { fetch: noKeys }).append("leaf-0")).rejects.toThrow(/could not be fetched/);
    const wrongSize: typeof fetch = async (_url, init) => {
      const leaf = (JSON.parse(String((init as { body?: unknown }).body)) as { leaf: string }).leaf;
      const e = mlog.append(leaf);
      const head = { treeSize: e.treeSize + 1, rootHash: e.rootHash, timestamp: new Date().toISOString() };
      return new Response(JSON.stringify({ inclusion: { leafIndex: e.leafIndex, treeSize: e.treeSize, hashes: e.hashes }, treeHead: dsseSign(TREEHEAD_TYPE, head, honest) }), { status: 200 });
    };
    await expect(httpLog("http://wrongsize.invalid/", { fetch: wrongSize, keys: [honest] }).append("leaf-1")).rejects.toThrow(/tree head of size/);
  });
});

describe("openLog", () => {
  it("refuses a config with neither logFile nor log.url", () => {
    expect(() => openLog({}, generateKeyPair())).toThrow(/config needs logFile or log\.url/);
  });
});

describe("CheckpointPublisher", () => {
  it("warns and keeps running when one log fails, and still publishes the healthy one", async () => {
    const dir = mkdtempSync(join(tmpdir(), "log-publisher-"));
    const kp = generateKeyPair();
    const goodFile = join(dir, "good.jsonl");
    new MerkleLog(goodFile).append("a");
    const badBackend = { ...fileBackend(join(dir, "bad.jsonl")), size: async () => { throw new Error("disk gone"); } };
    const resolver = {
      resolve: async (tenant: string | null) =>
        tenant === "bad"
          ? { backend: badBackend, logId: "bad", authorize: async () => true }
          : { backend: fileBackend(goodFile), logId: "good", authorize: async () => true },
      tenants: async () => ["bad", null] as (string | null)[],
    };
    const store = dirCheckpoints(join(dir, "checkpoints"));
    const warnings: string[] = [];
    const publisher = new CheckpointPublisher(resolver, localSigner(kp), store, 60_000, (m) => warnings.push(m));
    const out = await publisher.publishOnce();
    expect(out).toHaveLength(1);
    expect(out[0]!.tenant).toBe("default");
    expect(warnings).toEqual(["agent-custody log: checkpoint for bad failed: disk gone"]);
    expect((await store.latest("default"))?.treeSize).toBe(1);
  });

  it("start publishes once immediately and stop keeps it from publishing again", async () => {
    const dir = mkdtempSync(join(tmpdir(), "log-publisher-start-"));
    const kp = generateKeyPair();
    const file = join(dir, "log.jsonl");
    const log = new MerkleLog(file);
    log.append("a");
    const resolver = fileResolver(file, { logId: "good" });
    const store = dirCheckpoints(join(dir, "checkpoints"));
    const publisher = new CheckpointPublisher(resolver, localSigner(kp), store, 50);
    publisher.start();
    for (let i = 0; i < 50 && !(await store.latest("default")); i++) await new Promise((r) => setTimeout(r, 20));
    expect((await store.latest("default"))?.treeSize).toBe(1);
    publisher.stop();
    log.append("b");
    await new Promise((r) => setTimeout(r, 300));
    expect((await store.latest("default"))?.treeSize).toBe(1);
  });
});

describe("the reference log server's refusal answers", () => {
  let log: RunningLog;
  let dir: string;
  const post = (path: string, token: string | null, body: unknown) => fetch(new URL(path, log.url), { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
  const get = (path: string, token?: string) => fetch(new URL(path, log.url), { headers: token ? { authorization: `Bearer ${token}` } : {} });
  const errOf = async (r: Response) => ((await r.json()) as { error: string }).error;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "log-refusals-"));
    const kp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "log");
    log = await serveLog(join(dir, "log.jsonl"), loadPrivateKey(kp.keyFile), { port: 0, tokens: ["t1"] });
    expect((await post("append", "t1", { leafHash: "ab".repeat(32) })).status).toBe(200);
  });
  afterAll(() => log.close());

  it("answers 400 for a bad body, a bad leaf, and out-of-range sizes", async () => {
    const badJson = await fetch(new URL("append", log.url), { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer t1" }, body: "{not json" });
    expect(badJson.status).toBe(400);
    expect(await errOf(badJson)).toMatch(/body must be JSON/);
    const emptyLeaf = await post("append", "t1", { leaf: "" });
    expect(emptyLeaf.status).toBe(400);
    expect(await errOf(emptyLeaf)).toMatch(/leaf must be a non-empty string/);
    const badHash = await post("append", "t1", { leafHash: "zz" });
    expect(badHash.status).toBe(400);
    expect(await errOf(badHash)).toMatch(/leafHash must be 64 lowercase/);
    expect((await get("root?size=99")).status).toBe(400);
    expect((await get("root?size=-1")).status).toBe(400);
    expect((await get("consistency?old=1&new=0")).status).toBe(400);
    expect((await get("leaves?since=99", "t1")).status).toBe(400);
    expect((await get("leaves?limit=0", "t1")).status).toBe(400);
    expect((await get("checkpoints?since=abc")).status).toBe(400);
  });

  it("answers 404 where a file log keeps nothing, and 401 without a token", async () => {
    expect((await get("nope")).status).toBe(404);
    expect((await get("policies", "t1")).status).toBe(404);
    expect((await get("audit", "t1")).status).toBe(404);
    expect((await get("audit?limit=0", "t1")).status).toBe(404);
    expect((await get("usage", "t1")).status).toBe(404);
    expect((await post("append", null, { leaf: "x" })).status).toBe(401);
  });

  it("a hash-only log refuses a leaf with 400", async () => {
    const d = mkdtempSync(join(tmpdir(), "log-hashonly-"));
    const kp = writeKeyPair(generateKeyPair(), join(d, "keys"), "log");
    const server = await serveLog(join(d, "log.jsonl"), loadPrivateKey(kp.keyFile), { port: 0, hashOnly: true });
    try {
      const r = await fetch(new URL("append", server.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf: "plain receipt" }) });
      expect(r.status).toBe(400);
      expect(await errOf(r)).toMatch(/leaf hashes only/);
    } finally {
      await server.close();
    }
  });

  it("answers 503 when the log cannot be reached, and 500 when the log fails", async () => {
    const kp = generateKeyPair();
    const throwingResolver = {
      resolve: async (): Promise<null> => { throw new Error("pg is down"); },
      tenants: async () => [] as (string | null)[],
    };
    const down = await serveLog(throwingResolver, localSigner(kp), { port: 0 });
    try {
      const r = await fetch(new URL("root", down.url));
      expect(r.status).toBe(503);
      expect(await errOf(r)).toMatch(/log unavailable/);
    } finally {
      await down.close();
    }
    const brokenBackend = { ...fileBackend(join(dir, "broken.jsonl")), root: async () => { throw new Error("tree gone"); } };
    const brokenResolver = {
      resolve: async () => ({ backend: brokenBackend, logId: undefined, authorize: async () => true }),
      tenants: async () => [null] as (string | null)[],
    };
    const broken = await serveLog(brokenResolver, localSigner(kp), { port: 0 });
    try {
      const r = await fetch(new URL("head", broken.url));
      expect(r.status).toBe(500);
      expect(await errOf(r)).toMatch(/tree gone/);
    } finally {
      await broken.close();
    }
  });

  it("answers 429 when the plan's monthly quota is spent", async () => {
    const kp = generateKeyPair();
    const resolver = {
      resolve: async () => ({ backend: fileBackend(join(dir, "quota.jsonl")), logId: "q", authorize: async () => true, quota: async () => ({ plan: "free" as const, used: 10, quota: 10 }) }),
      tenants: async () => [null] as (string | null)[],
    };
    const server = await serveLog(resolver, localSigner(kp), { port: 0 });
    try {
      const r = await fetch(new URL("append", server.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf: "x" }) });
      expect(r.status).toBe(429);
      expect(await errOf(r)).toMatch(/monthly quota reached: 10 of 10/);
      expect(r.headers.get("retry-after")).not.toBeNull();
    } finally {
      await server.close();
    }
  });

  it("the health and key endpoints answer 503 when the signer cannot answer", async () => {
    const kp = generateKeyPair();
    const brokenSigner = { keyid: kp.keyid, sign: async () => localSigner(kp).sign("x", {}), keys: async () => { throw new Error("signer down"); } };
    const server = await serveLog(join(dir, "nosigner.jsonl"), brokenSigner, { port: 0 });
    try {
      expect((await fetch(new URL("health", server.url))).status).toBe(503);
      const keys = await fetch(new URL(".well-known/agent-custody-log.json", server.url));
      expect(keys.status).toBe(503);
      expect(await errOf(keys)).toMatch(/keys unavailable/);
    } finally {
      await server.close();
    }
  });
});
