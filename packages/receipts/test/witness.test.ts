// The witness exists so a verifier does not have to trust the log's operator either. It countersigns a checkpoint
// only after proving it extends the last head it signed; a log that rewrites history, or shows a second history at
// the same size, gets an alarm instead of a signature. Everything here runs in-process: a log with published
// checkpoints, a static server for them, and a witness pointed at both.
import { createServer, type Server } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { dirCheckpoints } from "../src/checkpoints.ts";
import { dsseSign, dsseVerifiers, generateKeyPair, loadPublicKey, writeKeyPair, type Envelope, type KeyPair } from "../src/crypto.ts";
import { CheckpointPublisher, fileResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { TREEHEAD_TYPE } from "../src/receipt.ts";
import { localSigner } from "../src/signer.ts";
import { auditExtends } from "../src/verify.ts";
import { fetchWitnessKeys, Witness } from "../src/witness.ts";

/** The witness's fetch: refuses a call that carries no abort signal, because every outbound fetch needs a timeout. */
const timedFetch: typeof fetch = async (input, init) => {
  if (!(init?.signal instanceof AbortSignal)) throw new Error(`fetch without a timeout signal: ${String(input)}`);
  return fetch(input, init);
};

/** Serves a directory the way the checkpoints host does. */
function staticHost(dir: string): Promise<{ server: Server; url: string }> {
  const server = createServer((req, res) => {
    const file = join(dir, decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname));
    if (!existsSync(file)) {
      res.writeHead(404);
      return res.end();
    }
    try {
      const body = readFileSync(file);
      res.writeHead(200, { "content-type": extname(file) === ".json" ? "application/json" : "text/plain" });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end();
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${(server.address() as { port: number }).port}/` })));
}

describe("the witness", () => {
  let dir: string;
  let log: RunningLog;
  let host: { server: Server; url: string };
  let publisher: CheckpointPublisher;
  let logKp: { keyFile: string; pubFile: string };
  let witnessKp: { keyFile: string; pubFile: string };
  let witness: Witness;
  const cpDir = () => join(dir, "checkpoints");
  const post = (leaf: string) => fetch(new URL("append", log.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf }) });
  const witnessed = (name = "latest.json") => JSON.parse(readFileSync(join(dir, "witness", "default", name), "utf8")) as { treeSize: number; envelope: Envelope; witness: { keyid: string } };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "witness-"));
    logKp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "log");
    witnessKp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "witness");
    const { loadPrivateKey } = await import("../src/crypto.ts");
    const signer = localSigner(loadPrivateKey(logKp.keyFile));
    const store = dirCheckpoints(cpDir());
    const resolver = fileResolver(join(dir, "log.jsonl"), { logId: "watched-log" });
    log = await serveLog(resolver, signer, { port: 0, checkpoints: store });
    publisher = new CheckpointPublisher(resolver, signer, store, 60_000);
    host = await staticHost(cpDir());
    witness = new Witness({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default"], key: loadPrivateKey(witnessKp.keyFile), outDir: join(dir, "witness"), fetch: timedFetch, warn: () => {} });
  });
  afterAll(async () => {
    await log.close();
    host.server.close();
  });

  it("publishes its own key document, waits while there is nothing to sign, then countersigns the first checkpoint", async () => {
    const keys = (JSON.parse(readFileSync(join(dir, "witness", ".well-known", "agent-custody-witness.json"), "utf8")) as { keys: { keyid: string }[] }).keys;
    expect(keys[0]?.keyid).toBe(loadPublicKey(witnessKp.pubFile).keyid);
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "unavailable", reason: "no checkpoint published yet" }]);
    await post("a");
    await post("b");
    await publisher.publishOnce();
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "countersigned", treeSize: 2 }]);
    const w = witnessed();
    expect(w.treeSize).toBe(2);
    expect(w.envelope.signatures.map((s) => s.keyid).sort()).toEqual([loadPublicKey(logKp.pubFile).keyid, loadPublicKey(witnessKp.pubFile).keyid].sort());
    expect(dsseVerifiers(w.envelope, [loadPublicKey(logKp.pubFile), loadPublicKey(witnessKp.pubFile)])).toHaveLength(2);
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "unchanged", treeSize: 2 }]);
  });

  it("countersigns a later checkpoint only after the log proves it extends the earlier one, and an audit can require the witness", async () => {
    await post("c");
    await publisher.publishOnce();
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "countersigned", treeSize: 3 }]);
    const older = witnessed("2.json").envelope;
    const newer = witnessed("3.json").envelope;
    const proof = (await (await fetch(new URL("consistency?old=2&new=3", log.url))).json()) as { hashes: string[] };
    const keys = [loadPublicKey(logKp.pubFile)];
    const both = auditExtends(older, newer, proof.hashes, keys, "watched-log", { witnessKeys: [loadPublicKey(witnessKp.pubFile)] });
    expect(both.checks.filter((c) => !c.ok)).toEqual([]);
    expect(both.checks.map((c) => c.name)).toContain("newer tree head countersigned by a witness");
    // the log's own checkpoint, without the witness's signature, fails a verifier who requires one
    const unwitnessed = (JSON.parse(readFileSync(join(cpDir(), "default", "3.json"), "utf8")) as { envelope: Envelope }).envelope;
    const alone = auditExtends(older, unwitnessed, proof.hashes, keys, "watched-log", { witnessKeys: [loadPublicKey(witnessKp.pubFile)] });
    expect(alone.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual(["newer tree head countersigned by a witness"]);
    // a verifier fetches the witness's keys from its host, the way it fetches the log's
    const wHost = await staticHost(join(dir, "witness"));
    try {
      expect((await fetchWitnessKeys(wHost.url, timedFetch)).map((k) => k.keyid)).toEqual([loadPublicKey(witnessKp.pubFile).keyid]);
    } finally {
      wHost.server.close();
    }
  });

  it("a second history at the same size, a rewritten history, and a stranger's key each get an alarm and no signature; the last good head is kept", async () => {
    const { loadPrivateKey } = await import("../src/crypto.ts");
    const logKey = loadPrivateKey(logKp.keyFile);
    const publish = (treeSize: number, rootHash: string, key = logKey) =>
      writeFileSync(join(cpDir(), "default", "latest.json"), JSON.stringify({ tenant: "default", logId: "watched-log", treeSize, rootHash, signedAt: "t", envelope: dsseSign(TREEHEAD_TYPE, { treeSize, rootHash, timestamp: "t", log: "watched-log" }, key) }));
    // same size, different root: the log is showing two histories
    publish(3, "ee".repeat(32));
    const [split] = await witness.runOnce();
    expect(split).toMatchObject({ tenant: "default", outcome: "refused" });
    expect((split as { reason: string }).reason).toMatch(/two histories/);
    expect(existsSync(join(dir, "witness", "default", "ALARM.json"))).toBe(true);
    // the log grows to 4 honestly, but the published checkpoint at 4 carries a root that is not the log's: the proof from the log refutes it
    await post("d");
    publish(4, "ff".repeat(32));
    const [rewritten] = await witness.runOnce();
    expect(rewritten).toMatchObject({ outcome: "refused" });
    expect((rewritten as { reason: string }).reason).toMatch(/does not extend|history was rewritten/);
    expect(existsSync(join(dir, "witness", "default", "4.json"))).toBe(false);
    expect(witnessed().treeSize).toBe(3);
    // a checkpoint signed by a key the log does not publish is refused too
    publish(4, "aa".repeat(32), generateKeyPair());
    const [stranger] = await witness.runOnce();
    expect(stranger).toMatchObject({ outcome: "refused" });
    expect((stranger as { reason: string }).reason).toMatch(/published keys/);
    // the honest log carries on: the next real checkpoint extends the last good head and is countersigned
    await post("e");
    await publisher.publishOnce();
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "countersigned", treeSize: 5 }]);
    expect(readdirSync(join(dir, "witness", "default")).filter((n) => n.startsWith("ALARM-")).length).toBe(3);
  });
});

// A witness that signs when it cannot check is worse than no witness. Each failure here must end in an outcome that
// says so, with no signature on disk, and the next good run must carry on from the last head that was signed.
describe("the witness, when the log or its hosts fail", () => {
  let dir: string;
  let log: RunningLog;
  let host: { server: Server; url: string };
  let publisher: CheckpointPublisher;
  let logKey: KeyPair;
  const witnessKey = generateKeyPair();
  /** a part of a request path, and the HTTP status that requests with it get */
  const failing = new Map<string, number>();
  const warnings: string[] = [];
  const faultyFetch: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname;
    for (const [part, status] of failing) if (path.includes(part)) return new Response(null, { status });
    return timedFetch(input, init);
  };
  const cpFile = (tenant: string) => join(dir, "checkpoints", tenant, "latest.json");
  const post = (leaf: string) => fetch(new URL("append", log.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf }) });
  const make = (name: string, tenants = ["default"]) => new Witness({ logUrl: log.url, checkpointsUrl: host.url, tenants, key: witnessKey, outDir: join(dir, name), fetch: faultyFetch, warn: (m) => warnings.push(m) });
  const publish = (tenant: string, head: { treeSize: number; rootHash: string; log: string }) => {
    mkdirSync(join(dir, "checkpoints", tenant), { recursive: true });
    writeFileSync(cpFile(tenant), JSON.stringify({ tenant, envelope: dsseSign(TREEHEAD_TYPE, { ...head, timestamp: "t" }, logKey) }));
  };
  const files = (name: string, tenant = "default") => (existsSync(join(dir, name, tenant)) ? readdirSync(join(dir, name, tenant)).sort() : []);
  const alarms = (name: string) => files(name).filter((n) => n.startsWith("ALARM-"));
  const signedSize = (name: string) => (JSON.parse(readFileSync(join(dir, name, "default", "latest.json"), "utf8")) as { treeSize: number }).treeSize;
  /** runs `body` with a forged checkpoint in place of the log's, then puts the log's back */
  const withForged = async (head: { treeSize: number; rootHash: string; log: string }, body: () => Promise<void>) => {
    const honest = readFileSync(cpFile("default"));
    publish("default", head);
    try {
      await body();
    } finally {
      writeFileSync(cpFile("default"), honest);
    }
  };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "witness-faults-"));
    const { loadPrivateKey } = await import("../src/crypto.ts");
    logKey = loadPrivateKey(writeKeyPair(generateKeyPair(), join(dir, "keys"), "log").keyFile);
    const signer = localSigner(logKey);
    const store = dirCheckpoints(join(dir, "checkpoints"));
    const resolver = fileResolver(join(dir, "log.jsonl"), { logId: "watched-log" });
    log = await serveLog(resolver, signer, { port: 0, checkpoints: store });
    publisher = new CheckpointPublisher(resolver, signer, store, 60_000);
    host = await staticHost(join(dir, "checkpoints"));
    await post("a");
    await post("b");
    await publisher.publishOnce();
    publish("acme", { treeSize: 9, rootHash: "cd".repeat(32), log: "acme-log" });
  });
  afterEach(() => {
    failing.clear();
    warnings.length = 0;
    vi.useRealTimers();
  });
  afterAll(async () => {
    await log.close();
    host.server.close();
  });

  it("gives every tenant an unavailable outcome and signs nothing while the log's key document cannot be fetched", async () => {
    const w = make("no-keys", ["default", "acme"]);
    failing.set("agent-custody-log.json", 503);
    expect(await w.runOnce()).toEqual([
      { tenant: "default", outcome: "unavailable", reason: "log key document: 503" },
      { tenant: "acme", outcome: "unavailable", reason: "log key document: 503" },
    ]);
    expect(files("no-keys")).toEqual([]);
    expect(files("no-keys", "acme")).toEqual([]);
    expect(warnings).toHaveLength(1);
    failing.clear();
    expect(await w.runOnce()).toEqual([
      { tenant: "default", outcome: "countersigned", treeSize: 2 },
      { tenant: "acme", outcome: "countersigned", treeSize: 9 },
    ]);
  });

  it("leaves one tenant unavailable when its checkpoint cannot be fetched, and still countersigns the others", async () => {
    failing.set("/default/latest.json", 500);
    expect(await make("checkpoint-error", ["default", "acme"]).runOnce()).toEqual([
      { tenant: "default", outcome: "unavailable", reason: "checkpoint for default: 500" },
      { tenant: "acme", outcome: "countersigned", treeSize: 9 },
    ]);
    expect(files("checkpoint-error")).toEqual([]);
  });

  it("does not countersign a larger checkpoint while the log gives no consistency proof, and raises no alarm for it", async () => {
    const w = make("proof-error");
    const [first] = await w.runOnce();
    expect(first).toMatchObject({ outcome: "countersigned" });
    const size = (first as { treeSize: number }).treeSize;
    await post("c");
    await publisher.publishOnce();
    failing.set("/consistency", 500);
    expect(await w.runOnce()).toEqual([{ tenant: "default", outcome: "unavailable", reason: "consistency proof for default: 500" }]);
    expect(signedSize("proof-error")).toBe(size);
    expect(files("proof-error")).not.toContain(`${size + 1}.json`);
    expect(alarms("proof-error")).toEqual([]);
    failing.clear();
    expect(await w.runOnce()).toEqual([{ tenant: "default", outcome: "countersigned", treeSize: size + 1 }]);
  });

  it("refuses a checkpoint that names another log than the one it signed before, and writes an alarm", async () => {
    const w = make("log-id");
    const [first] = await w.runOnce();
    const size = (first as { treeSize: number }).treeSize;
    // signed by the log's own key, and larger, so only the log id tells it from an honest checkpoint
    await withForged({ treeSize: size + 1, rootHash: "ab".repeat(32), log: "another-log" }, async () => {
      expect(await w.runOnce()).toEqual([{ tenant: "default", outcome: "refused", reason: "checkpoint names log another-log, the last one signed named watched-log" }]);
    });
    expect(alarms("log-id")).toHaveLength(1);
    const alarm = JSON.parse(readFileSync(join(dir, "log-id", "default", alarms("log-id")[0]!), "utf8")) as { reason: string; checkpoint: Envelope };
    expect(alarm.reason).toMatch(/names log another-log/);
    expect(alarm.checkpoint.payloadType).toBe(TREEHEAD_TYPE);
    expect(files("log-id")).toContain("ALARM.json");
    expect(files("log-id")).not.toContain(`${size + 1}.json`);
    expect(signedSize("log-id")).toBe(size);
  });

  it("keeps both alarms when two refusals fall in the same millisecond", async () => {
    const w = make("same-instant");
    const [first] = await w.runOnce();
    const size = (first as { treeSize: number }).treeSize;
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-02T03:04:05.006Z"));
    await withForged({ treeSize: size, rootHash: "ee".repeat(32), log: "watched-log" }, async () => {
      expect((await w.runOnce())[0]).toMatchObject({ outcome: "refused" });
      expect((await w.runOnce())[0]).toMatchObject({ outcome: "refused" });
    });
    expect(alarms("same-instant")).toEqual(["ALARM-2026-01-02T03-04-05-006Z-2.json", "ALARM-2026-01-02T03-04-05-006Z.json"]);
  });

  it("start runs at once and then on its interval, a second start adds nothing, and stop ends the runs", async () => {
    vi.useFakeTimers();
    let runs = 0;
    // each run asks for the key document once; this log never answers, so a run is one request
    const down = (async () => {
      runs++;
      return new Response(null, { status: 503 });
    }) as typeof fetch;
    const w = new Witness({ logUrl: "http://log.test/", checkpointsUrl: "http://checkpoints.test/", tenants: ["default"], key: witnessKey, outDir: join(dir, "scheduled"), fetch: down, warn: () => {} });
    w.start(1000);
    w.start(1000);
    expect(runs).toBe(1);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(3000);
    expect(runs).toBe(4);
    w.stop();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(3000);
    expect(runs).toBe(4);
    // a stopped witness can start again
    w.start(1000);
    expect(runs).toBe(5);
    w.stop();
  });

  it("a verifier gets an error, not an empty key list, from a witness host with no key document or no keys", async () => {
    const empty = join(dir, "witness-host");
    mkdirSync(join(empty, ".well-known"), { recursive: true });
    const wHost = await staticHost(empty);
    try {
      await expect(fetchWitnessKeys(wHost.url, timedFetch)).rejects.toThrow(/serves no key document: 404/);
      for (const doc of [{ keys: [] }, {}]) {
        writeFileSync(join(empty, ".well-known", "agent-custody-witness.json"), JSON.stringify(doc));
        await expect(fetchWitnessKeys(wHost.url, timedFetch)).rejects.toThrow(/lists no keys/);
      }
    } finally {
      wHost.server.close();
    }
  });
});
