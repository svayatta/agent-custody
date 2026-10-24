// The anchor exists so a verifier does not have to trust the log's operator, its checkpoints host, or even the
// anchor's own host: a rewritten tree is caught from the chain alone. These tests run a real log with published
// checkpoints, a static host for them, and an in-process chain that signs-and-recovers real Ethereum transactions,
// so the sender a verifier checks is the one that signed. Nothing reaches the network.
import { spawnSync } from "node:child_process";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { keccak256, parseTransaction, recoverTransactionAddress, toHex } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Anchor, ANCHOR_CHAINS, anchorCalldata, checkAnchorRecord, resolveAnchorChain, type AnchorChain, type AnchorRecord } from "../src/anchor.ts";
import { evmChain } from "../src/anchor-evm.ts";
import { dirCheckpoints } from "../src/checkpoints.ts";
import { dsseSign, generateKeyPair, loadPrivateKey, writeKeyPair, type PublicKeyRef } from "../src/crypto.ts";
import { checkLog } from "../src/log-check.ts";
import { CheckpointPublisher, fileResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { TREEHEAD_TYPE } from "../src/receipt.ts";
import { fetchLogKeys, localSigner } from "../src/signer.ts";

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

interface Tx {
  hash: string;
  from: string;
  to: string | null;
  input: string;
  nonce: number;
  blockNumber: number | null;
  status: "0x1" | "0x0";
}

/** A chain in a Map: transactions are parsed and their sender recovered from the signature, blocks are mined on demand. */
function devnet(chainId = 1) {
  const txs = new Map<string, Tx>();
  const blocks: { number: number; hash: string; timestamp: number }[] = [{ number: 0, hash: keccak256(toHex("genesis")), timestamp: 1_700_000_000 }];
  const net = {
    baseFeeGwei: 2n,
    finalizedLag: 2,
    revertNext: false,
    sent: [] as Tx[],
    mine() {
      const prev = blocks[blocks.length - 1]!;
      const b = { number: prev.number + 1, hash: keccak256(toHex(`block ${prev.number + 1}`)), timestamp: prev.timestamp + 12 };
      blocks.push(b);
      for (const tx of txs.values()) if (tx.blockNumber === null) tx.blockNumber = b.number;
      return b.number;
    },
    finalizeAll() {
      net.finalizedLag = 0;
    },
    /** another sender's transaction, e.g. someone else posting a root that looks like ours */
    inject(tx: Omit<Tx, "blockNumber">) {
      txs.set(tx.hash, { ...tx, blockNumber: null });
    },
    blockHash(n: number) {
      return blocks[n]!.hash;
    },
    async request({ method, params }: { method: string; params?: unknown }): Promise<unknown> {
      const p = (params ?? []) as unknown[];
      const head = blocks[blocks.length - 1]!;
      const blockJson = (b: (typeof blocks)[number]) => ({ number: toHex(b.number), hash: b.hash, parentHash: blocks[b.number - 1]?.hash ?? `0x${"00".repeat(32)}`, timestamp: toHex(b.timestamp), baseFeePerGas: toHex(net.baseFeeGwei * 1_000_000_000n), gasLimit: toHex(30_000_000), gasUsed: "0x0", transactions: [], miner: `0x${"00".repeat(20)}`, difficulty: "0x0", extraData: "0x", logsBloom: `0x${"00".repeat(256)}`, nonce: "0x0000000000000000", sha3Uncles: `0x${"00".repeat(32)}`, size: "0x0", stateRoot: `0x${"00".repeat(32)}`, receiptsRoot: `0x${"00".repeat(32)}`, transactionsRoot: `0x${"00".repeat(32)}`, mixHash: `0x${"00".repeat(32)}`, totalDifficulty: "0x0", uncles: [] });
      const txJson = (t: Tx) => ({ hash: t.hash, from: t.from, to: t.to, input: t.input, nonce: toHex(t.nonce), blockNumber: t.blockNumber === null ? null : toHex(t.blockNumber), blockHash: t.blockNumber === null ? null : blocks[t.blockNumber]!.hash, transactionIndex: t.blockNumber === null ? null : "0x0", value: "0x0", gas: toHex(30_000), type: "0x2", chainId: toHex(chainId), maxFeePerGas: "0x1", maxPriorityFeePerGas: "0x1", v: "0x0", r: "0x1", s: "0x1", yParity: "0x0", accessList: [] });
      switch (method) {
        case "eth_chainId":
          return toHex(chainId);
        case "eth_blockNumber":
          return toHex(head.number);
        case "eth_getBlockByNumber": {
          const tag = p[0] as string;
          if (tag === "finalized") return blockJson(blocks[Math.max(0, head.number - net.finalizedLag)]!);
          if (tag === "latest" || tag === "pending" || tag === "safe") return blockJson(head);
          const b = blocks[Number(tag)];
          return b ? blockJson(b) : null;
        }
        case "eth_maxPriorityFeePerGas":
          return toHex(1_000_000_000n);
        case "eth_getTransactionCount": {
          const who = String(p[0]).toLowerCase();
          return toHex([...txs.values()].filter((t) => t.from === who).length);
        }
        case "eth_estimateGas":
          return toHex(22_000);
        case "eth_sendRawTransaction": {
          const raw = p[0] as `0x${string}`;
          const parsed = parseTransaction(raw);
          if (parsed.chainId !== chainId) throw new Error("wrong chain id");
          const from = (await recoverTransactionAddress({ serializedTransaction: raw as never })).toLowerCase();
          const tx: Tx = { hash: keccak256(raw), from, to: parsed.to?.toLowerCase() ?? null, input: parsed.data ?? "0x", nonce: parsed.nonce ?? 0, blockNumber: null, status: net.revertNext ? "0x0" : "0x1" };
          net.revertNext = false;
          txs.set(tx.hash, tx);
          net.sent.push(tx);
          return tx.hash;
        }
        case "eth_getTransactionByHash": {
          const t = txs.get(String(p[0]));
          return t ? txJson(t) : null;
        }
        case "eth_getTransactionReceipt": {
          const t = txs.get(String(p[0]));
          if (!t || t.blockNumber === null) return null;
          return { transactionHash: t.hash, blockNumber: toHex(t.blockNumber), blockHash: blocks[t.blockNumber]!.hash, status: t.status, from: t.from, to: t.to, transactionIndex: "0x0", gasUsed: toHex(21_700), cumulativeGasUsed: toHex(21_700), effectiveGasPrice: toHex(3_000_000_000n), logs: [], logsBloom: `0x${"00".repeat(256)}`, type: "0x2", contractAddress: null };
        }
        default:
          throw Object.assign(new Error(`method ${method} not supported`), { code: -32601 });
      }
    },
  };
  return net;
}

type Devnet = ReturnType<typeof devnet>;
type Endpoint = { request: Devnet["request"] };

/** The same chain seen through an endpoint that reports another hash for one block, as on the losing side of a fork. */
function forkedAt(net: Devnet, n: number): Endpoint {
  const other = keccak256(toHex(`fork ${n}`));
  return {
    async request(args) {
      const r = (await net.request(args)) as Record<string, unknown> | null;
      if (!r) return r;
      if (args.method === "eth_getBlockByNumber" && Number(r.number) === n) return { ...r, hash: other };
      if (args.method === "eth_getTransactionReceipt" && Number(r.blockNumber) === n) return { ...r, blockHash: other };
      return r;
    },
  };
}

/** The same chain seen through an endpoint that has finalized nothing yet. */
function notFinalized(net: Devnet): Endpoint {
  return {
    async request(args) {
      if (args.method === "eth_getBlockByNumber" && (args.params as unknown[])[0] === "finalized") return net.request({ method: "eth_getBlockByNumber", params: ["0x0", false] });
      return net.request(args);
    },
  };
}

/** A fetch that answers JSON-RPC for the given endpoints and passes everything else (the log, the hosts) through. */
function rpcFetch(endpoints: Record<string, Endpoint>): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    const net = endpoints[url];
    if (!net) return fetch(input, init);
    const body = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
    try {
      return Response.json({ jsonrpc: "2.0", id: body.id, result: await net.request({ method: body.method, params: body.params }) });
    } catch (e) {
      return Response.json({ jsonrpc: "2.0", id: body.id, error: { code: -32000, message: e instanceof Error ? e.message : String(e) } });
    }
  }) as typeof fetch;
}

describe("anchoring the log's checkpoints on a chain", () => {
  let dir: string;
  let log: RunningLog;
  let host: { server: Server; url: string };
  let anchorHost: { server: Server; url: string };
  let publisher: CheckpointPublisher;
  let logKp: { keyFile: string; pubFile: string };
  let net: Devnet;
  let chain: AnchorChain;
  let anchor: Anchor;
  let logKeys: PublicKeyRef[];
  const RPC = "http://rpc.devnet.test/";
  const cpDir = () => join(dir, "checkpoints");
  const outDir = () => join(dir, "anchor");
  const post = (leaf: string) => fetch(new URL("append", log.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf }) });
  const record = (name = "latest.json") => JSON.parse(readFileSync(join(outDir(), "default", name), "utf8")) as AnchorRecord;
  const check = (r: AnchorRecord, extra: Partial<Parameters<typeof checkAnchorRecord>[1]> = {}) => checkAnchorRecord(r, { rpcUrls: [RPC], address: chain.address, chainId: 1, logKeys, fetch: rpcFetch({ [RPC]: net }), ...extra });

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "anchor-"));
    logKp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "log");
    const signer = localSigner(loadPrivateKey(logKp.keyFile));
    const store = dirCheckpoints(cpDir());
    const resolver = fileResolver(join(dir, "log.jsonl"), { logId: "anchored-log" });
    log = await serveLog(resolver, signer, { port: 0, checkpoints: store });
    publisher = new CheckpointPublisher(resolver, signer, store, 60_000);
    host = await staticHost(cpDir());
    net = devnet();
    chain = await evmChain({ rpcUrl: RPC, privateKey: generatePrivateKey(), maxFeeGwei: 20, provider: net });
    anchor = new Anchor({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default"], chain, outDir: outDir(), waitMs: 0, warn: () => {} });
    anchorHost = await staticHost(outDir());
    logKeys = (await fetchLogKeys(log.url)).keys;
  });
  afterAll(async () => {
    await log.close();
    host.server.close();
    anchorHost.server.close();
  });

  it("sends nothing until there is a checkpoint, then one transaction from its own address to itself carrying the root", async () => {
    expect(await anchor.runOnce()).toEqual({ tenants: [{ tenant: "default", outcome: "unavailable", reason: "no checkpoint published yet" }], tx: { outcome: "none" } });
    expect(net.sent).toHaveLength(0);
    await post("a");
    await post("b");
    await publisher.publishOnce();
    const sent = await anchor.runOnce();
    expect(sent.tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 2 }]);
    expect(sent.tx.outcome).toBe("pending");
    expect(net.sent).toHaveLength(1);
    const tx = net.sent[0]!;
    // the sender is recovered from the signature, so this is the key's address, not a field the anchor filled in
    expect(tx.from).toBe(chain.address);
    expect(tx.to).toBe(chain.address);
    expect(tx.input).toMatch(new RegExp(`^${anchorCalldata("00".repeat(32)).slice(0, -64)}[0-9a-f]{64}$`));
    // no record exists until the transaction is in a block
    expect(existsSync(join(outDir(), "default", "latest.json"))).toBe(false);
    net.mine();
    const landed = await anchor.runOnce();
    expect(landed.tx).toMatchObject({ outcome: "anchored", txHash: tx.hash, tenants: ["default"] });
    const r = record();
    expect(r.treeSize).toBe(2);
    expect(anchorCalldata(r.anchor.root)).toBe(tx.input);
    expect(JSON.parse(readFileSync(join(outDir(), ".well-known", "agent-custody-anchor.json"), "utf8"))).toEqual({ chainId: 1, address: chain.address });
  });

  it("a record checks out against the chain, and is reported finalized only once the chain says so", async () => {
    const early = await check(record());
    expect(early).toMatchObject({ ok: true, finalized: false });
    net.mine();
    net.mine();
    const later = await check(record());
    expect(later).toMatchObject({ ok: true, finalized: true, blockNumber: record().anchor.blockNumber });
    // two endpoints that agree pass; finality is the least-finalized endpoint's
    const RPC2 = "http://rpc2.devnet.test/";
    expect(await check(record(), { rpcUrls: [RPC, RPC2], fetch: rpcFetch({ [RPC]: net, [RPC2]: net }) })).toMatchObject({ ok: true, finalized: true });
    expect(await check(record(), { rpcUrls: [RPC, RPC2], fetch: rpcFetch({ [RPC]: net, [RPC2]: notFinalized(net) }) })).toMatchObject({ ok: true, finalized: false });
    // an endpoint on the other side of a fork does not agree that the transaction is in this block
    expect(await check(record(), { rpcUrls: [RPC, RPC2], fetch: rpcFetch({ [RPC]: net, [RPC2]: forkedAt(net, record().anchor.blockNumber) }) })).toMatchObject({ ok: false, error: expect.stringMatching(/disagree on block/) });
  });

  it("sends no transaction while no log has grown, so an idle log costs nothing", async () => {
    await publisher.publishOnce();
    const before = net.sent.length;
    expect(await anchor.runOnce()).toEqual({ tenants: [{ tenant: "default", outcome: "unchanged", treeSize: 2 }], tx: { outcome: "none" } });
    expect(net.sent.length).toBe(before);
  });

  it("anchors a later checkpoint only after the log proves it extends the one anchored before", async () => {
    await post("c");
    await publisher.publishOnce();
    expect((await anchor.runOnce()).tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 3 }]);
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
    expect(record().treeSize).toBe(3);
    expect(record("2.json").treeSize).toBe(2);
  });

  it("a second history, a rewritten history, and a stranger's key each get an alarm and no transaction", async () => {
    const logKey = loadPrivateKey(logKp.keyFile);
    const publish = (treeSize: number, rootHash: string, key = logKey) =>
      writeFileSync(join(cpDir(), "default", "latest.json"), JSON.stringify({ tenant: "default", logId: "anchored-log", treeSize, rootHash, signedAt: "t", envelope: dsseSign(TREEHEAD_TYPE, { treeSize, rootHash, timestamp: "t", log: "anchored-log" }, key) }));
    const before = net.sent.length;
    publish(3, "ee".repeat(32));
    expect((await anchor.runOnce()).tenants[0]).toMatchObject({ outcome: "refused", reason: expect.stringMatching(/two histories/) });
    await post("d");
    publish(4, "ff".repeat(32));
    expect((await anchor.runOnce()).tenants[0]).toMatchObject({ outcome: "refused", reason: expect.stringMatching(/history was rewritten/) });
    publish(4, "aa".repeat(32), generateKeyPair());
    expect((await anchor.runOnce()).tenants[0]).toMatchObject({ outcome: "refused", reason: expect.stringMatching(/published keys/) });
    expect(net.sent.length).toBe(before);
    expect(readdirSync(join(outDir(), "default")).filter((n) => n.startsWith("ALARM-"))).toHaveLength(3);
    expect(record().treeSize).toBe(3);
    // the honest log carries on and is anchored again
    await publisher.publishOnce();
    expect((await anchor.runOnce()).tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 4 }]);
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
  });

  it("holds a transaction in flight: overlapping runs share one pass, and nothing new is sent until it lands", async () => {
    await post("e");
    await publisher.publishOnce();
    const before = net.sent.length;
    const [a, b] = await Promise.all([anchor.runOnce(), anchor.runOnce()]);
    expect(a).toBe(b);
    expect(net.sent.length).toBe(before + 1);
    await post("f");
    await publisher.publishOnce();
    // still pending: the new checkpoint waits, so one nonce is never used twice
    expect((await anchor.runOnce()).tx.outcome).toBe("pending");
    expect(net.sent.length).toBe(before + 1);
    net.mine();
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "anchored" });
    expect(record().treeSize).toBe(5);
    expect((await anchor.runOnce()).tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 6 }]);
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
  });

  it("skips a run whose fees are above the cap rather than paying them, and retries a transaction that failed", async () => {
    await post("g");
    await publisher.publishOnce();
    net.baseFeeGwei = 50n;
    const before = net.sent.length;
    const costly = await anchor.runOnce();
    expect(costly.tx).toMatchObject({ outcome: "failed", reason: expect.stringMatching(/above the cap of 20/) });
    expect(net.sent.length).toBe(before);
    net.baseFeeGwei = 2n;
    net.revertNext = true;
    expect((await anchor.runOnce()).tx.outcome).toBe("pending");
    net.mine();
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "failed", reason: expect.stringMatching(/failed in block/) });
    expect(record().treeSize).toBe(6);
    // the failed transaction is not a record; the next run sends the same checkpoint again
    expect((await anchor.runOnce()).tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 7 }]);
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
    expect(record().treeSize).toBe(7);
  });

  it("a verifier refuses a record that does not match the chain, whoever edited it", async () => {
    const good = record();
    expect((await check(good)).ok).toBe(true);
    // the pinned address is not the one that sent it
    expect(await check(good, { address: `0x${"11".repeat(20)}` })).toMatchObject({ ok: false, error: expect.stringMatching(/pinned anchor/) });
    // a checkpoint swapped for another one, signed by the log, of a different size
    const other = record("2.json");
    expect(await check({ ...good, checkpoint: other.checkpoint })).toMatchObject({ ok: false, error: expect.stringMatching(/not the checkpoint's/) });
    // a proof that does not lead from this checkpoint to the root the transaction carries
    expect(await check({ ...good, anchor: { ...good.anchor, proof: { leafIndex: 0, treeSize: 2, hashes: ["ab".repeat(32)] } } })).toMatchObject({ ok: false, error: expect.stringMatching(/not under the anchored root/) });
    // the record's root changed to match a different checkpoint: the transaction does not carry it
    expect(await check({ ...other, anchor: { ...other.anchor, txHash: good.anchor.txHash, blockNumber: good.anchor.blockNumber } })).toMatchObject({ ok: false, error: expect.stringMatching(/does not carry the anchored root/) });
    // someone else posts our root from their own address, and the record points at that transaction
    const fake = { hash: keccak256(toHex("someone else")), from: `0x${"22".repeat(20)}`, to: chain.address, input: anchorCalldata(good.anchor.root), nonce: 0, status: "0x1" as const };
    net.inject(fake);
    const n = net.mine();
    expect(await check({ ...good, anchor: { ...good.anchor, txHash: fake.hash, blockNumber: n } })).toMatchObject({ ok: false, error: expect.stringMatching(/not from the anchor to itself/) });
    // an endpoint on another chain, and two endpoints that disagree about the block
    const testnet = devnet(11155111);
    expect(await check(good, { fetch: rpcFetch({ [RPC]: testnet }) })).toMatchObject({ ok: false, error: expect.stringMatching(/chain 11155111/) });
    const fork = devnet();
    expect(await check(good, { rpcUrls: [RPC, "http://fork.devnet.test/"], fetch: rpcFetch({ [RPC]: net, "http://fork.devnet.test/": fork }) })).toMatchObject({ ok: false });
  });

  it("log-check catches a rewritten tree from the chain alone, with the log's checkpoints host out of the picture", async () => {
    const opts = { logUrl: log.url, anchorUrl: anchorHost.url, anchorAddress: chain.address, anchorRpcUrls: [RPC], fetch: rpcFetch({ [RPC]: net }) };
    const honest = await checkLog(opts);
    expect(honest.ok).toBe(true);
    expect(honest.checks.map((c) => c.name)).toEqual(["key document served", "head verifies against the published keys", "anchor is running and keeps up", "anchor verifies on chain", "head extends the anchored checkpoint"]);
    // the operator replaces the whole log with another history under the same key and log id
    const forged = await serveLog(fileResolver(join(dir, "forged.jsonl"), { logId: "anchored-log" }), localSigner(loadPrivateKey(logKp.keyFile)), { port: 0 });
    try {
      for (const leaf of ["a", "b", "x", "y", "z", "w", "v", "u"]) await fetch(new URL("append", forged.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf }) });
      const caught = await checkLog({ ...opts, logUrl: forged.url });
      expect(caught.ok).toBe(false);
      expect(caught.checks.find((c) => c.name === "head extends the anchored checkpoint")).toMatchObject({ ok: false, detail: expect.stringMatching(/history was rewritten/) });
      // a log rolled back below its anchor is caught too
      const short = await serveLog(fileResolver(join(dir, "short.jsonl"), { logId: "anchored-log" }), localSigner(loadPrivateKey(logKp.keyFile)), { port: 0 });
      try {
        await fetch(new URL("append", short.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf: "a" }) });
        expect((await checkLog({ ...opts, logUrl: short.url })).checks.find((c) => c.name === "head extends the anchored checkpoint")).toMatchObject({ ok: false, detail: expect.stringMatching(/rolled back/) });
      } finally {
        await short.close();
      }
    } finally {
      await forged.close();
    }
  });

  it("log-check fails an anchor that has stopped running or stays behind a log that grew", async () => {
    const opts = { logUrl: log.url, anchorUrl: anchorHost.url, anchorAddress: chain.address, anchorRpcUrls: [RPC], fetch: rpcFetch({ [RPC]: net }) };
    const later = Date.now() + 14 * 3_600_000;
    expect((await checkLog({ ...opts, now: () => later })).checks.find((c) => c.name === "anchor is running and keeps up")).toMatchObject({ ok: false });
    await post("h");
    await publisher.publishOnce();
    net.baseFeeGwei = 50n;
    await anchor.runOnce();
    net.baseFeeGwei = 2n;
    const beat = JSON.parse(readFileSync(join(outDir(), "default", "checked.json"), "utf8")) as { behindSince: string | null };
    expect(beat.behindSince).not.toBeNull();
    const behind = Date.parse(beat.behindSince!) + 14 * 3_600_000;
    // a fresh heartbeat does not hide a log that has stayed ahead of its anchor
    writeFileSync(join(outDir(), "default", "checked.json"), JSON.stringify({ ...beat, at: new Date(behind).toISOString() }));
    expect((await checkLog({ ...opts, now: () => behind })).checks.find((c) => c.name === "anchor is running and keeps up")).toMatchObject({ ok: false, detail: expect.stringMatching(/behind the log/) });
    // once anchored, it is clear again
    await anchor.runOnce();
    net.mine();
    await anchor.runOnce();
    expect((JSON.parse(readFileSync(join(outDir(), "default", "checked.json"), "utf8")) as { behindSince: string | null }).behindSince).toBeNull();
    expect((await checkLog(opts)).ok).toBe(true);
  });

  it("one transaction anchors several logs, and each log's record proves only its own checkpoint", async () => {
    const logKey = loadPrivateKey(logKp.keyFile);
    const acme = { treeSize: 9, rootHash: "cd".repeat(32), timestamp: new Date().toISOString(), log: "acme-log" };
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(cpDir(), "acme"), { recursive: true });
    writeFileSync(join(cpDir(), "acme", "latest.json"), JSON.stringify({ tenant: "acme", logId: "acme-log", ...acme, signedAt: acme.timestamp, envelope: dsseSign(TREEHEAD_TYPE, acme, logKey) }));
    const both = new Anchor({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default", "acme"], chain, outDir: join(dir, "anchor-both"), waitMs: 0, warn: () => {} });
    const before = net.sent.length;
    expect((await both.runOnce()).tenants.map((t) => t.outcome)).toEqual(["moved", "moved"]);
    expect(net.sent.length).toBe(before + 1);
    net.mine();
    expect((await both.runOnce()).tx).toMatchObject({ outcome: "anchored", tenants: ["default", "acme"] });
    const read = (t: string) => JSON.parse(readFileSync(join(dir, "anchor-both", t, "latest.json"), "utf8")) as AnchorRecord;
    const [d, a] = [read("default"), read("acme")];
    expect(d.anchor.txHash).toBe(a.anchor.txHash);
    expect(d.anchor.proof.treeSize).toBe(2);
    // a record holds its own checkpoint and a proof, never the other log's checkpoint
    expect(JSON.stringify(d)).not.toContain("acme");
    expect((await check(d)).ok).toBe(true);
    expect((await check(a)).ok).toBe(true);
    // the other log's proof does not prove this log's checkpoint
    expect(await check({ ...d, anchor: { ...d.anchor, proof: a.anchor.proof } })).toMatchObject({ ok: false, error: expect.stringMatching(/not under the anchored root/) });
  });

  it("an installation can anchor on another EVM chain, and a record is checked against the chain it names", async () => {
    // Base is an OP Stack chain: viem's own definition, with its formatters, signs and reads the transactions
    const base = devnet(8453);
    const onBase = await evmChain({ rpcUrl: RPC, privateKey: generatePrivateKey(), chainId: 8453, maxFeeGwei: ANCHOR_CHAINS.base!.maxFeeGwei, provider: base });
    expect(onBase.chainId).toBe(8453);
    base.baseFeeGwei = 0n;
    const a = new Anchor({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default"], chain: onBase, outDir: join(dir, "anchor-base"), waitMs: 0, warn: () => {} });
    expect((await a.runOnce()).tx.outcome).toBe("pending");
    // the transaction was signed for Base: a replay on another chain would not verify
    expect(base.sent[0]!.from).toBe(onBase.address);
    base.mine();
    expect((await a.runOnce()).tx.outcome).toBe("anchored");
    const r = JSON.parse(readFileSync(join(dir, "anchor-base", "default", "latest.json"), "utf8")) as AnchorRecord;
    expect(r.anchor.chainId).toBe(8453);
    const via = { rpcUrls: [RPC], address: onBase.address, logKeys, fetch: rpcFetch({ [RPC]: base }) };
    expect(await checkAnchorRecord(r, { ...via, chainId: 8453 })).toMatchObject({ ok: true });
    // a verifier pinned to Ethereum refuses a Base record, and a Base record checked through an Ethereum endpoint fails
    expect(await checkAnchorRecord(r, { ...via, chainId: 1 })).toMatchObject({ ok: false, error: "anchored on chain 8453, expected 1" });
    expect(await checkAnchorRecord(r, { ...via, chainId: 8453, fetch: rpcFetch({ [RPC]: net }) })).toMatchObject({ ok: false, error: expect.stringMatching(/is chain 1, expected 8453/) });
    // the Base default cap is 1 gwei, so fees that Ethereum's cap of 20 would allow are refused there
    await post("i");
    await publisher.publishOnce();
    base.baseFeeGwei = 5n;
    expect((await a.runOnce()).tx).toMatchObject({ outcome: "failed", reason: expect.stringMatching(/above the cap of 1$/) });
  });

  it("an anchor URL without a pinned address or an endpoint is a failure, not a silent skip", async () => {
    const r = await checkLog({ logUrl: log.url, anchorUrl: anchorHost.url });
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === "anchor verifies on chain")).toMatchObject({ ok: false, detail: expect.stringMatching(/pinned anchor address/) });
  });
});

describe("choosing the anchor's chain", () => {
  it("names the common EVM chains, defaulting to Ethereum, and takes any other chain by its id", () => {
    expect(resolveAnchorChain("ethereum")).toEqual({ name: "ethereum", chainId: 1, maxFeeGwei: 20 });
    expect(resolveAnchorChain("base")).toMatchObject({ chainId: 8453 });
    expect(resolveAnchorChain("arbitrum")).toMatchObject({ chainId: 42161 });
    expect(resolveAnchorChain("optimism")).toMatchObject({ chainId: 10 });
    expect(resolveAnchorChain("polygon")).toMatchObject({ chainId: 137 });
    // a named chain's id gets that chain's defaults
    expect(resolveAnchorChain("8453")).toEqual(resolveAnchorChain("base"));
    // any other chain id has no default cap: whoever picks the chain picks what an anchor may cost there
    expect(resolveAnchorChain("11155111")).toEqual({ name: undefined, chainId: 11155111, maxFeeGwei: undefined });
    expect(() => resolveAnchorChain("solana")).toThrow(/unknown chain "solana"/);
    expect(() => resolveAnchorChain("constructor")).toThrow(/unknown chain/);
    expect(() => resolveAnchorChain("0x1")).toThrow(/unknown chain/);
  });

  it("the anchor command refuses a chain id with no default cap unless --max-fee-gwei is given", () => {
    const cli = join(import.meta.dirname, "..", "src", "cli.ts");
    const args = ["--import", "tsx", cli, "anchor", "--log-url", "http://127.0.0.1:9/", "--checkpoints-url", "http://127.0.0.1:9/", "--out", mkdtempSync(join(tmpdir(), "anchor-cli-")), "--rpc-url-env", "ANCHOR_TEST_RPC", "--key-env", "ANCHOR_TEST_KEY", "--once"];
    const env = { ...process.env, ANCHOR_TEST_RPC: "http://127.0.0.1:9/", ANCHOR_TEST_KEY: generatePrivateKey() };
    const r = spawnSync(process.execPath, [...args, "--chain", "11155111"], { encoding: "utf8", timeout: 30_000, env });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/chain 11155111 has no default fee cap; give --max-fee-gwei/);
    const bad = spawnSync(process.execPath, [...args, "--chain", "solana"], { encoding: "utf8", timeout: 30_000, env });
    expect(bad.stderr).toMatch(/unknown chain "solana"/);
  });
});
