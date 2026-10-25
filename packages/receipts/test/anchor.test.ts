// The anchor exists so a verifier does not have to trust the log's operator, its checkpoints host, or even the
// anchor's own host: a rewritten tree is caught from the chain alone. These tests run a real log with published
// checkpoints, a static host for them, and an in-process chain that signs-and-recovers real Ethereum transactions,
// so the sender a verifier checks is the one that signed. Nothing reaches the network.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
  const blocks: { number: number; hash: string; timestamp: number }[] = [{ number: 0, hash: keccak256(toHex(`genesis ${chainId}`)), timestamp: Math.floor(Date.now() / 1000) - 3600 }];
  let forks = 0;
  const net = {
    baseFeeGwei: 2n,
    finalizedLag: 0,
    revertNext: false,
    sent: [] as Tx[],
    mine(include = true) {
      const prev = blocks[blocks.length - 1]!;
      const b = { number: prev.number + 1, hash: keccak256(toHex(`block ${prev.number + 1} fork ${forks}`)), timestamp: prev.timestamp + 12 };
      blocks.push(b);
      if (include) for (const tx of txs.values()) if (tx.blockNumber === null) tx.blockNumber = b.number;
      return b.number;
    },
    /** drops every block from `n` on; their transactions go back to the mempool, or are lost with `drop` */
    reorg(n: number, drop = false) {
      forks++;
      blocks.length = n;
      for (const [hash, tx] of txs) {
        if (tx.blockNumber === null || tx.blockNumber < n) continue;
        if (drop) txs.delete(hash);
        else tx.blockNumber = null;
      }
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
          // "latest" counts mined transactions; "pending" (what a signer asks for its next nonce) counts the mempool too
          return toHex([...txs.values()].filter((t) => t.from === who && (p[1] !== "latest" || t.blockNumber !== null)).length);
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
  const appendTo = (url: string, leaf: string) => fetch(new URL("append", url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf }) });
  const post = (leaf: string) => appendTo(log.url, leaf);
  const record = (name = "latest.json", tenant = "default", out = outDir()) => JSON.parse(readFileSync(join(out, tenant, name), "utf8")) as AnchorRecord;
  const check = (r: AnchorRecord, extra: Partial<Parameters<typeof checkAnchorRecord>[1]> = {}) => checkAnchorRecord(r, { rpcUrls: [RPC], address: chain.address, chainId: 1, logKeys, fetch: rpcFetch({ [RPC]: net }), ...extra });
  const watch = (extra: Partial<Parameters<typeof checkLog>[0]> = {}) => checkLog({ logUrl: log.url, anchorUrl: anchorHost.url, anchorAddress: chain.address, anchorRpcUrls: [RPC], anchorLogIds: { default: "anchored-log" }, fetch: rpcFetch({ [RPC]: net }), ...extra });
  const named = (r: { checks: { name: string }[] }, name: string) => r.checks.find((c) => c.name === name);
  /** a log under the same key and log id with another history: what an operator rewriting the log would serve */
  const forgedLog = async (leaves: string[]) => {
    const forged = await serveLog(fileResolver(join(dir, `forged-${leaves.join("")}.jsonl`), { logId: "anchored-log" }), localSigner(loadPrivateKey(logKp.keyFile)), { port: 0 });
    for (const leaf of leaves) await appendTo(forged.url, leaf);
    return forged;
  };

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

  it("sends nothing until there is a checkpoint, then one transaction from its own address to itself, settled only once finalized", async () => {
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
    expect(existsSync(join(outDir(), "default", "latest.json"))).toBe(false);
    // in a block but not finalized: the record is published, and the anchor keeps the transaction pending
    net.finalizedLag = 2;
    net.mine();
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "included", txHash: tx.hash });
    expect(anchorCalldata(record().anchor.root)).toBe(tx.input);
    expect(await check(record())).toMatchObject({ ok: true, finalized: false, newer: 0 });
    expect(anchor.pending).toBe(true);
    net.mine();
    net.mine();
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "anchored", txHash: tx.hash, tenants: ["default"] });
    expect(anchor.pending).toBe(false);
    expect(await check(record())).toMatchObject({ ok: true, finalized: true, blockNumber: record().anchor.blockNumber });
    expect(JSON.parse(readFileSync(join(outDir(), ".well-known", "agent-custody-anchor.json"), "utf8"))).toEqual({ chainId: 1, address: chain.address });
    net.finalizedLag = 0;
  });

  it("finality is the least-finalized endpoint's, and endpoints on two sides of a fork do not agree", async () => {
    const RPC2 = "http://rpc2.devnet.test/";
    expect(await check(record(), { rpcUrls: [RPC, RPC2], fetch: rpcFetch({ [RPC]: net, [RPC2]: net }) })).toMatchObject({ ok: true, finalized: true });
    expect(await check(record(), { rpcUrls: [RPC, RPC2], fetch: rpcFetch({ [RPC]: net, [RPC2]: notFinalized(net) }) })).toMatchObject({ ok: true, finalized: false });
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
    await publisher.publishOnce();
    expect((await anchor.runOnce()).tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 4 }]);
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
  });

  it("holds a transaction in flight: overlapping runs share one pass, and nothing new is sent until it is finalized", async () => {
    await post("e");
    await publisher.publishOnce();
    const before = net.sent.length;
    const [a, b] = await Promise.all([anchor.runOnce(), anchor.runOnce()]);
    expect(a).toBe(b);
    expect(net.sent.length).toBe(before + 1);
    await post("f");
    await publisher.publishOnce();
    expect((await anchor.runOnce()).tx.outcome).toBe("pending");
    // in a block, not yet finalized: still held, so one nonce is never used twice
    net.finalizedLag = 1;
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("included");
    expect(net.sent.length).toBe(before + 1);
    net.finalizedLag = 0;
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
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "failed", reason: expect.stringMatching(/above the cap of 20/) });
    expect(net.sent.length).toBe(before);
    net.baseFeeGwei = 2n;
    net.revertNext = true;
    expect((await anchor.runOnce()).tx.outcome).toBe("pending");
    net.mine();
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "failed", reason: expect.stringMatching(/failed in block/) });
    expect((await anchor.runOnce()).tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 7 }]);
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
    expect(record().treeSize).toBe(7);
  });

  it("follows a transaction that a reorg moves to another block, and resends one that a reorg drops", async () => {
    await post("h");
    await publisher.publishOnce();
    net.finalizedLag = 3;
    await anchor.runOnce();
    const first = net.mine();
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "included", blockNumber: first });
    // the block is reorged away before it is finalized; the transaction goes back to the mempool
    net.reorg(first);
    expect((await anchor.runOnce()).tx.outcome).toBe("pending");
    expect(await check(record())).toMatchObject({ ok: false });
    // the new branch's first block leaves it out; the next one takes it
    net.mine(false);
    net.mine();
    // the record follows the transaction to the block it is in now
    expect((await anchor.runOnce()).tx).toMatchObject({ outcome: "included" });
    expect(record().anchor.blockNumber).not.toBe(first);
    expect(await check(record())).toMatchObject({ ok: true, finalized: false });
    net.finalizedLag = 0;
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
    expect(record().treeSize).toBe(8);

    // this time the reorg drops the transaction for good: after resendAfterMs the same root goes out again
    const resending = new Anchor({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default"], chain, outDir: outDir(), waitMs: 0, resendAfterMs: 0, warn: () => {} });
    await post("i");
    await publisher.publishOnce();
    net.finalizedLag = 3;
    await resending.runOnce();
    const lost = net.sent[net.sent.length - 1]!;
    const n = net.mine();
    expect((await resending.runOnce()).tx.outcome).toBe("included");
    net.reorg(n, true);
    const before = net.sent.length;
    expect((await resending.runOnce()).tx.outcome).toBe("pending");
    expect((await resending.runOnce()).tx.outcome).toBe("pending");
    expect(net.sent.length).toBe(before + 1);
    // the same root, sent again: with the dropped transaction's nonce free, it may even be the same signed transaction
    const resent = net.sent[net.sent.length - 1]!;
    expect(resent.input).toBe(lost.input);
    net.finalizedLag = 0;
    net.mine();
    expect((await resending.runOnce()).tx).toMatchObject({ outcome: "anchored", txHash: resent.hash });
    expect(await check(record())).toMatchObject({ ok: true, newer: 0 });
  });

  it("a verifier refuses a record that does not match the chain, whoever edited it", async () => {
    const good = record();
    expect((await check(good)).ok).toBe(true);
    expect(await check(good, { address: `0x${"11".repeat(20)}` })).toMatchObject({ ok: false, error: expect.stringMatching(/pinned anchor/) });
    const other = record("2.json");
    expect(await check({ ...good, checkpoint: other.checkpoint })).toMatchObject({ ok: false, error: expect.stringMatching(/not the checkpoint's/) });
    expect(await check({ ...good, anchor: { ...good.anchor, proof: { leafIndex: 0, treeSize: 2, hashes: ["ab".repeat(32)] } } })).toMatchObject({ ok: false, error: expect.stringMatching(/not under the anchored root/) });
    expect(await check({ ...other, anchor: { ...other.anchor, txHash: good.anchor.txHash, blockNumber: good.anchor.blockNumber } })).toMatchObject({ ok: false, error: expect.stringMatching(/does not carry the anchored root/) });
    const fake = { hash: keccak256(toHex("someone else")), from: `0x${"22".repeat(20)}`, to: chain.address, input: anchorCalldata(good.anchor.root), nonce: 0, status: "0x1" as const };
    net.inject(fake);
    const n = net.mine();
    expect(await check({ ...good, anchor: { ...good.anchor, txHash: fake.hash, blockNumber: n } })).toMatchObject({ ok: false, error: expect.stringMatching(/not from the anchor to itself/) });
    const testnet = devnet(11155111);
    expect(await check(good, { fetch: rpcFetch({ [RPC]: testnet }) })).toMatchObject({ ok: false, error: expect.stringMatching(/chain 11155111/) });
    // an older record is still a genuine anchor, but the chain says the address has sent anchors since
    expect(await check(other)).toMatchObject({ ok: true, newer: expect.any(Number) });
    expect(((await check(other)) as { newer: number }).newer).toBeGreaterThan(0);
  });

  it("log-check catches a rewritten tree from the chain alone, with the log's checkpoints host out of the picture", async () => {
    const honest = await watch();
    expect(honest.ok).toBe(true);
    expect(honest.checks.map((c) => c.name)).toEqual(["key document served", "head verifies against the published keys", "anchor verifies on chain", "anchor and head name the pinned log", "anchor is the newest from its address", "head extends the anchored checkpoint", "anchor keeps up with the log"]);
    const forged = await forgedLog(["a", "b", "x", "y", "z", "w", "v", "u", "t", "s"]);
    try {
      expect(named(await watch({ logUrl: forged.url }), "head extends the anchored checkpoint")).toMatchObject({ ok: false, detail: expect.stringMatching(/history was rewritten/) });
    } finally {
      await forged.close();
    }
    const short = await forgedLog(["a"]);
    try {
      expect(named(await watch({ logUrl: short.url }), "head extends the anchored checkpoint")).toMatchObject({ ok: false, detail: expect.stringMatching(/rolled back/) });
    } finally {
      await short.close();
    }
  });

  it("log-check refuses an older genuine anchor passed off as the current one, so a rewrite after it is not hidden", async () => {
    // the anchor host serves the size-2 record as latest, and the operator rewrites the log after leaf 2: from the
    // older record alone the forged log extends it, but the chain shows the address has sent anchors since
    const replay = join(dir, "replayed-anchor");
    const { cpSync } = await import("node:fs");
    cpSync(outDir(), replay, { recursive: true });
    writeFileSync(join(replay, "default", "latest.json"), readFileSync(join(outDir(), "default", "2.json")));
    const replayHost = await staticHost(replay);
    const forged = await forgedLog(["a", "b", "x"]);
    try {
      const r = await watch({ logUrl: forged.url, anchorUrl: replayHost.url });
      expect(named(r, "head extends the anchored checkpoint")).toMatchObject({ ok: true });
      expect(named(r, "anchor is the newest from its address")).toMatchObject({ ok: false, detail: expect.stringMatching(/not the current anchor/) });
      expect(r.ok).toBe(false);
    } finally {
      await forged.close();
      replayHost.server.close();
    }
  });

  it("log-check refuses another log's anchor served for this log, and will not check an anchor without a pinned log id", async () => {
    // a second tenant under the same log key and anchor address, anchored at size 0
    const logKey = loadPrivateKey(logKp.keyFile);
    const empty = { treeSize: 0, rootHash: createHash("sha256").update("").digest("hex"), timestamp: new Date().toISOString(), log: "other-tenant" };
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(cpDir(), "other"), { recursive: true });
    writeFileSync(join(cpDir(), "other", "latest.json"), JSON.stringify({ tenant: "other", logId: "other-tenant", ...empty, signedAt: empty.timestamp, envelope: dsseSign(TREEHEAD_TYPE, empty, logKey) }));
    const both = new Anchor({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default", "other"], chain, outDir: join(dir, "anchor-other"), waitMs: 0, warn: () => {} });
    await both.runOnce();
    net.mine();
    expect((await both.runOnce()).tx.outcome).toBe("anchored");
    // the other tenant's genuine record, served where this log's should be, beside a rewritten history of this log
    const swapped = join(dir, "swapped-anchor");
    const { cpSync } = await import("node:fs");
    cpSync(join(dir, "anchor-other"), swapped, { recursive: true });
    writeFileSync(join(swapped, "default", "latest.json"), readFileSync(join(dir, "anchor-other", "other", "latest.json")));
    const swappedHost = await staticHost(swapped);
    const forged = await forgedLog(["p", "q", "r"]);
    try {
      const r = await watch({ logUrl: forged.url, anchorUrl: swappedHost.url });
      expect(named(r, "anchor and head name the pinned log")).toMatchObject({ ok: false, detail: expect.stringMatching(/pinned anchored-log, anchored other-tenant/) });
      expect(r.ok).toBe(false);
      // and this log's own record beside a head that names another log is refused too
      const imposter = await serveLog(fileResolver(join(dir, "imposter.jsonl"), { logId: "other-tenant" }), localSigner(logKey), { port: 0 });
      try {
        for (const leaf of ["a", "b", "c", "d"]) await appendTo(imposter.url, leaf);
        expect(named(await watch({ logUrl: imposter.url }), "anchor and head name the pinned log")).toMatchObject({ ok: false, detail: expect.stringMatching(/head other-tenant/) });
      } finally {
        await imposter.close();
      }
      const unpinned = await watch({ anchorLogIds: {} });
      expect(unpinned.ok).toBe(false);
      expect(named(unpinned, "anchor verifies on chain")).toMatchObject({ ok: false, detail: expect.stringMatching(/log id of default pinned/) });
    } finally {
      await forged.close();
      swappedHost.server.close();
    }
  });

  it("log-check fails a log that stays ahead of its newest anchor, timed by the anchor's block, not by the anchor's host", async () => {
    // the anchor in this directory is at the head; a log that grows past it is fine until the anchor is older than the lag
    await post("j");
    const ahead = await watch();
    expect(named(ahead, "anchor keeps up with the log")).toMatchObject({ ok: true, detail: expect.stringMatching(/ahead of an anchor/) });
    const later = Date.now() + 14 * 3_600_000;
    expect(named(await watch({ now: () => later }), "anchor keeps up with the log")).toMatchObject({ ok: false });
    // an anchor at the head is never behind, however old
    await publisher.publishOnce();
    await anchor.runOnce();
    net.mine();
    expect((await anchor.runOnce()).tx.outcome).toBe("anchored");
    expect(named(await watch({ now: () => later }), "anchor keeps up with the log")).toMatchObject({ ok: true });
  });

  it("one transaction covers every log, unchanged ones at their last checkpoint, and each record proves only its own", async () => {
    const logKey = loadPrivateKey(logKp.keyFile);
    const acme = { treeSize: 9, rootHash: "cd".repeat(32), timestamp: new Date().toISOString(), log: "acme-log" };
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(cpDir(), "acme"), { recursive: true });
    writeFileSync(join(cpDir(), "acme", "latest.json"), JSON.stringify({ tenant: "acme", logId: "acme-log", ...acme, signedAt: acme.timestamp, envelope: dsseSign(TREEHEAD_TYPE, acme, logKey) }));
    const out = join(dir, "anchor-both");
    const both = new Anchor({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default", "acme"], chain, outDir: out, waitMs: 0, warn: () => {} });
    const before = net.sent.length;
    expect((await both.runOnce()).tenants.map((t) => t.outcome)).toEqual(["moved", "moved"]);
    expect(net.sent.length).toBe(before + 1);
    net.mine();
    expect((await both.runOnce()).tx).toMatchObject({ outcome: "anchored", tenants: ["default", "acme"] });
    const [d, a] = [record("latest.json", "default", out), record("latest.json", "acme", out)];
    expect(d.anchor.txHash).toBe(a.anchor.txHash);
    expect(JSON.stringify(d)).not.toContain("acme");
    expect((await check(d)).ok).toBe(true);
    expect((await check(a)).ok).toBe(true);
    expect(await check({ ...d, anchor: { ...d.anchor, proof: a.anchor.proof } })).toMatchObject({ ok: false, error: expect.stringMatching(/not under the anchored root/) });
    // only the default log grows; acme is anchored again at its last checkpoint, in the newest transaction
    await post("k");
    await publisher.publishOnce();
    expect((await both.runOnce()).tenants).toEqual([{ tenant: "default", outcome: "moved", treeSize: 11 }, { tenant: "acme", outcome: "unchanged", treeSize: 9 }]);
    net.mine();
    expect((await both.runOnce()).tx).toMatchObject({ outcome: "anchored", tenants: ["default", "acme"] });
    const acmeNow = record("latest.json", "acme", out);
    expect(acmeNow.treeSize).toBe(9);
    expect(acmeNow.anchor.txHash).not.toBe(a.anchor.txHash);
    expect(await check(acmeNow)).toMatchObject({ ok: true, newer: 0 });
  });

  it("an installation can anchor on another EVM chain, and a record is checked against the chain it names", async () => {
    // Base is an OP Stack chain: viem's own definition, with its formatters, signs and reads the transactions
    const base = devnet(8453);
    const onBase = await evmChain({ rpcUrl: RPC, privateKey: generatePrivateKey(), chainId: 8453, maxFeeGwei: ANCHOR_CHAINS.base!.maxFeeGwei, provider: base });
    expect(onBase.chainId).toBe(8453);
    base.baseFeeGwei = 0n;
    const a = new Anchor({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default"], chain: onBase, outDir: join(dir, "anchor-base"), waitMs: 0, warn: () => {} });
    expect((await a.runOnce()).tx.outcome).toBe("pending");
    expect(base.sent[0]!.from).toBe(onBase.address);
    base.mine();
    expect((await a.runOnce()).tx.outcome).toBe("anchored");
    const r = record("latest.json", "default", join(dir, "anchor-base"));
    expect(r.anchor.chainId).toBe(8453);
    const via = { rpcUrls: [RPC], address: onBase.address, logKeys, fetch: rpcFetch({ [RPC]: base }) };
    expect(await checkAnchorRecord(r, { ...via, chainId: 8453 })).toMatchObject({ ok: true });
    expect(await checkAnchorRecord(r, { ...via, chainId: 1 })).toMatchObject({ ok: false, error: "anchored on chain 8453, expected 1" });
    expect(await checkAnchorRecord(r, { ...via, chainId: 8453, fetch: rpcFetch({ [RPC]: net }) })).toMatchObject({ ok: false, error: expect.stringMatching(/is chain 1, expected 8453/) });
    await post("l");
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
