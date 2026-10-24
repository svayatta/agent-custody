// The anchor: a public chain as a witness nobody can collude with. It watches a log's published checkpoints the way
// the witness does, and after proving that each new one extends the last one it anchored, it commits a Merkle root
// over the new checkpoints of every watched log in one transaction from a published address. Each log gets a
// record with its checkpoint and its inclusion proof, so it can be checked without seeing the other logs. A rewritten
// tree is then caught from the chain alone, without trusting the log's operator, its checkpoints host, or the anchor's
// own host. What a chain proves is that a checkpoint existed by a block's time; it says nothing about whether the
// receipts under it are true.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, dsseVerify, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { inclusionProof, leafHash, rootOf, verifyConsistency, verifyInclusion, type InclusionProof } from "./log.ts";
import { TREEHEAD_TYPE, type TreeHead } from "./receipt.ts";
import { fetchLogKeys } from "./signer.ts";

/**
 * EVM chains known by name, with the chain id and a default fee cap in gwei per gas, sized to what one anchor costs
 * there. Any other EVM chain is named by its chain id and needs an explicit cap.
 */
export const ANCHOR_CHAINS: Record<string, { chainId: number; maxFeeGwei: number }> = {
  ethereum: { chainId: 1, maxFeeGwei: 20 },
  base: { chainId: 8453, maxFeeGwei: 1 },
  arbitrum: { chainId: 42161, maxFeeGwei: 1 },
  optimism: { chainId: 10, maxFeeGwei: 1 },
  polygon: { chainId: 137, maxFeeGwei: 1000 },
};

/** A chain name from `ANCHOR_CHAINS`, or a decimal chain id; `maxFeeGwei` is undefined for an id with no known default. */
export function resolveAnchorChain(chain: string): { name: string | undefined; chainId: number; maxFeeGwei: number | undefined } {
  const known = Object.hasOwn(ANCHOR_CHAINS, chain) ? ANCHOR_CHAINS[chain] : undefined;
  if (known) return { name: chain, ...known };
  if (!/^[1-9][0-9]{0,15}$/.test(chain)) throw new Error(`unknown chain "${chain}": use ${Object.keys(ANCHOR_CHAINS).join(", ")}, or a chain id`);
  const chainId = Number(chain);
  const named = Object.entries(ANCHOR_CHAINS).find(([, c]) => c.chainId === chainId);
  return named ? { name: named[0], ...named[1] } : { name: undefined, chainId, maxFeeGwei: undefined };
}

/** The chain the anchor writes to. `evmChain` in `anchor-evm.ts` is the one this package ships. */
export interface AnchorChain {
  chainId: number;
  /** the anchor's address, lowercase hex; every anchor is a zero-value transaction from it to itself */
  address: string;
  /** sends `data` as calldata and resolves to the transaction hash; throws when fees are above the cap */
  send(data: string): Promise<string>;
  /** null while the transaction is not in a block */
  included(txHash: string): Promise<{ blockNumber: number; ok: boolean } | null>;
}

export interface AnchorOptions {
  /** the log's API base; the key document and consistency proofs come from here */
  logUrl: string;
  /** where the log publishes checkpoints */
  checkpointsUrl: string;
  /** "default" for the root paths, else tenant names */
  tenants: string[];
  chain: AnchorChain;
  /** where anchor records, alarms, the anchor's document, and its state go; serve it read-only */
  outDir: string;
  /** how long a run waits for its transaction to land before leaving it for the next run; default ten minutes */
  waitMs?: number;
  pollMs?: number;
  fetch?: typeof fetch;
  warn?: (message: string) => void;
}

export interface AnchorRecord {
  tenant: string;
  logId: string | undefined;
  treeSize: number;
  rootHash: string;
  /** the log's signed checkpoint, exactly as published */
  checkpoint: Envelope;
  anchor: { chainId: number; address: string; txHash: string; blockNumber: number; root: string; proof: InclusionProof; sentAt: string };
}

export type AnchorTenantOutcome =
  | { tenant: string; outcome: "moved"; treeSize: number }
  | { tenant: string; outcome: "unchanged"; treeSize: number }
  | { tenant: string; outcome: "refused"; reason: string }
  | { tenant: string; outcome: "unavailable"; reason: string };

export type AnchorTxOutcome =
  | { outcome: "anchored"; txHash: string; blockNumber: number; tenants: string[] }
  | { outcome: "pending"; txHash: string; sentAt: string }
  | { outcome: "none" }
  | { outcome: "failed"; reason: string };

export interface AnchorRun {
  tenants: AnchorTenantOutcome[];
  tx: AnchorTxOutcome;
}

interface Entry {
  tenant: string;
  logId: string | undefined;
  treeSize: number;
  rootHash: string;
  checkpoint: Envelope;
}

interface State {
  /** the last checkpoint anchored for each log */
  anchored: Record<string, { treeSize: number; rootHash: string; logId: string | undefined }>;
  pending?: { txHash: string; root: string; sentAt: string; entries: Entry[] };
  /** when each log was first seen ahead of its last anchor, until that is anchored */
  behind?: Record<string, string>;
}

/** Written for each log on every run, so a monitor can tell a stopped or stuck anchor from a quiet log. */
export interface AnchorHeartbeat {
  at: string;
  anchoredSize: number | null;
  behindSince: string | null;
}

const safe = (s: string) => s.replace(/[^A-Za-z0-9_.-]/g, "_");
const slash = (u: string) => (u.endsWith("/") ? u : `${u}/`);
const TAG = Buffer.from("agent-custody/anchor/1:").toString("hex");

/** The calldata of the anchor transaction for a Merkle root: a fixed tag, then the 32-byte root. */
export function anchorCalldata(rootHex: string): string {
  if (!/^[0-9a-f]{64}$/.test(rootHex)) throw new Error("an anchor root is 32 bytes of lowercase hex");
  return `0x${TAG}${rootHex}`;
}

/** The leaf of a checkpoint in the anchor's tree: the canonical bytes of the log's signed envelope. */
export const anchorLeaf = (checkpoint: Envelope): Buffer => leafHash(canonicalize(checkpoint));

export class Anchor {
  private readonly o: AnchorOptions;
  private readonly f: typeof fetch;
  private readonly warn: (m: string) => void;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running: Promise<AnchorRun> | null = null;
  constructor(opts: AnchorOptions) {
    this.o = opts;
    this.f = opts.fetch ?? fetch;
    this.warn = opts.warn ?? ((m) => console.error(m));
    mkdirSync(join(opts.outDir, ".well-known"), { recursive: true });
    // for discovery only: a verifier pins the address it was given, never this file's
    writeFileSync(join(opts.outDir, ".well-known", "agent-custody-anchor.json"), JSON.stringify({ chainId: opts.chain.chainId, address: opts.chain.address }, null, 2));
  }

  get address(): string {
    return this.o.chain.address;
  }

  private load(): State {
    try {
      return JSON.parse(readFileSync(join(this.o.outDir, "state.json"), "utf8")) as State;
    } catch {
      return { anchored: {} };
    }
  }

  private save(s: State): void {
    const file = join(this.o.outDir, "state.json");
    writeFileSync(`${file}.tmp`, JSON.stringify(s, null, 2));
    renameSync(`${file}.tmp`, file);
  }

  private async get(url: URL): Promise<Response> {
    return this.f(url, { signal: AbortSignal.timeout(10_000) });
  }

  private async latest(tenant: string): Promise<{ envelope: Envelope } | null> {
    const res = await this.get(new URL(`${safe(tenant)}/latest.json`, slash(this.o.checkpointsUrl)));
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`checkpoint for ${tenant}: ${res.status}`);
    return (await res.json()) as { envelope: Envelope };
  }

  private async proof(tenant: string, oldSize: number, newSize: number): Promise<string[]> {
    const path = tenant === "default" ? `consistency?old=${oldSize}&new=${newSize}` : `t/${tenant}/consistency?old=${oldSize}&new=${newSize}`;
    const res = await this.get(new URL(path, slash(this.o.logUrl)));
    if (!res.ok) throw new Error(`consistency proof for ${tenant}: ${res.status}`);
    return ((await res.json()) as { hashes: string[] }).hashes;
  }

  /** One pass. Never throws; runs that overlap share one pass, so two transactions are never in flight at once. */
  runOnce(): Promise<AnchorRun> {
    this.running ??= this.pass().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async pass(): Promise<AnchorRun> {
    const state = this.load();
    const run = await this.passOn(state);
    this.beat(state, run);
    return run;
  }

  private beat(state: State, run: AnchorRun): void {
    const behind = (state.behind ??= {});
    for (const t of run.tenants) if (t.outcome === "moved") behind[t.tenant] ??= new Date().toISOString();
    if (run.tx.outcome === "anchored") for (const t of run.tx.tenants) delete behind[t];
    for (const t of run.tenants) if (t.outcome === "unchanged") delete behind[t.tenant];
    this.save(state);
    const at = new Date().toISOString();
    for (const tenant of this.o.tenants) {
      const dir = join(this.o.outDir, safe(tenant));
      mkdirSync(dir, { recursive: true });
      const beat: AnchorHeartbeat = { at, anchoredSize: state.anchored[tenant]?.treeSize ?? null, behindSince: behind[tenant] ?? null };
      writeFileSync(join(dir, "checked.json"), JSON.stringify(beat, null, 2));
    }
  }

  private async passOn(state: State): Promise<AnchorRun> {
    // a transaction in flight holds the address's nonce: nothing new is sent until it lands, or fails and the next run resends
    if (state.pending) return { tenants: [], tx: await this.settle(state) };
    let keys: PublicKeyRef[];
    try {
      keys = (await fetchLogKeys(slash(this.o.logUrl), this.f)).keys;
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      this.warn(`agent-custody anchor: ${reason}`);
      return { tenants: this.o.tenants.map((tenant) => ({ tenant, outcome: "unavailable", reason })), tx: { outcome: "none" } };
    }
    const tenants: AnchorTenantOutcome[] = [];
    const entries: Entry[] = [];
    for (const tenant of this.o.tenants) {
      try {
        const r = await this.check(tenant, keys, state);
        tenants.push(r.outcome);
        if (r.entry) entries.push(r.entry);
      } catch (e) {
        const reason = e instanceof Error ? e.message : String(e);
        this.warn(`agent-custody anchor: ${tenant}: ${reason}`);
        tenants.push({ tenant, outcome: "unavailable", reason });
      }
    }
    if (entries.length === 0) return { tenants, tx: { outcome: "none" } };
    const root = rootOf(entries.map((e) => anchorLeaf(e.checkpoint)));
    let txHash: string;
    try {
      txHash = await this.o.chain.send(anchorCalldata(root));
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      this.warn(`agent-custody anchor: not sent: ${reason}`);
      return { tenants, tx: { outcome: "failed", reason } };
    }
    state.pending = { txHash, root, sentAt: new Date().toISOString(), entries };
    this.save(state);
    const deadline = Date.now() + (this.o.waitMs ?? 600_000);
    for (;;) {
      const tx = await this.settle(state);
      if (tx.outcome !== "pending" || Date.now() >= deadline) return { tenants, tx };
      await new Promise((r) => setTimeout(r, this.o.pollMs ?? 12_000));
    }
  }

  private async check(tenant: string, keys: PublicKeyRef[], state: State): Promise<{ outcome: AnchorTenantOutcome; entry?: Entry }> {
    const cp = await this.latest(tenant);
    if (!cp) return { outcome: { tenant, outcome: "unavailable", reason: "no checkpoint published yet" } };
    const v = dsseVerify(cp.envelope, keys);
    if (!v.ok || cp.envelope.payloadType !== TREEHEAD_TYPE) return { outcome: this.refuse(tenant, `checkpoint does not verify against the log's published keys: ${v.ok ? "not a tree head" : v.error}`, cp.envelope) };
    const head = v.payload as TreeHead;
    const prev = state.anchored[tenant];
    if (prev) {
      if (prev.logId !== head.log) return { outcome: this.refuse(tenant, `checkpoint names log ${head.log ?? "none"}, the last one anchored named ${prev.logId ?? "none"}`, cp.envelope) };
      if (head.treeSize < prev.treeSize) return { outcome: this.refuse(tenant, `checkpoint at size ${head.treeSize} is smaller than the last one anchored at ${prev.treeSize}`, cp.envelope) };
      if (head.treeSize === prev.treeSize) {
        if (head.rootHash !== prev.rootHash) return { outcome: this.refuse(tenant, `a different root at the same size ${head.treeSize}: the log shows two histories`, cp.envelope) };
        return { outcome: { tenant, outcome: "unchanged", treeSize: head.treeSize } };
      }
      const proof = await this.proof(tenant, prev.treeSize, head.treeSize);
      if (!verifyConsistency(prev.treeSize, prev.rootHash, head.treeSize, head.rootHash, proof)) return { outcome: this.refuse(tenant, `the log at ${head.treeSize} does not extend the head anchored at ${prev.treeSize}: history was rewritten`, cp.envelope) };
    }
    return { outcome: { tenant, outcome: "moved", treeSize: head.treeSize }, entry: { tenant, logId: head.log, treeSize: head.treeSize, rootHash: head.rootHash, checkpoint: cp.envelope } };
  }

  /** Looks the pending transaction up once; writes the records and clears it when it has landed. */
  private async settle(state: State): Promise<AnchorTxOutcome> {
    const p = state.pending!;
    let inc: { blockNumber: number; ok: boolean } | null;
    try {
      inc = await this.o.chain.included(p.txHash);
    } catch (e) {
      this.warn(`agent-custody anchor: looking up ${p.txHash}: ${e instanceof Error ? e.message : String(e)}`);
      return { outcome: "pending", txHash: p.txHash, sentAt: p.sentAt };
    }
    if (inc === null) return { outcome: "pending", txHash: p.txHash, sentAt: p.sentAt };
    delete state.pending;
    if (!inc.ok) {
      this.save(state);
      const reason = `transaction ${p.txHash} failed in block ${inc.blockNumber}`;
      this.warn(`agent-custody anchor: ${reason}; the checkpoints go in the next run`);
      return { outcome: "failed", reason };
    }
    const leaves = p.entries.map((e) => anchorLeaf(e.checkpoint));
    p.entries.forEach((e, i) => {
      const record: AnchorRecord = { tenant: e.tenant, logId: e.logId, treeSize: e.treeSize, rootHash: e.rootHash, checkpoint: e.checkpoint, anchor: { chainId: this.o.chain.chainId, address: this.o.chain.address, txHash: p.txHash, blockNumber: inc.blockNumber, root: p.root, proof: inclusionProof(leaves, i), sentAt: p.sentAt } };
      const dir = join(this.o.outDir, safe(e.tenant));
      mkdirSync(dir, { recursive: true });
      const text = JSON.stringify(record, null, 2);
      writeFileSync(join(dir, `${e.treeSize}.json`), text);
      writeFileSync(join(dir, "latest.json"), text);
      state.anchored[e.tenant] = { treeSize: e.treeSize, rootHash: e.rootHash, logId: e.logId };
    });
    this.save(state);
    return { outcome: "anchored", txHash: p.txHash, blockNumber: inc.blockNumber, tenants: p.entries.map((e) => e.tenant) };
  }

  /** An alarm is written where the records would have gone, so whoever reads the anchor's host sees it. */
  private refuse(tenant: string, reason: string, envelope: Envelope): AnchorTenantOutcome {
    const dir = join(this.o.outDir, safe(tenant));
    mkdirSync(dir, { recursive: true });
    const at = new Date().toISOString();
    const stamp = at.replace(/[:.]/g, "-");
    let file = join(dir, `ALARM-${stamp}.json`);
    for (let n = 2; existsSync(file); n++) file = join(dir, `ALARM-${stamp}-${n}.json`);
    writeFileSync(file, JSON.stringify({ tenant, at, reason, checkpoint: envelope }, null, 2));
    writeFileSync(join(dir, "ALARM.json"), JSON.stringify({ tenant, at, reason }, null, 2));
    this.warn(`agent-custody anchor: REFUSED ${tenant}: ${reason}`);
    return { tenant, outcome: "refused", reason };
  }

  start(everyMs = 21_600_000): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.runOnce(), everyMs);
    this.timer.unref?.();
    void this.runOnce();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    await this.running;
  }
}

export interface AnchorCheckOptions {
  /** JSON-RPC endpoints of the chain; with more than one, they must all agree */
  rpcUrls: string[];
  /** the anchor's address, pinned from a source other than the anchor's host */
  address: string;
  chainId: number;
  /** the log's published keys */
  logKeys: PublicKeyRef[];
  fetch?: typeof fetch;
}

export type AnchorCheck =
  | { ok: true; blockNumber: number; blockTime: string; finalized: boolean }
  | { ok: false; error: string };

async function rpc(f: typeof fetch, url: string, method: string, params: unknown[]): Promise<unknown> {
  // the URL can carry a provider's key, so errors name the host only
  const host = new URL(url).host;
  const res = await f(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`${host} ${method}: HTTP ${res.status}`);
  const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
  if (body.error) throw new Error(`${host} ${method}: ${body.error.message ?? "error"}`);
  return body.result;
}

const lower = (s: unknown) => (typeof s === "string" ? s.toLowerCase() : undefined);

/**
 * Checks an anchor record against the chain: the checkpoint is the log's, it is a leaf under the anchored root, and a
 * successful transaction from the pinned address to itself carries exactly that root. Needs no Ethereum library.
 */
export async function checkAnchorRecord(record: AnchorRecord, o: AnchorCheckOptions): Promise<AnchorCheck> {
  const f = o.fetch ?? fetch;
  const address = o.address.toLowerCase();
  const a = record.anchor;
  if (!a || typeof a.txHash !== "string" || typeof a.root !== "string" || !a.proof) return { ok: false, error: "not an anchor record" };
  if (a.chainId !== o.chainId) return { ok: false, error: `anchored on chain ${a.chainId}, expected ${o.chainId}` };
  if (lower(a.address) !== address) return { ok: false, error: `anchored from ${a.address}, the pinned anchor is ${o.address}` };
  const v = dsseVerify(record.checkpoint, o.logKeys);
  if (!v.ok || record.checkpoint.payloadType !== TREEHEAD_TYPE) return { ok: false, error: `checkpoint does not verify against the log's keys: ${v.ok ? "not a tree head" : v.error}` };
  const head = v.payload as TreeHead;
  if (head.treeSize !== record.treeSize || head.rootHash !== record.rootHash || head.log !== record.logId) return { ok: false, error: "the record's size, root, or log id is not the checkpoint's" };
  if (!verifyInclusion(anchorLeaf(record.checkpoint), a.proof, a.root)) return { ok: false, error: "the checkpoint is not under the anchored root" };
  let data: string;
  try {
    data = anchorCalldata(a.root);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  if (o.rpcUrls.length === 0) return { ok: false, error: "no JSON-RPC endpoint to check the chain with" };
  let seen: { blockHash: string; blockNumber: number; blockTime: string; finalized: boolean } | undefined;
  for (const url of o.rpcUrls) {
    try {
      const chainId = Number(await rpc(f, url, "eth_chainId", []));
      if (chainId !== o.chainId) return { ok: false, error: `${new URL(url).host} is chain ${chainId}, expected ${o.chainId}` };
      const tx = (await rpc(f, url, "eth_getTransactionByHash", [a.txHash])) as Record<string, unknown> | null;
      if (!tx) return { ok: false, error: `${new URL(url).host} has no transaction ${a.txHash}` };
      if (lower(tx.from) !== address || lower(tx.to) !== address) return { ok: false, error: `transaction ${a.txHash} is not from the anchor to itself` };
      if (lower(tx.input) !== data) return { ok: false, error: `transaction ${a.txHash} does not carry the anchored root` };
      if (tx.blockNumber == null || Number(tx.blockNumber) !== a.blockNumber) return { ok: false, error: `transaction ${a.txHash} is not in block ${a.blockNumber}` };
      const receipt = (await rpc(f, url, "eth_getTransactionReceipt", [a.txHash])) as Record<string, unknown> | null;
      if (!receipt || receipt.status !== "0x1") return { ok: false, error: `transaction ${a.txHash} did not succeed` };
      const block = (await rpc(f, url, "eth_getBlockByNumber", [`0x${a.blockNumber.toString(16)}`, false])) as Record<string, unknown> | null;
      if (!block || lower(block.hash) !== lower(receipt.blockHash)) return { ok: false, error: `block ${a.blockNumber} is not the one the transaction is in` };
      const fin = (await rpc(f, url, "eth_getBlockByNumber", ["finalized", false])) as Record<string, unknown> | null;
      const here = { blockHash: String(lower(block.hash)), blockNumber: a.blockNumber, blockTime: new Date(Number(block.timestamp) * 1000).toISOString(), finalized: fin !== null && Number(fin.number) >= a.blockNumber };
      if (seen && seen.blockHash !== here.blockHash) return { ok: false, error: `the endpoints disagree on block ${a.blockNumber}` };
      // finality is only as good as the least-finalized endpoint says
      seen = seen ? { ...here, finalized: seen.finalized && here.finalized } : here;
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }
  return { ok: true, blockNumber: seen!.blockNumber, blockTime: seen!.blockTime, finalized: seen!.finalized };
}
