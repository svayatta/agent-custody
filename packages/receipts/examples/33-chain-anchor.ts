// Aspect: anchoring the log's checkpoints on a chain. Source: src/anchor.ts, src/log-check.ts
// Run:    node examples/33-chain-anchor.ts
//
// The log's operator holds the log's key, so a signed checkpoint alone cannot show that the operator never rewrote
// a tenant's tree. The anchor commits each new checkpoint to a public chain from a published address; a monitor then
// checks the log against the chain alone. Here the chain is a small in-memory stand-in that answers the same JSON-RPC
// calls Ethereum does (the tests drive real signed transactions; on Ethereum or another EVM chain, `evmChain` sends them).
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Anchor, type AnchorChain } from "../src/anchor.ts";
import { dirCheckpoints } from "../src/checkpoints.ts";
import { generateKeyPair } from "../src/crypto.ts";
import { checkLog, formatLogCheck } from "../src/log-check.ts";
import { CheckpointPublisher, fileResolver, serveLog } from "../src/log-sink.ts";
import { localSigner } from "../src/signer.ts";
import { out, step } from "./_out.ts";

const dir = out("33-chain-anchor");
const hex = (n: number) => `0x${n.toString(16)}`;

// the stand-in chain: transactions go into a block on the next lookup
const ADDRESS = "0x5afe00000000000000000000000000000000a11c";
const txs = new Map<string, { input: string; block: number | null }>();
let height = 1;
const chain: AnchorChain = {
  chainId: 1,
  address: ADDRESS,
  async send(data) {
    const hash = `0x${createHash("sha256").update(`${txs.size}:${data}`).digest("hex")}`;
    txs.set(hash, { input: data, block: null });
    return hash;
  },
  async included(hash) {
    const t = txs.get(hash)!;
    t.block ??= ++height;
    return { blockNumber: t.block, ok: true };
  },
};
const rpc = async (method: string, params: unknown[]): Promise<unknown> => {
  const t = txs.get(String(params[0]));
  const block = (n: number) => ({ number: hex(n), hash: `0x${createHash("sha256").update(`block ${n}`).digest("hex")}`, timestamp: hex(1_760_000_000 + n * 12) });
  if (method === "eth_chainId") return "0x1";
  if (method === "eth_getTransactionByHash") return t && { from: ADDRESS, to: ADDRESS, input: t.input, blockNumber: t.block === null ? null : hex(t.block) };
  if (method === "eth_getTransactionReceipt") return t?.block && { status: "0x1", blockHash: block(t.block).hash };
  if (method === "eth_getBlockByNumber") return params[0] === "finalized" ? block(height) : block(Number(params[0]));
  return null;
};
const RPC = "http://rpc.example/";
const viaRpc = (async (input: string | URL | Request, init?: RequestInit) => {
  if (String(input) !== RPC) return fetch(input, init);
  const { id, method, params } = JSON.parse(String(init?.body));
  return Response.json({ jsonrpc: "2.0", id, result: await rpc(method, params) });
}) as typeof fetch;

/** A directory served the way the checkpoints and anchor hosts serve theirs. */
const serveDir = (root: string) =>
  new Promise<{ url: string; close: () => void }>((resolve) => {
    const server = createServer((req, res) => {
      const file = join(root, new URL(req.url ?? "/", "http://x").pathname);
      if (!existsSync(file)) return void res.writeHead(404).end();
      res.writeHead(200, { "content-type": "application/json" }).end(readFileSync(file));
    });
    server.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${(server.address() as { port: number }).port}/`, close: () => server.close() }));
  });

step(1, "a log takes three receipts and publishes its checkpoint");
const logKey = generateKeyPair();
const store = dirCheckpoints(join(dir, "checkpoints"));
const resolver = fileResolver(join(dir, "log.jsonl"), { logId: "example-log" });
const log = await serveLog(resolver, localSigner(logKey), { port: 0, checkpoints: store });
const append = (url: string, leaf: string) => fetch(new URL("append", url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf }) });
for (const leaf of ["refund 2500", "refund 1200", "refund 900"]) await append(log.url, leaf);
await new CheckpointPublisher(resolver, localSigner(logKey), store).publishOnce();
const checkpoints = await serveDir(join(dir, "checkpoints"));

step(2, "the anchor commits the signed checkpoint to the chain, in one transaction from its address");
const anchor = new Anchor({ logUrl: log.url, checkpointsUrl: checkpoints.url, tenants: ["default"], chain, outDir: join(dir, "anchor"), waitMs: 0 });
const run = await anchor.runOnce();
console.log(`   ${run.tenants.map((t) => `${t.tenant}: ${t.outcome}`).join(", ")}; transaction ${run.tx.outcome}${"blockNumber" in run.tx ? ` in block ${run.tx.blockNumber}` : ""}`);
const anchorHost = await serveDir(join(dir, "anchor"));

step(3, "a monitor checks the log against the chain, pinning the anchor's address");
const opts = { logUrl: log.url, anchorUrl: anchorHost.url, anchorAddress: ADDRESS, anchorRpcUrls: [RPC], fetch: viaRpc };
const honest = await checkLog(opts);
console.log(formatLogCheck(honest).replace(/^/gm, "   "));

step(4, "the operator swaps in a rewritten log, with the same key and log id, and leaves out the 2500 refund");
const rewritten = await serveLog(fileResolver(join(dir, "rewritten.jsonl"), { logId: "example-log" }), localSigner(logKey), { port: 0 });
for (const leaf of ["refund 1200", "refund 900", "refund 300", "refund 100"]) await append(rewritten.url, leaf);
const caught = await checkLog({ ...opts, logUrl: rewritten.url });
console.log(formatLogCheck(caught).replace(/^/gm, "   "));

await log.close();
await rewritten.close();
checkpoints.close();
anchorHost.close();
const failed = caught.checks.find((c) => c.name === "head extends the anchored checkpoint");
if (!(run.tx.outcome === "anchored" && honest.ok && !caught.ok && failed && !failed.ok)) throw new Error("unexpected result");
console.log("\nOK");
