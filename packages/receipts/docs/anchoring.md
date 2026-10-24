# Anchoring the log on Ethereum

The log's operator holds the key that signs the log's tree heads. A signed checkpoint therefore shows what the log said at one moment, but it cannot show that the operator never rewrote a tenant's tree later. Anyone who saved an earlier checkpoint can check that, and so can a witness on a machine the operator does not control. The anchor removes the need for either: it commits each new checkpoint to a public chain that nobody in the chain of custody controls. A monitor then checks the log against the chain alone.

## What it proves, and what it does not

| claim | who can check it | holds against |
| --- | --- | --- |
| this signed checkpoint existed no later than this block's time | anyone with a JSON-RPC endpoint and the pinned anchor address | the log's operator, the checkpoints host, the anchor's own host |
| the log today extends what was anchored, so nothing before it was removed or changed | the same, plus the log's consistency proof | the log's operator |
| the receipts under the checkpoint are true | nobody, from the chain | nothing: a chain commits to existence, not truth |

A rewritten tree is caught between anchors as well as at them: once a checkpoint is anchored, every later head must extend it. What the anchor does not catch is a rewrite inside the window before the first anchor that covers it. That window is at most the anchor's interval, six hours by default.

The anchor host is not trusted. A record it publishes is checked against the chain: the checkpoint must verify against the log's published keys, its leaf must be under the anchored Merkle root, and a successful transaction from the pinned address to itself must carry exactly that root. Pin the address from a source other than the anchor's host, such as the welcome sheet or the security page. The anchor's `/.well-known/agent-custody-anchor.json` is for discovery only.

JSON-RPC endpoints are trusted to report the chain. With several `--anchor-rpc-env` endpoints from different providers, each one must agree on the transaction and its block. A block counts as finalized only when every endpoint says so.

## How it works

Each run, for each watched log, the anchor:

1. fetches `latest.json` from the checkpoints host and verifies it against the log's published keys;
2. proves, with the log's `GET /consistency`, that it extends the last checkpoint this anchor committed;
3. refuses, and writes `<dir>/<tenant>/ALARM.json` and `ALARM-<time>.json`, when it does not, when a second root appears at the same size, or when an unpublished key signed it.

The checkpoints that moved become the leaves of one Merkle tree, each leaf the RFC 9162 leaf hash of the checkpoint's canonical envelope. The anchor sends one zero-value transaction from its address to itself, with calldata `0x` + hex(`agent-custody/anchor/1:`) + the 32-byte root. Once the transaction is in a block, each log gets `<dir>/<tenant>/<treeSize>.json` and `latest.json`: its own checkpoint, the transaction, the block, the root, and its inclusion proof. A log's record names no other log.

Nothing is sent when no checkpoint has moved, so an idle log costs nothing. A transaction in flight holds the address's nonce: no new one is sent until it lands. One that fails is reported, and the next run sends the same checkpoints again. Each run also writes `<dir>/<tenant>/checked.json` (`at`, `anchoredSize`, `behindSince`), so a monitor can tell a quiet log from a stopped or stuck anchor.

## Running it

```bash
export ANCHOR_RPC_URL=https://...        # a mainnet JSON-RPC endpoint; a provider URL often carries its key
export ANCHOR_KEY=0x...                  # the anchor's private key, for this purpose only
npm install viem                         # optional dependency, needed by the anchor only
agent-custody anchor --log-url https://log.example.com/ --checkpoints-url https://checkpoints.example.com/ \
  --out /srv/anchors --rpc-url-env ANCHOR_RPC_URL --key-env ANCHOR_KEY --tenant acme --tenant default
```

| flag | default | meaning |
| --- | --- | --- |
| `--rpc-url-env NAME` | | the environment variable holding the JSON-RPC URL |
| `--key-env NAME` | | the environment variable holding the private key, 0x-prefixed hex |
| `--chain-id` | `1` | the chain; the endpoint must report the same |
| `--max-fee-gwei` | `20` | a run whose fee per gas would exceed this is skipped, not sent |
| `--every` | `21600` | seconds between runs |
| `--once` | | one run; exit 1 when a log was refused |

Serve `<dir>` read-only from a host of its own, or under the checkpoints host.

**The key.** Generate it for this purpose and hold only what it needs to pay for anchors. Its address is the anchor's identity: publish it where tenants already read the log's key ids. A key that leaks lets someone else post transactions from that address. A transaction that carries a root nobody computed proves nothing, so the harm is spent funds, not a false anchor. To rotate, publish the new address beside the old one with its date and keep the old one listed, so earlier records still check.

**Cost.** One transaction uses about 23,200 gas: 21,000 for the transaction and the calldata floor of EIP-7623 for its 55 bytes. At 2 gwei per gas that is about 0.000046 ETH, and at the default cap of 20 gwei about 0.00046 ETH. The anchor sends at most one transaction per run and only when a log grew, so the default interval means at most four a day.

## Checking it

```bash
export ETH_RPC_A=https://...  ETH_RPC_B=https://...
agent-custody log-check --log-url https://log.example.com/ --tenant acme \
  --anchor-url https://anchors.example.com/ --anchor-address 0x... --anchor-rpc-env ETH_RPC_A --anchor-rpc-env ETH_RPC_B
```

Three checks are added per log:

- **`anchor is running and keeps up`**: the last run is no older than `--max-anchor-lag` (default 46800 s, thirteen hours), and the log has not stayed ahead of its last anchor for longer than that.
- **`anchor verifies on chain`**: the record checks out against the chain as described above. The detail says whether the block is finalized yet.
- **`head extends the anchored checkpoint`**: the log's head is at or beyond the anchored size, and the log's consistency proof shows that it extends the anchored root. A head below the anchored size is a rolled-back log. A head that does not extend the anchored root is a rewritten one.

An `--anchor-url` without `--anchor-address` and at least one `--anchor-rpc-env` is a failure, never a skipped check.

In code, `checkAnchorRecord(record, { rpcUrls, address, chainId, logKeys })` checks one record and needs no Ethereum library. `new Anchor({ logUrl, checkpointsUrl, tenants, chain, outDir })` runs the anchor with any `AnchorChain`, and `ethereumChain({ rpcUrl, privateKey, maxFeeGwei })` is the Ethereum one. Example 33 runs the whole loop against an in-memory chain; the tests drive real signed transactions.
