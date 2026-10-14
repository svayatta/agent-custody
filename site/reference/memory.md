# Memory: the ledger and the memory server

`@agent-custody/state` is a bitemporal fact ledger and an MCP server over it. Behind the gateway, every write to memory is a receipted tool call with an attested actor; a fact carries its provenance, its validity, the receipt that wrote it, and every store it was written through to. Retraction, erasure with a certificate, legal holds, and retention are events on the same history.

## Running the server

```bash
agent-custody-memory serve --ledger ledger.sqlite [--key memory.key] [--forget-key-env FORGET_KEY] [--retention 'org=P365D,team:*=P90D'] [--allow-direct]
agent-custody-memory serve --ledger postgres://… --http --port 8790 --host 127.0.0.1 --token-env MEMORY_TOKEN [--direct-token-env MEMORY_DIRECT_TOKEN]
```

Over stdio it is the gateway's upstream (`"upstream": { "command": "agent-custody-memory", "args": ["serve", "--ledger", "ledger.sqlite"] }`); over HTTP several gateways share one ledger (`"upstream": { "url": "http://memory:8790/mcp", "tokenEnv": "MEMORY_TOKEN" }`). The ledger is a JSONL file, SQLite when the path ends in `.sqlite` or `.db`, or a `postgres://` URL (needs the `pg` package; `?table=` names the table). By default the server refuses calls that did not come through the gateway; `--allow-direct` accepts them as `claimed` and quarantines what they write. `--key` signs every result for its receipt, so memory executions verify as attested. `--forget-key-env` keys forgotten values' digests with a secret held outside the ledger. Over HTTP, `--token-env` is the gateways' token and `--direct-token-env` the direct writers' token; the two must differ. The server reads the receipt, agent, and observed keys from `_meta` only for a caller with the gateway token, and drops them for every other caller. With no token, no caller is a gateway.

In code: `createMemoryServer(ledger, { requireGateway?, trustMeta? = true, stores?, identity?, retention?, verify?: { attempts?, delayMs? } }): Server` (an MCP `Server` to connect to any transport; `trustMeta: false` drops the privileged `_meta` keys) and `serveMemoryHttp(ledger, { port, host?, tokens?, directTokens?, ...same })`, where `tokens` are gateway tokens and `directTokens` are direct-writer tokens.

## The tools

Every tool returns its JSON as one text content item; a refusal is `isError: true` with the reason as text. The gateway sets `_meta["agent-custody/receipt"]`, `agent-custody/agent`, and `agent-custody/observed` on each call; the agent cannot. A fact:

```json
{ "factId": "70cea8ca-…", "subject": "acct:42", "predicate": "plan", "value": "enterprise", "space": "org", "actor": "support-agent", "source": { "receiptId": "2814…" }, "provenance": "attested", "validFrom": "2026-09-08T18:26:04.449Z", "validTo": null, "confidence": null, "external": { "mem0": "mem_7" } }
```

`provenance` is `claimed` (a direct writer said so; quarantined), `attested` (written through the gateway under a signed grant), or `verified` (attested, and the value equals what the gateway itself fetched). A forgotten fact has `value: null` and `forgotten: { valueDigest, digestKind, at }`.

### `memory.write`

**Request** `{ "subject", "predicate", "value", "space", "actor"?, "validFrom"?, "confidence"?, "supersedes"?, "evidence"?: { "fact", "path"? } }`

`supersedes` names the fact this one replaces, which stops being believed. `evidence` names a fact the gateway fetched for this call (a configured lookup); the value must equal it, or the field at `path`, and the write is then `verified`; otherwise it is refused. Through the gateway the actor is the grant's agent regardless of `actor`.

**Response** `{ "fact": {…}, "eventId": "…", "txTime": "…", "supersedes": "<factId>" | null }`

### `memory.read`

**Request** `{ "subject"?, "predicate"?, "space"?, "validAt"?, "txAt"?, "includeClaimed"?, "requireVerified"? }`

`validAt` asks what was true then; `txAt` asks what the ledger knew then; both default to now. Quarantined facts are left out unless `includeClaimed`; `requireVerified` returns only verified ones.

**Response** `{ "facts": [ {…}, … ] }`, and `_meta["agent-custody/facts"]` listing the ids served, which the gateway records as `consumed` on every later receipt of the session.

### `memory.confirm`

Lifts a quarantined fact to `attested`. Gateway only. **Request** `{ "factId" }` → **Response** `{ "eventId", "factId", "txTime", "actor", "source" }`.

### `memory.retract`

The fact leaves the present, stays visible to questions about the past, and whatever it superseded is believed again. The ledger is retracted first, then every store. **Request** `{ "factId", "reason", "actor"? }` → **Response** `{ "eventId", "factId", "txTime", "actor", "reason", "source", "removedFrom": ["mem0"], "verification": { "mem0": "verified" } }`. A store that still holds the value makes the result `isError` with the reason and the same JSON second.

### `memory.forget`

Erases the value from the ledger, keeping its digest (keyed when the server has a forget key; none when `keepDigest` is false), and from every store; the fact stops being believed. The receipt of this call is the certificate. **Request** `{ "factId", "reason", "keepDigest"? }` → **Response** `{ "factId", "valueDigest", "digestKind": "sha256" | "hmac-sha256" | "none", "txTime", "actor", "reason", "source", "erasedFromLedger": true, "removedFrom": [...], "verification": { "<store>": "verified" | "stillIndexed" | "unverified" | "failed" } }`. Refused while a hold stands.

### `memory.hold`, `memory.release`

A legal hold refuses forget and sweep until released. **Request** `{ "factId", "reason" }` → **Response** the hold or release event `{ "eventId", "kind": "hold" | "release", "txTime", "factId", "actor", "reason", "source" }`.

### `memory.sweep`

Retention: forgets every fact the ledger learned of before an instant, in one space or all, skipping held facts. **Request** `{ "reason", "before"?, "space"?, "keepDigest"? }`; without `before`, the server's `--retention` windows decide per space. **Response** `{ "before", "retention", "space", "forgotten": [{ "factId", "valueDigest", "digestKind", "removedFrom", "verification" }], "held": ["<factId>", …] }`.

### `memory.get`, `memory.history`

`memory.get { "factId" }` → the fact with `retracted: boolean`, null fields omitted, for the gateway's own fact lookups so policy can decide on the fact a write supersedes. `memory.history { "factId" }` → `{ "events": [ …oldest first ] }`, each an `assert`, `confirm`, `retract`, `forget`, `hold`, or `release` event as above.

## The `Ledger` in code

```ts
import { Ledger } from "@agent-custody/state";
const ledger = new Ledger("ledger.sqlite", { forgetKey?: process.env.FORGET_KEY });
```

| method | request | response |
| --- | --- | --- |
| `assert({ subject, predicate, value, space, actor, source?, provenance?, external?, validFrom?, confidence?, supersedes?, factId? })` | | `AssertEvent { eventId, kind: "assert", txTime, fact, supersedes }` |
| `asOf({ validAt?, txAt?, space?, subject?, predicate?, include?: "attested" \| "verified" \| "all" })` | | `Fact[]` believed at that moment |
| `retract({ factId, actor, reason, source? })` | | `RetractEvent` |
| `confirm({ factId, actor, source? })` | | `ConfirmEvent` |
| `forget({ factId, actor, reason, source?, keepDigest? })` | | `ForgetEvent { …, valueDigest, digestKind }` |
| `hold(input)`, `release(input)`, `held(factId)` | `{ factId, actor, reason, source? }` | `HoldEvent`, `boolean` |
| `sweep({ before, space?, actor, reason, source?, keepDigest? })` | | `{ forgotten: ForgetEvent[], held: string[] }` |
| `get(factId)`, `history(factId)`, `facts()`, `spaces()`, `count()`, `learnedBefore(before, space?)` | | a fact, its events, every fact, the space names, the event count, the facts learned before an instant |
| `compact()`, `close()` | | SQLite checkpoints the WAL, Postgres runs `VACUUM FULL`; releases the store |

The event stores behind it, `JsonlStore`, `SqliteStore`, and `PostgresStore`, implement one `EventStore` interface; `openStore(location)` picks by path.

## Write-through stores

Every write lands in each configured store with custody metadata (`factId`, `space`, `actor`, `provenance`, `receiptId`, `validFrom`, `source: "agent-custody"`), the store's own id is recorded on the fact under `external`, and a retraction or forget reaches the store by that id; then the store's own search is asked whether the value is gone.

```ts
interface Store { name: string; put(fact): Promise<string>; remove(externalId, fact): Promise<void>; verifyRemoved?(externalId, fact): Promise<boolean> }
```

| adapter | constructor | notes |
| --- | --- | --- |
| `mem0Store(client, { userId, infer? })` | a `mem0ai` `MemoryClient` | `infer` off by default, so the memory is the fact verbatim |
| `zepStore(client, { userId } \| { graphId })` | a `@getzep/zep-cloud` client | one episode per fact |
| `pgvectorStore(client, { embed, dimensions, table, topK? })` | a `pg` pool | one row per fact keyed by the fact id; removal verified by nearest-neighbour search |
| `lettaStore(client, { agentId, tags? })` | a `@letta-ai/letta-client` `Letta` | archival passages, custody as tags |
| `langgraphStore(store, { namespace })` | any LangGraph `BaseStore` | one item per fact keyed by the fact id; where LangMem keeps its memories |
| `cogneeStore({ url, datasetId, apiKeyEnv? \| tokenEnv? })` | Cognee's REST API | no client package exists; the id is found by listing the dataset |
