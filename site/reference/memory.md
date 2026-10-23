# Memory: the ledger and the memory server

`@agent-custody/state` is a bitemporal fact ledger and an MCP server over it. Behind the gateway, every write to memory is a receipted tool call with an attested actor; a fact carries its provenance, its validity, the receipt that wrote it, and every store it was written through to. Retraction, erasure with a certificate, legal holds, retention, and the repair of orphan store entries are events on the same history.

## Running the server

```bash
agent-custody-memory serve --ledger ledger.sqlite [--key memory.key] [--forget-key-env FORGET_KEY] [--retention 'org=P365D,team:*=P90D'] [--allow-direct]
agent-custody-memory serve --ledger postgres://… --http --port 8790 --host 127.0.0.1 --token-env MEMORY_TOKEN [--allow-direct --direct-token-env MEMORY_DIRECT_TOKEN]
```

Over stdio it is the gateway's upstream (`"upstream": { "command": "agent-custody-memory", "args": ["serve", "--ledger", "ledger.sqlite"] }`); over HTTP several gateways share one ledger (`"upstream": { "url": "http://memory:8790/mcp", "tokenEnv": "MEMORY_TOKEN" }`). The ledger is a JSONL file, SQLite when the path ends in `.sqlite` or `.db`, or a `postgres://` URL (needs the `pg` package; `?table=` names the table). By default the server refuses calls that did not come through the gateway; `--allow-direct` accepts them as `claimed` and quarantines what they write. Over HTTP a direct writer presents the token under `--direct-token-env`, never the gateways' token under `--token-env`: the token decides whether the call's `_meta` (receipt id, agent, observed facts) is believed, and a direct writer's is dropped, so it cannot attest or verify its own write. Over HTTP `--token-env` is required: a server without a gateway token would take any caller for a gateway. Over stdio the one client is a gateway unless `--allow-direct` is given, in which case its `_meta` is dropped the same way, so a gateway must never spawn the server with `--allow-direct`: its writes would be `claimed` and its confirmations refused. `--key` signs every result for its receipt, so memory executions verify as attested. `--forget-key-env` keys forgotten values' digests with a secret held outside the ledger. Over HTTP, SIGINT or SIGTERM closes the server and then the ledger, so a container runtime or systemd stops it cleanly. The server stops listening, closes idle connections at once, and lets a request in flight finish. After 3 seconds it cuts the connections that remain, for example a request whose body never arrives. It answers any method but POST with 405 and opens no GET stream, so a connected gateway does not hold the stop; the gateway's client accepts the 405. `RunningMemoryServer.close()` follows the same steps.

In code: `createMemoryServer(ledger, { requireGateway?, stores?, identity?, retention?, verify?: { attempts?, delayMs? } }): Server` (an MCP `Server` to connect to any transport) and `serveMemoryHttp(ledger, { port, host?, tokens, directTokens?, ...same })` (`tokens` are the gateways' tokens, at least one required, `directTokens` the direct writers', required when `requireGateway` is false; `createMemoryServer` also takes `trustMeta?`, default true exactly when `requireGateway` is not false).

## The tools

Every tool returns its JSON as one text content item; a refusal is `isError: true` with the reason as text. The gateway sets `_meta["agent-custody/receipt"]`, `agent-custody/agent`, and `agent-custody/observed` on each call; the agent cannot. A fact:

```json
{ "factId": "70cea8ca-…", "subject": "acct:42", "predicate": "plan", "value": "enterprise", "space": "org", "actor": "support-agent", "source": { "receiptId": "2814…" }, "provenance": "attested", "validFrom": "2026-09-08T18:26:04.449Z", "validTo": null, "confidence": null, "external": { "mem0": "mem_7" } }
```

`provenance` is `claimed` (a direct writer said so; quarantined), `attested` (written through the gateway under a signed grant), or `verified` (attested, and the value equals what the gateway itself fetched). A forgotten fact has `value: null` and `forgotten: { valueDigest, digestKind, at }`.

### `memory.write`

**Request** `{ "subject", "predicate", "value", "space", "actor"?, "validFrom"?, "confidence"?, "supersedes"?, "evidence"?: { "fact", "path"? } }`

`supersedes` names the fact this one replaces, which stops being believed. `evidence` names a fact the gateway fetched for this call (a configured lookup); the value must equal it, or the field at `path`, and the write is then `verified`; otherwise it is refused. Through the gateway the actor is the grant's agent regardless of `actor`. With stores configured, a write whose stores take more than five minutes is refused before its ledger append; [`memory.repair`](#memory-repair) removes what the stores took.

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

### `memory.repair`

Removes the store entries that the ledger has no fact for. A write reaches the stores before the ledger (validate, stores, ledger), so a failed ledger append leaves such an entry in a store. **Request** `{ "reason", "before"?: "<ISO instant>" }` → **Response** `{ "before": "<ISO instant>", "repaired": [{ "store", "externalId", "factId", "outcome", "eventId" }], "unlisted": ["<store name>", …], "stillHeld": ["<store>: <error>", …], "unrecorded": [{ "store", "externalId", "factId", "error" }] }`.

For each store that has `list`, the sweep reads every entry with custody metadata and removes an entry once if a listing holds it twice. It skips an entry whose fact id the ledger knows. It skips an entry that was not stored before the cutoff. The cutoff is the earlier of `before` and ten minutes ago (`REPAIR_MIN_AGE_MS`): `before` can move it earlier, never later. An entry whose `storedAt` is missing or does not parse counts as young and is never removed. The response `before` is the cutoff that the sweep used. For each other entry, the sweep first records a `repair` event under the fact id from the entry's metadata, as a retraction records its event first. Then it removes the entry and verifies the removal as a forget does. The first record of a fact id wins: `Ledger.assert` refuses a fact id that has a repair event, and `Ledger.repair` refuses one that has an assert. In one server process, a repair of an entry that has a repair event adds no second event, so a retry after a failed removal uses the first event. One sweep runs at a time in a server process. `outcome`, in the result and in the receipt, is `verified`, `stillIndexed`, `unverified`, or `failed`. `unlisted` names the stores that have no `list`. `stillHeld` holds the removals that failed and `<store>: cannot list: <error>` for a store whose listing failed; the sweep goes on with the other stores. `unrecorded` holds the entries that the sweep did not remove, because the ledger did not take the repair event; the next sweep tries them again. When `stillHeld` or `unrecorded` is not empty, the result is `isError` with the reason as text and the same JSON second.

A write in progress is safe, across server processes that share the stores, because `memory.write` refuses a write whose stores take more than five minutes (half of `REPAIR_MIN_AGE_MS`) before its ledger append. So the entries of a write in progress are never older than the cutoff. If a ledger append stalls for longer, the first record of the fact id wins and the other fails with an error. In one server process, the ledger makes the check and the append of the two records one step. For servers in different processes, the window is the time between the check and the commit of one append; to close it, the check and the append must be one transaction in the shared ledger store (for example with a per-fact-id advisory lock), which this version does not do. A unique constraint on `fact_id` does not work, because retract, confirm, hold, release, and forget events share the fact id, and an orphan in two stores has one repair event for each store. Two conditions apply. One store scope (a pgvector table, a Mem0 user, a Zep user or graph, a Letta agent with its exact tag set, a LangGraph namespace, a Cognee dataset) belongs to one ledger, because a repair on one ledger removes the entries of the other. And the clocks of the memory servers agree to within a few minutes, because `storedAt` comes from the clock of the writer and the cutoff from the clock of the repairer. From the command line: `agent-custody-memory repair --via gateway.json --reason "…" [--before <ISO instant>]`.

### `memory.get`, `memory.history`

`memory.get { "factId" }` → the fact with `retracted: boolean`, null fields omitted, for the gateway's own fact lookups so policy can decide on the fact a write supersedes. `memory.history { "factId" }` → `{ "events": [ …oldest first ] }`, each an `assert`, `confirm`, `retract`, `forget`, `hold`, `release`, or `repair` event as above. The history of an orphan fact id, one the ledger never recorded, is its `repair` event: `{ "eventId", "kind": "repair", "txTime", "factId", "actor", "reason", "source", "store", "externalId" }`.

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
| `repair({ factId, store, externalId, actor, reason, source? })` | | `RepairEvent`; throws when the ledger knows the fact id; returns the event that the entry already has |
| `get(factId)`, `history(factId)`, `facts()`, `spaces()`, `count()`, `learnedBefore(before, space?)` | | a fact, its events, every fact, the space names, the event count, the facts learned before an instant |
| `compact()`, `close()` | | SQLite checkpoints the WAL, Postgres runs `VACUUM FULL`; releases the store |

The event stores behind it, `JsonlStore`, `SqliteStore`, and `PostgresStore`, implement one `EventStore` interface; `openStore(location)` picks by path.

## Write-through stores

Every write lands in each configured store with custody metadata (`factId`, `space`, `actor`, `provenance`, `receiptId`, `validFrom`, `source: "agent-custody"`), the store's own id is recorded on the fact under `external`, and a retraction or forget reaches the store by that id; then the store's own search is asked whether the value is gone. The write order is validate, stores, ledger; a retraction goes ledger first, then stores. [`memory.repair`](#memory-repair) removes the entry that a failed ledger append leaves in a store.

```ts
interface StoreEntry { externalId: string; factId: string; text: string; storedAt?: string }
interface Store {
  name: string;
  put(fact): Promise<string>;
  delete(entry: StoreEntry): Promise<void>;
  verifyDeleted?(entry: StoreEntry): Promise<boolean>;
  list?(): Promise<StoreEntry[]>;
}
```

`list` returns every entry with custody metadata, for `memory.repair`. `storedAt` is the ISO time of the store write, which `factMetadata` records; Letta records it in the tag `stored:<iso>`. When the metadata has no `storedAt`, an adapter falls back to the store's own creation time (pgvector `created_at`; Mem0, Zep, Letta, and LangGraph the creation time their client reports; Cognee only if its listing has one). An entry without a parseable `storedAt` is never repaired. A store without `list` is reported as `unlisted`. `entryOf(fact, externalId)` builds an entry from a fact. **Breaking change for custom stores:** `remove(externalId, fact)` and `verifyRemoved(externalId, fact)` are now `delete(entry)` and `verifyDeleted(entry)`, with one `StoreEntry`. `createMemoryServer` refuses a store that has no `delete`, so a store written for the earlier interface fails at startup, not with wrong arguments at run time. Every adapter implements `list`: pgvector and Cognee always, LangGraph when the store has `search`, and Mem0, Zep, and Letta when their client has a method that lists entries.

| adapter | constructor | notes |
| --- | --- | --- |
| `mem0Store(client, { userId, infer? })` | a `mem0ai` `MemoryClient` | `infer` off by default, so the memory is the fact verbatim |
| `zepStore(client, { userId } \| { graphId })` | a `@getzep/zep-cloud` client | one episode per fact |
| `pgvectorStore(client, { embed, dimensions, table, topK? })` | a `pg` pool | one row per fact keyed by the fact id; removal verified by nearest-neighbour search |
| `lettaStore(client, { agentId, tags? })` | a `@letta-ai/letta-client` `Letta` | archival passages, custody as tags; `tags` must not be `agent-custody` or start with `fact:`, `space:`, `stored:`, or `receipt:`; a change to `tags` strands the passages written under the old tags, and `memory.repair` cannot remove the orphans among them |
| `langgraphStore(store, { namespace })` | any LangGraph `BaseStore` | one item per fact keyed by the fact id; where LangMem keeps its memories |
| `cogneeStore({ url, datasetId, apiKeyEnv? \| tokenEnv? })` | Cognee's REST API | no client package exists; the id is found by listing the dataset |
