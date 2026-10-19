// Write-through to the retrieval stores teams already use. The ledger keeps provenance, time, and undo; the store
// keeps serving recall. A fact written through the memory server lands in every configured store, the store's id is
// recorded on the fact, and a retraction reaches the store. Clients are typed structurally, as the receipts adapters
// are, so this package has no runtime dependency on either vendor; the tests run against the real client packages.
import type { Fact } from "./ledger.ts";

/** One entry a store holds for a fact: the store's id for it, the fact's id, and the text the store indexed. */
export interface StoreEntry {
  externalId: string;
  factId: string;
  text: string;
  /** when the store received the entry, from its custody metadata; repair removes only entries older than its cutoff. Absent on entries that version 0.7.0 or earlier wrote. */
  storedAt?: string;
}

/**
 * The storedAt field of an entry: the first of the given times that parses, as an ISO string. The custody storedAt comes
 * first. The store's own creation time follows, for entries that version 0.7.0 or earlier wrote.
 */
const stored = (...times: unknown[]): { storedAt?: string } => {
  for (const t of times) {
    const d = typeof t === "string" || t instanceof Date ? new Date(t) : null;
    if (d && !Number.isNaN(d.getTime())) return { storedAt: d.toISOString() };
  }
  return {};
};

/**
 * The ids of a page that no earlier page of the same listing returned. A non-empty page with none of them means the
 * backend ignores the cursor, and the listing throws instead of looping forever.
 */
function freshIds(store: string, seen: Set<string>, ids: string[]): Set<string> {
  const fresh = new Set(ids.filter((i) => !seen.has(i)));
  if (ids.length > 0 && fresh.size === 0) throw new Error(`${store}: listing does not advance`);
  for (const i of fresh) seen.add(i);
  return fresh;
}

export interface Store {
  /** the key under which the store's id is recorded on the fact */
  readonly name: string;
  /** writes the fact and returns the store's own id for it */
  put(fact: Fact): Promise<string>;
  /**
   * removes the entry from the store; called on retraction, forget, and repair. Named delete, not remove, so that a
   * store written for the earlier remove(externalId, fact) is refused at startup instead of called with the wrong arguments.
   */
  delete(entry: StoreEntry): Promise<void>;
  /**
   * Checks the store's own search no longer surfaces the entry: a delete by id and a search index catching up are
   * different moments. Optional; a store without it is reported as unverified, never as verified.
   */
  verifyDeleted?(entry: StoreEntry): Promise<boolean>;
  /**
   * Every entry the store holds that carries custody metadata. The repair sweep compares them with the ledger.
   * Optional; the sweep reports a store without it as unlisted.
   */
  list?(): Promise<StoreEntry[]>;
}

/** The entry a fact has in a store, from the id the ledger recorded for it there. */
export function entryOf(fact: Fact, externalId: string): StoreEntry {
  return { externalId, factId: fact.factId, text: factText(fact) };
}

/** What the server reports per store after a removal. */
export type RemovalOutcome = "verified" | "stillIndexed" | "unverified" | "failed";

/** One line a retrieval store can index: what the fact says, in words. */
export function factText(f: Pick<Fact, "subject" | "predicate" | "value">): string {
  return `${f.subject} ${f.predicate}: ${typeof f.value === "string" ? f.value : JSON.stringify(f.value)}`;
}

/** Metadata every store receives alongside the text, so a memory can always be traced back to its custody. */
export function factMetadata(f: Fact): Record<string, unknown> {
  return { factId: f.factId, space: f.space, actor: f.actor, provenance: f.provenance, receiptId: f.source.receiptId, validFrom: f.validFrom, source: "agent-custody", storedAt: new Date().toISOString() /* the time of the store write, not of the fact; repair compares it with its cutoff */ };
}

// ---- Mem0 ----
/** The subset of mem0ai's MemoryClient this adapter uses. */
export interface Mem0Like {
  add(messages: { role: "user" | "assistant"; content: string }[], options?: Record<string, unknown>): Promise<{ id?: string }[]>;
  delete(memoryId: string): Promise<unknown>;
  search?(query: string, options?: Record<string, unknown>): Promise<{ results: { id?: string; memory?: string }[] }>;
  /** pages are numbered from 1; `next` is null on the last page */
  getAll?(options?: { filters?: Record<string, unknown>; page?: number; pageSize?: number }): Promise<{ next?: string | null; results: { id?: string; memory?: string; metadata?: unknown; createdAt?: string | Date }[] }>;
}

export interface Mem0Options {
  userId: string;
  /** Mem0 extracts memories with an LLM when infer is true. Off by default, so the memory is the fact, verbatim. */
  infer?: boolean;
}

export function mem0Store(client: Mem0Like, opts: Mem0Options): Store {
  return {
    name: "mem0",
    async put(fact) {
      const results = await client.add([{ role: "user", content: factText(fact) }], { user_id: opts.userId, infer: opts.infer ?? false, metadata: factMetadata(fact) });
      const id = results.find((r) => typeof r.id === "string")?.id;
      if (!id) throw new Error("mem0 returned no memory id");
      return id;
    },
    async delete({ externalId }) {
      await client.delete(externalId);
    },
    ...(client.search
      ? {
          async verifyDeleted({ externalId, text }) {
            // Mem0's search scopes by filters, not by top-level entity parameters; the real client refuses the latter.
            const { results } = await client.search!(text, { filters: { user_id: opts.userId } });
            return !results.some((r) => r.id === externalId || r.memory === text);
          },
        }
      : {}),
    ...(client.getAll
      ? {
          async list() {
            const out: StoreEntry[] = [];
            const seen = new Set<string>();
            // The API is paginated by `next`, and it answers a page past the end with 404: never ask for that page.
            for (let page = 1; ; page++) {
              const { results, next } = await client.getAll!({ filters: { user_id: opts.userId }, page, pageSize: 100 });
              const fresh = freshIds("mem0", seen, results.flatMap((r) => (r.id ? [r.id] : [])));
              for (const r of results) {
                const m = (r.metadata ?? {}) as { source?: unknown; factId?: unknown; storedAt?: unknown };
                if (r.id && fresh.has(r.id) && m.source === "agent-custody" && typeof m.factId === "string") out.push({ externalId: r.id, factId: m.factId, text: r.memory ?? "", ...stored(m.storedAt, r.createdAt) });
              }
              if (!next || results.length === 0) return out;
            }
          },
        }
      : {}),
  };
}

// ---- Zep ----
/** The subset of @getzep/zep-cloud's ZepClient this adapter uses. */
export interface ZepLike {
  graph: {
    add(request: { userId?: string; graphId?: string; type: "json" | "text"; data: string; sourceDescription?: string; metadata?: Record<string, unknown> }): Promise<{ uuid: string }>;
    episode: {
      delete(uuid: string): Promise<unknown>;
      /** one page of at most 50 episodes; the next cursor is the Zep-Next-Cursor response header, absent on the last page */
      listByUserId?(userId: string, request: { cursor?: string; limit?: number }): { withRawResponse(): Promise<{ data: { uuid: string; content: string; createdAt?: string }[]; rawResponse: { headers: { get(name: string): string | null } } }> };
      listByGraphId?(graphId: string, request: { cursor?: string; limit?: number }): { withRawResponse(): Promise<{ data: { uuid: string; content: string; createdAt?: string }[]; rawResponse: { headers: { get(name: string): string | null } } }> };
    };
    search?(request: { userId?: string; graphId?: string; query: string; limit?: number }): Promise<{ edges?: { uuid: string; fact: string; episodes?: string[] }[]; episodes?: { uuid: string; content: string }[] }>;
  };
}

export type ZepOptions = { userId: string; graphId?: undefined } | { graphId: string; userId?: undefined };

export function zepStore(client: ZepLike, opts: ZepOptions): Store {
  return {
    name: "zep",
    async put(fact) {
      const target = opts.graphId ? { graphId: opts.graphId } : { userId: opts.userId! };
      const meta = factMetadata(fact);
      const episode = await client.graph.add({ ...target, type: "json", data: JSON.stringify({ subject: fact.subject, predicate: fact.predicate, value: fact.value, ...meta }), sourceDescription: "agent-custody", metadata: meta });
      if (!episode?.uuid) throw new Error("zep returned no episode uuid");
      return episode.uuid;
    },
    async delete({ externalId }) {
      await client.graph.episode.delete(externalId);
    },
    ...(client.graph.search
      ? {
          async verifyDeleted({ externalId, text }) {
            const target = opts.graphId ? { graphId: opts.graphId } : { userId: opts.userId! };
            const r = await client.graph.search!({ ...target, query: text, limit: 20 });
            const episodeHit = (r.episodes ?? []).some((e) => e.uuid === externalId);
            const edgeHit = (r.edges ?? []).some((e) => (e.episodes ?? []).includes(externalId));
            return !episodeHit && !edgeHit;
          },
        }
      : {}),
    ...((opts.graphId ? client.graph.episode.listByGraphId : client.graph.episode.listByUserId)
      ? {
          async list() {
            const out: StoreEntry[] = [];
            const seen = new Set<string>();
            const cursors = new Set<string>();
            let cursor: string | undefined;
            do {
              const request = { limit: 50, ...(cursor ? { cursor } : {}) };
              const { data, rawResponse } = await (opts.graphId ? client.graph.episode.listByGraphId!(opts.graphId, request) : client.graph.episode.listByUserId!(opts.userId!, request)).withRawResponse();
              const fresh = freshIds("zep", seen, data.map((e) => e.uuid));
              for (const e of data) {
                if (!fresh.has(e.uuid)) continue;
                // The episode content is the JSON that put wrote. Text is rebuilt from it, the way search indexes it.
                let d: { subject?: unknown; predicate?: unknown; value?: unknown; factId?: unknown; source?: unknown; storedAt?: unknown };
                try { d = JSON.parse(e.content); } catch { continue; }
                if (d && d.source === "agent-custody" && typeof d.factId === "string") out.push({ externalId: e.uuid, factId: d.factId, text: factText({ subject: String(d.subject), predicate: String(d.predicate), value: d.value }), ...stored(d.storedAt, e.createdAt) });
              }
              cursor = rawResponse.headers.get("Zep-Next-Cursor") || undefined;
              if (cursor && cursors.has(cursor)) throw new Error("zep: listing does not advance");
              if (cursor) cursors.add(cursor);
            } while (cursor);
            return out;
          },
        }
      : {}),
  };
}

// ---- pgvector ----
/** What the pgvector adapter needs from a client: the query method of a pg Pool or of PGlite. */
export interface PgLike {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

export interface PgvectorOptions {
  /** turns the fact's text into the vector the table indexes; the same function the retrieval side uses */
  embed: (text: string) => Promise<number[]>;
  /** the vector's length, fixed per table */
  dimensions: number;
  /** table name, optionally schema-qualified; default "agent_memories"; created if missing */
  table?: string;
  /** how many nearest rows verifyDeleted inspects for the removed id; default 10 */
  topK?: number;
}

/**
 * Write-through to a pgvector table: the fact's text, its embedding, and its custody metadata as one row, keyed by
 * the fact id, in the Postgres a team already runs. Removal deletes the row, and verification embeds the text again
 * and checks the removed id is not among the nearest rows, which is what a retrieval query would return.
 */
export function pgvectorStore(client: PgLike, opts: PgvectorOptions): Store {
  const table = opts.table ?? "agent_memories";
  if (!/^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$/.test(table)) throw new Error(`pgvector: table must be a plain identifier, optionally schema-qualified; got "${table}"`);
  if (!(Number.isInteger(opts.dimensions) && opts.dimensions > 0)) throw new Error("pgvector: dimensions must be a positive integer");
  let ready: Promise<void> | null = null;
  const init = () =>
    (ready ??= (async () => {
      await client.query("CREATE EXTENSION IF NOT EXISTS vector");
      await client.query(`CREATE TABLE IF NOT EXISTS ${table} (id TEXT PRIMARY KEY, text TEXT NOT NULL, embedding vector(${opts.dimensions}) NOT NULL, metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    })());
  const literal = (v: number[]) => {
    if (v.length !== opts.dimensions) throw new Error(`pgvector: embedding has ${v.length} dimensions, the table has ${opts.dimensions}`);
    return `[${v.join(",")}]`;
  };
  return {
    name: "pgvector",
    async put(fact) {
      await init();
      const text = factText(fact);
      await client.query(`INSERT INTO ${table} (id, text, embedding, metadata) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET text = EXCLUDED.text, embedding = EXCLUDED.embedding, metadata = EXCLUDED.metadata`, [fact.factId, text, literal(await opts.embed(text)), JSON.stringify(factMetadata(fact))]);
      return fact.factId;
    },
    async delete({ externalId }) {
      await init();
      await client.query(`DELETE FROM ${table} WHERE id = $1`, [externalId]);
    },
    async verifyDeleted({ externalId, text }) {
      await init();
      const rows = (await client.query(`SELECT id FROM ${table} ORDER BY embedding <=> $1 LIMIT $2`, [literal(await opts.embed(text)), opts.topK ?? 10])).rows as { id: string }[];
      return !rows.some((r) => r.id === externalId);
    },
    async list() {
      await init();
      const rows = (await client.query(`SELECT id, text, metadata->>'factId' AS fact_id, COALESCE(metadata->>'storedAt', to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) AS stored_at FROM ${table} WHERE metadata->>'source' = 'agent-custody'`)).rows as { id: string; text: string; fact_id: string | null; stored_at: string }[];
      return rows.filter((r) => r.fact_id).map((r) => ({ externalId: r.id, factId: r.fact_id!, text: r.text, storedAt: r.stored_at }));
    },
  };
}


// ---- Letta ----
/** The subset of @letta-ai/letta-client's Letta this adapter uses: an agent's archival memory. */
export interface LettaLike {
  agents: {
    passages: {
      create(agentId: string, body: { text: string; tags?: string[] | null }): Promise<{ id?: string | undefined }[]>;
      delete(memoryId: string, params: { agent_id: string }): Promise<unknown>;
      search?(agentId: string, query: { query: string; tags?: string[] | null; tag_match_mode?: "any" | "all" }): Promise<{ results: { id: string; content: string }[] }>;
      /** cursor pages: `after` is the id of the last passage of the previous page; oldest first by default */
      list?(agentId: string, query?: { after?: string | null; limit?: number | null }): Promise<{ id?: string; text: string; tags?: string[] | null; created_at?: string | null }[]>;
    };
  };
}

export interface LettaOptions {
  /** the agent whose archival memory receives the fact */
  agentId: string;
  /** tags attached to every passage, beside the custody tags; list() returns only passages whose tags, beside the custody tags, are exactly this set; default none */
  tags?: string[];
}

/**
 * Letta keeps archival memory as passages with text and tags, no free metadata. Custody travels as tags
 * (`agent-custody`, `fact:<id>`, `space:<name>`, `receipt:<id>`) so a passage always leads back to its fact.
 */
export function lettaStore(client: LettaLike, opts: LettaOptions): Store {
  const tagsFor = (f: Fact) => ["agent-custody", `fact:${f.factId}`, `space:${f.space}`, `stored:${new Date().toISOString()}`, ...(f.source.receiptId ? [`receipt:${f.source.receiptId}`] : []), ...(opts.tags ?? [])];
  return {
    name: "letta",
    async put(fact) {
      const passages = await client.agents.passages.create(opts.agentId, { text: factText(fact), tags: tagsFor(fact) });
      const id = passages.find((p) => typeof p.id === "string")?.id;
      if (!id) throw new Error("letta returned no passage id");
      return id;
    },
    async delete({ externalId }) {
      await client.agents.passages.delete(externalId, { agent_id: opts.agentId });
    },
    ...(client.agents.passages.search
      ? {
          async verifyDeleted({ externalId, factId, text }) {
            const { results } = await client.agents.passages.search!(opts.agentId, { query: text, tags: [`fact:${factId}`], tag_match_mode: "any" });
            return !results.some((r) => r.id === externalId || r.content === text);
          },
        }
      : {}),
    ...(client.agents.passages.list
      ? {
          async list() {
            const out: StoreEntry[] = [];
            const limit = 100;
            const seen = new Set<string>();
            const own = new Set(opts.tags ?? []);
            for (let after: string | undefined; ; ) {
              const page = await client.agents.passages.list!(opts.agentId, { limit, ...(after ? { after } : {}) });
              const fresh = freshIds("letta", seen, page.flatMap((p) => (p.id ? [p.id] : [])));
              for (const p of page) {
                if (!p.id || !fresh.has(p.id)) continue;
                const factTag = p.tags?.find((t) => t.startsWith("fact:"));
                const rest = new Set((p.tags ?? []).filter((t) => t !== "agent-custody" && !/^(fact|space|stored|receipt):/.test(t)));
                if (p.id && factTag && p.tags!.includes("agent-custody") && rest.size === own.size && [...own].every((t) => rest.has(t))) out.push({ externalId: p.id, factId: factTag.slice("fact:".length), text: p.text, ...stored(p.tags!.find((t) => t.startsWith("stored:"))?.slice("stored:".length), p.created_at) });
              }
              const last = page.at(-1)?.id;
              if (page.length < limit || !last) return out;
              if (last === after) throw new Error("letta: listing does not advance");
              after = last;
            }
          },
        }
      : {}),
  };
}

// ---- LangGraph store (LangMem) ----
/**
 * The subset of LangGraph's BaseStore this adapter uses. LangMem's memories live in this store, so custody over a
 * LangMem deployment is custody over its store: one item per fact, keyed by the fact id, in the namespace given.
 */
export interface LangGraphStoreLike {
  put(namespace: string[], key: string, value: Record<string, unknown>): Promise<void>;
  get(namespace: string[], key: string): Promise<{ key: string; value: Record<string, unknown> } | null>;
  delete(namespace: string[], key: string): Promise<void>;
  search?(namespacePrefix: string[], options?: { filter?: Record<string, unknown>; limit?: number; offset?: number; query?: string }): Promise<{ key: string; namespace: string[]; value: Record<string, unknown>; createdAt?: Date | string }[]>;
}

export interface LangGraphStoreOptions {
  /** the namespace the memories live under, e.g. ["memories", userId] */
  namespace: string[];
}

export function langgraphStore(store: LangGraphStoreLike, opts: LangGraphStoreOptions): Store {
  const sameNamespace = (ns: string[]) => ns.length === opts.namespace.length && ns.every((part, i) => part === opts.namespace[i]);
  return {
    name: "langgraph",
    async put(fact) {
      await store.put(opts.namespace, fact.factId, { content: factText(fact), subject: fact.subject, predicate: fact.predicate, value: fact.value, ...factMetadata(fact) });
      return fact.factId;
    },
    async delete({ externalId }) {
      await store.delete(opts.namespace, externalId);
    },
    async verifyDeleted({ externalId, factId }) {
      if ((await store.get(opts.namespace, externalId)) !== null) return false;
      if (!store.search) return true;
      const hits = await store.search(opts.namespace, { filter: { factId }, limit: 10 });
      return !hits.some((h) => h.key === externalId);
    },
    ...(store.search
      ? {
          async list() {
            const out: StoreEntry[] = [];
            const seen = new Set<string>();
            for (let offset = 0, page = 100; ; offset += page) {
              const hits = await store.search!(opts.namespace, { filter: { source: "agent-custody" }, limit: page, offset });
              const idOf = (h: { namespace: string[]; key: string }) => [...h.namespace, h.key].join("\u0000");
              const fresh = freshIds("langgraph", seen, hits.map(idOf));
              // search matches by prefix; an item in a child namespace is not this store's to remove.
              for (const h of hits) if (sameNamespace(h.namespace) && fresh.has(idOf(h)) && typeof h.value.factId === "string") out.push({ externalId: h.key, factId: h.value.factId, text: String(h.value.content ?? ""), ...stored(h.value.storedAt, h.createdAt) });
              if (hits.length < page) return out;
            }
          },
        }
      : {}),
  };
}

// ---- Cognee ----
export interface CogneeOptions {
  /** the Cognee server, e.g. http://localhost:8000 */
  url: string;
  /** the dataset the facts go into, by id */
  datasetId: string;
  /** environment variable holding an API key (sent as X-Api-Key) */
  apiKeyEnv?: string;
  /** environment variable holding a bearer token (sent as Authorization: Bearer) */
  tokenEnv?: string;
  fetch?: typeof fetch;
  env?: Record<string, string | undefined>;
}

/**
 * Cognee has no JavaScript client; this adapter speaks its REST API directly, built against the add and datasets
 * routers of cognee 0.3: `POST /api/v1/add` (multipart, `raw_data` and `external_metadata`), `GET
 * /api/v1/datasets/{id}/data`, `DELETE /api/v1/datasets/{id}/data/{dataId}`. The add call returns a pipeline run,
 * not the data id, so the id is found by listing the dataset and matching the fact id written into the item's
 * external metadata. Tested against a stand-in of those three routes, not against a running Cognee.
 */
export function cogneeStore(opts: CogneeOptions): Store {
  const f = opts.fetch ?? fetch;
  const env = opts.env ?? process.env;
  const headers: Record<string, string> = {};
  if (opts.apiKeyEnv) {
    const v = env[opts.apiKeyEnv];
    if (!v) throw new Error(`cognee: environment variable ${opts.apiKeyEnv} is not set`);
    headers["x-api-key"] = v;
  }
  if (opts.tokenEnv) {
    const v = env[opts.tokenEnv];
    if (!v) throw new Error(`cognee: environment variable ${opts.tokenEnv} is not set`);
    headers.authorization = `Bearer ${v}`;
  }
  const base = opts.url.endsWith("/") ? opts.url : `${opts.url}/`;
  const call = async (method: string, path: string, body?: BodyInit): Promise<unknown> => {
    const res = await f(new URL(path, base), { method, headers, ...(body ? { body } : {}), signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`cognee ${method} ${path}: ${res.status} ${(await res.text()).slice(0, 200)}`);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  };
  interface Item { id: string; external_metadata?: unknown; name?: string; created_at?: unknown; createdAt?: unknown }
  const list = async (): Promise<Item[]> => (await call("GET", `api/v1/datasets/${opts.datasetId}/data`)) as Item[];
  const metadataOf = (item: Item): Record<string, unknown> => {
    const m = item.external_metadata;
    if (typeof m === "string") {
      try {
        return JSON.parse(m) as Record<string, unknown>;
      } catch {
        return {};
      }
    }
    return (m ?? {}) as Record<string, unknown>;
  };
  return {
    name: "cognee",
    async put(fact) {
      const form = new FormData();
      form.append("raw_data", factText(fact));
      form.append("datasetId", opts.datasetId);
      form.append("external_metadata", JSON.stringify([factMetadata(fact)]));
      form.append("labels", JSON.stringify(["agent-custody", `fact:${fact.factId}`]));
      await call("POST", "api/v1/add", form);
      const item = (await list()).reverse().find((i) => metadataOf(i).factId === fact.factId);
      if (!item) throw new Error(`cognee accepted the add but the dataset lists no item carrying fact ${fact.factId}`);
      return item.id;
    },
    async delete({ externalId }) {
      await call("DELETE", `api/v1/datasets/${opts.datasetId}/data/${externalId}`);
    },
    async verifyDeleted({ externalId, factId }) {
      return !(await list()).some((i) => i.id === externalId || metadataOf(i).factId === factId);
    },
    async list() {
      // The data listing carries no text; the repair sweep needs the id and the fact id only, and this store verifies by them.
      return (await list()).flatMap((i) => {
        const m = metadataOf(i);
        return m.source === "agent-custody" && typeof m.factId === "string" ? [{ externalId: i.id, factId: m.factId, text: "", ...stored(m.storedAt, i.created_at, i.createdAt) }] : [];
      });
    },
  };
}
