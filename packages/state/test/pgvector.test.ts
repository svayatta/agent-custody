// Write-through to pgvector, against a real Postgres with the extension: the pgvector/pgvector image in Docker on a
// free port. Without a Docker daemon the suite says so and skips, the way the language examples skip a missing
// toolchain; it never passes vacuously. The embedding is a deterministic stand-in, since what is under test is the
// row, its metadata, its removal, and that removal is verified by the same nearest-neighbour query recall would run.
import { execSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { Ledger } from "../src/ledger.ts";
import { createMemoryServer } from "../src/server.ts";
import { pgvectorStore, type PgLike } from "../src/stores.ts";

const DIMS = 8;
/** A fixed embedding: the text's hash spread over eight numbers. Close texts are not close, which is fine here. */
const embed = async (text: string): Promise<number[]> => {
  const h = createHash("sha256").update(text).digest();
  return Array.from({ length: DIMS }, (_, i) => h[i]! / 255);
};

const dockerUp = (() => {
  try {
    return spawnSync("docker", ["info"], { encoding: "utf8", timeout: 10_000 }).status === 0;
  } catch {
    return false;
  }
})();

const value = (r: CallToolResult) => JSON.parse((r.content[0] as { text: string }).text);

describe.skipIf(!dockerUp)("pgvector write-through, against Postgres with the extension in Docker", () => {
  let container = "";
  let pool: PgLike & { end(): Promise<void> };
  let client: Client;
  let ledgerFile: string;

  beforeAll(async () => {
    container = `agent-custody-pgvector-${process.pid}`;
    execSync(`docker run -d --rm --name ${container} -e POSTGRES_PASSWORD=pw -p 127.0.0.1:0:5432 pgvector/pgvector:pg16`, { stdio: "ignore", timeout: 120_000 });
    const port = execSync(`docker port ${container} 5432/tcp`, { encoding: "utf8" }).trim().split(":").pop();
    for (let i = 0; i < 60; i++) {
      if (spawnSync("docker", ["exec", container, "pg_isready", "-U", "postgres"], { encoding: "utf8" }).status === 0) break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    // pg is an optional peer with no bundled types; loaded the way the CLI loads it
    const { Pool } = createRequire(import.meta.url)("pg") as { Pool: new (o: { connectionString: string }) => PgLike & { end(): Promise<void> } };
    pool = new Pool({ connectionString: `postgres://postgres:pw@127.0.0.1:${port}/postgres` });
    for (let i = 0; i < 30; i++) {
      try {
        await pool.query("SELECT 1");
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    ledgerFile = join(mkdtempSync(join(tmpdir(), "pgvector-")), "ledger.jsonl");
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(new Ledger(ledgerFile), { stores: [pgvectorStore(pool, { embed, dimensions: DIMS, table: "custody_memories" })], verify: { attempts: 2, delayMs: 1 } }).connect(a);
    client = new Client({ name: "test", version: "0" });
    await client.connect(b);
  }, 180_000);

  afterAll(async () => {
    await client?.close();
    await pool?.end();
    if (container) spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
  });

  it("a write lands as a row with the embedding and custody metadata, keyed by the fact id, and the id is recorded on the fact", async () => {
    const w = value((await client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "enterprise", space: "org", actor: "agent" } })) as CallToolResult);
    expect(w.fact.external).toEqual({ pgvector: w.fact.factId });
    const rows = (await pool.query("SELECT id, text, metadata, vector_dims(embedding) AS dims FROM custody_memories")).rows as { id: string; text: string; metadata: Record<string, unknown>; dims: number }[];
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: w.fact.factId, text: "acct:42 plan: enterprise", dims: DIMS });
    expect(rows[0]!.metadata).toMatchObject({ factId: w.fact.factId, space: "org", actor: "agent", provenance: "claimed", source: "agent-custody" });
    // recall finds it by similarity, the way a retrieval layer would
    const near = (await pool.query("SELECT id FROM custody_memories ORDER BY embedding <=> $1 LIMIT 1", [`[${(await embed("acct:42 plan: enterprise")).join(",")}]`])).rows as { id: string }[];
    expect(near[0]?.id).toBe(w.fact.factId);
  });

  it("a retraction removes the row and the removal is verified by the nearest-neighbour query; a forget does the same and certifies it", async () => {
    const w = value((await client.callTool({ name: "memory.write", arguments: { subject: "person:1", predicate: "email", value: "dana@example.com", space: "org", actor: "agent" } })) as CallToolResult);
    const r = value((await client.callTool({ name: "memory.retract", arguments: { factId: w.fact.factId, reason: "wrong" } })) as CallToolResult);
    expect(r.removedFrom).toEqual(["pgvector"]);
    expect(r.verification).toEqual({ pgvector: "verified" });
    expect((await pool.query("SELECT COUNT(*) AS n FROM custody_memories WHERE id = $1", [w.fact.factId])).rows).toEqual([{ n: "0" }]);
    const w2 = value((await client.callTool({ name: "memory.write", arguments: { subject: "person:2", predicate: "ssn", value: "SSN-1", space: "org", actor: "agent" } })) as CallToolResult);
    const f = value((await client.callTool({ name: "memory.forget", arguments: { factId: w2.fact.factId, reason: "deletion request" } })) as CallToolResult);
    expect(f).toMatchObject({ erasedFromLedger: true, removedFrom: ["pgvector"], verification: { pgvector: "verified" } });
    const all = (await pool.query("SELECT text FROM custody_memories")).rows as { text: string }[];
    expect(all.map((x) => x.text)).toEqual(["acct:42 plan: enterprise"]);
  });

  it("lists the rows that carry custody metadata, with the time stored, and not the rows without it", async () => {
    const store = pgvectorStore(pool, { embed, dimensions: DIMS, table: "custody_memories" });
    const f = { factId: "list-1", subject: "acct:1", predicate: "plan", value: "pro", space: "org", actor: "a", source: { receiptId: null }, provenance: "claimed" as const, validFrom: "t", validTo: null, confidence: null };
    await store.put(f);
    // a row an older version wrote has no storedAt in its metadata: the created_at column answers; a foreign row has no custody
    const vec = `[${new Array(DIMS).fill(0.5).join(",")}]`;
    await pool.query("INSERT INTO custody_memories (id, text, embedding, metadata) VALUES ('old-1', 'old fact', $1, $2), ('foreign-1', 'note', $1, '{}')", [vec, JSON.stringify({ source: "agent-custody", factId: "old-fact" })]);
    try {
      const iso = expect.stringMatching(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
      const listed = (await store.list!()).filter((e) => ["list-1", "old-1", "foreign-1"].includes(e.externalId)).sort((x, y) => x.externalId.localeCompare(y.externalId));
      expect(listed).toEqual([{ externalId: "list-1", factId: "list-1", text: "acct:1 plan: pro", storedAt: iso }, { externalId: "old-1", factId: "old-fact", text: "old fact", storedAt: iso }]);
    } finally {
      await pool.query("DELETE FROM custody_memories WHERE id IN ('list-1', 'old-1', 'foreign-1')");
    }
  });

  it("refuses a table name that is not an identifier and an embedding of the wrong length", async () => {
    expect(() => pgvectorStore(pool, { embed, dimensions: DIMS, table: "x; drop table y" })).toThrow(/plain identifier/);
    const wrong = pgvectorStore(pool, { embed: async () => [1, 2], dimensions: DIMS, table: "custody_memories" });
    await expect(wrong.put({ factId: "f", subject: "s", predicate: "p", value: 1, space: "org", actor: "a", source: { receiptId: null }, provenance: "claimed", validFrom: "t", validTo: null, confidence: null })).rejects.toThrow(/2 dimensions/);
  });
});

describe.skipIf(dockerUp)("pgvector write-through", () => {
  it("is skipped here because no Docker daemon is available to run Postgres with the extension", () => {
    console.warn("pgvector tests skipped: no Docker daemon");
  });
});
