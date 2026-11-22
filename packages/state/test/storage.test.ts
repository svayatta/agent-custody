// The ledger must behave identically on JSONL, SQLite and Postgres. The whole ledger suite runs against all three;
// this file adds what differs: durability, in-place forget with no value left in the file, a second
// process seeing appends, and export back to the auditable JSONL.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Ledger } from "../src/ledger.ts";
import { PGlite } from "@electric-sql/pglite";
import { JsonlStore, PostgresStore, SqliteStore, openStore } from "../src/storage.ts";

const dir = () => mkdtempSync(join(tmpdir(), "storage-"));

describe("storage backends", () => {
  it("openStore picks SQLite by extension and JSONL otherwise", async () => {
    const d = dir();
    expect(openStore(join(d, "a.jsonl")).kind).toBe("jsonl");
    expect(openStore(join(d, "b.sqlite")).kind).toBe("sqlite");
    expect(openStore(join(d, "c.db")).kind).toBe("sqlite");
  });

  for (const [name, ext] of [["jsonl", "ledger.jsonl"], ["sqlite", "ledger.sqlite"]] as const) {
    describe(name, () => {
      it("survives reopening with the same beliefs and the same history", async () => {
        const f = join(dir(), ext);
        const l = new Ledger(f);
        const a = await l.assert({ subject: "s", predicate: "p", value: 1, space: "org", actor: "x" });
        await l.assert({ subject: "s", predicate: "p", value: 2, space: "org", actor: "y", supersedes: a.fact.factId });
        await l.hold({ factId: a.fact.factId, actor: "legal", reason: "r" });
        await l.close();
        const again = new Ledger(f);
        expect(await again.count()).toBe(3);
        expect((await again.asOf()).map((x) => x.value)).toEqual([2]);
        expect((await again.history(a.fact.factId)).map((e) => e.kind)).toEqual(["assert", "assert", "hold"]);
        expect(await again.held(a.fact.factId)).toBe(true);
        await again.close();
      });

      it("forget leaves no copy of the value in the file, and the export carries the tombstone", async () => {
        const f = join(dir(), ext);
        const l = new Ledger(f);
        const secret = await l.assert({ subject: "p:1", predicate: "ssn", value: "SSN-987-65-4321", space: "org", actor: "x" });
        await l.assert({ subject: "p:1", predicate: "plan", value: "pro", space: "org", actor: "x" });
        await l.forget({ factId: secret.fact.factId, actor: "dpo", reason: "request" });
        await l.close();
        const bytes = readFileSync(f, "latin1");
        expect(bytes).not.toContain("SSN-987-65-4321");
        expect(bytes).toContain("pro");
        const again = new Ledger(f);
        expect((await again.facts()).find((x) => x.factId === secret.fact.factId)?.forgotten?.digestKind).toBe("sha256");
        expect((await again.export()).map((e) => e.kind)).toEqual(["assert", "assert", "forget"]);
        await again.close();
      });
    });
  }

  it("sqlite: a second process appending is seen on reopen, and the write-ahead log holds no forgotten value", async () => {
    const f = join(dir(), "shared.sqlite");
    const l = new Ledger(f);
    const a = await l.assert({ subject: "s", predicate: "p", value: "visible", space: "org", actor: "x" });
    const other = spawnSync(process.execPath, ["-e", `
      import("${join(import.meta.dirname, "..", "src", "index.ts")}").then(async ({ Ledger }) => {
        const l = new Ledger(${JSON.stringify(f)});
        await l.assert({ subject: "t", predicate: "q", value: "from-another-process", space: "org", actor: "y" });
        await l.close();
      });`], { encoding: "utf8", timeout: 30_000 });
    expect(other.status, other.stderr).toBe(0);
    await l.close();
    const again = new Ledger(f);
    expect(await again.count()).toBe(2);
    await again.forget({ factId: a.fact.factId, actor: "dpo", reason: "r" });
    await again.close();
    for (const suffix of ["", "-wal"]) {
      try {
        expect(readFileSync(f + suffix, "latin1")).not.toContain("visible");
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      }
    }
  });

  it("export writes the auditable JSONL from a SQLite ledger, and a JSONL ledger reads it back identically", async () => {
    const d = dir();
    const l = new Ledger(join(d, "ledger.sqlite"));
    await l.assert({ subject: "s", predicate: "p", value: { nested: [1, 2] }, space: "org", actor: "x" });
    await l.close();
    const r = spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "export", "--ledger", join(d, "ledger.sqlite"), "--out", join(d, "out.jsonl")], { encoding: "utf8", timeout: 30_000 });
    expect(r.status, r.stderr).toBe(0);
    const back = new Ledger(join(d, "out.jsonl"));
    expect(await back.export()).toEqual(await new Ledger(join(d, "ledger.sqlite")).export());
  });

  it("the stores can be passed directly", async () => {
    const d = dir();
    expect(new Ledger(new JsonlStore(join(d, "x.log"))).location).toMatch(/x\.log$/);
    expect(new Ledger(new SqliteStore(join(d, "y.sqlite"))).location).toMatch(/y\.sqlite$/);
  });
});

describe("sqlite: a ledger written before the query columns existed", () => {
  it("gets the columns filled from its JSON on open, and answers the indexed queries", async () => {
    const f = join(dir(), "old.sqlite");
    const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as { DatabaseSync: new (p: string) => { exec(sql: string): void; prepare(sql: string): { run(...a: unknown[]): unknown; all(): unknown[] }; close(): void } };
    const db = new DatabaseSync(f);
    db.exec("CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, tx_time TEXT NOT NULL, fact_id TEXT NOT NULL, json TEXT NOT NULL)");
    const assert = { eventId: "e1", kind: "assert", txTime: "2026-09-01T00:00:00.000Z", fact: { factId: "f1", subject: "acct:1", predicate: "plan", value: "pro", space: "org", actor: "x", source: { receiptId: null }, provenance: "attested", validFrom: "2026-09-01T00:00:00.000Z", validTo: null, confidence: null }, supersedes: null };
    const replacement = { ...assert, eventId: "e2", txTime: "2026-09-02T00:00:00.000Z", fact: { ...assert.fact, factId: "f2", value: "enterprise", validFrom: "2026-09-02T00:00:00.000Z" }, supersedes: "f1" };
    for (const e of [assert, replacement]) db.prepare("INSERT INTO events (event_id, kind, tx_time, fact_id, json) VALUES (?, ?, ?, ?, ?)").run(e.eventId, e.kind, e.txTime, e.fact.factId, JSON.stringify(e));
    db.close();
    const l = new Ledger(f);
    expect((await l.asOf({ subject: "acct:1", predicate: "plan" })).map((x) => x.value)).toEqual(["enterprise"]);
    expect((await l.asOf({ validAt: "2026-09-01T12:00:00.000Z" })).map((x) => x.value)).toEqual(["pro"]);
    expect((await l.history("f1")).map((e) => e.eventId)).toEqual(["e1", "e2"]);
    expect(await l.spaces()).toEqual(["org"]);
    await l.close();
    const check = new DatabaseSync(f);
    expect(check.prepare("SELECT space, subject, predicate, supersedes FROM events ORDER BY seq").all()).toEqual([{ space: "org", subject: "acct:1", predicate: "plan", supersedes: null }, { space: "org", subject: "acct:1", predicate: "plan", supersedes: "f1" }]);
    check.close();
  });
});

describe("postgres", () => {
  it("one table is one ledger for every server that opens it: a write through one store is read through another", async () => {
    const db = new PGlite();
    const writer = new Ledger(new PostgresStore(db, { table: "shared" }));
    const reader = new Ledger(new PostgresStore(db, { table: "shared" }));
    const a = await writer.assert({ subject: "s", predicate: "p", value: "from-writer", space: "org", actor: "x" });
    expect((await reader.asOf()).map((f) => f.value)).toEqual(["from-writer"]);
    await reader.hold({ factId: a.fact.factId, actor: "legal", reason: "matter" });
    await expect(writer.forget({ factId: a.fact.factId, actor: "dpo", reason: "r" })).rejects.toThrow(/legal hold/);
    expect(await writer.count()).toBe(2);
    await db.close();
  });

  it("spaces() lists the distinct spaces, sorted, and none on an empty ledger", async () => {
    const db = new PGlite();
    const store = new PostgresStore(db, { table: "spaces" });
    expect(await store.spaces()).toEqual([]);
    const l = new Ledger(store);
    await l.assert({ subject: "s", predicate: "p", value: 1, space: "team:x", actor: "x" });
    await l.assert({ subject: "s", predicate: "p", value: 2, space: "org", actor: "x" });
    await l.assert({ subject: "t", predicate: "q", value: 3, space: "team:x", actor: "x" });
    expect(await store.spaces()).toEqual(["org", "team:x"]);
    expect(await l.spaces()).toEqual(["org", "team:x"]);
    await db.close();
  });

  it("forget leaves no copy of the value in the database files once the table is vacuumed", async () => {
    const dataDir = join(dir(), "pgdata");
    const db = new PGlite(dataDir);
    const l = new Ledger(new PostgresStore(db, { table: "custody" }));
    const secret = await l.assert({ subject: "p:1", predicate: "ssn", value: "SSN-987-65-4321", space: "org", actor: "x" });
    await l.assert({ subject: "p:1", predicate: "plan", value: "pro", space: "org", actor: "x" });
    await l.forget({ factId: secret.fact.factId, actor: "dpo", reason: "request" });
    expect((await l.facts()).find((x) => x.factId === secret.fact.factId)?.forgotten?.digestKind).toBe("sha256");
    expect((await l.export()).map((e) => e.kind)).toEqual(["assert", "assert", "forget"]);
    await db.query("CHECKPOINT");
    await db.close();
    const hits = (await findInFiles(dataDir, "SSN-987-65-4321")).filter((p) => !p.includes("pg_wal"));
    expect(hits).toEqual([]);
    expect((await findInFiles(dataDir, "pro")).some((p) => p.includes("base"))).toBe(true);
  });

  it("without vacuum the old row image stays in the table file, which is what the option documents", async () => {
    const dataDir = join(dir(), "pgdata-novacuum");
    const db = new PGlite(dataDir);
    const l = new Ledger(new PostgresStore(db, { table: "custody", vacuum: false }));
    const secret = await l.assert({ subject: "p:1", predicate: "ssn", value: "SSN-111-22-3333", space: "org", actor: "x" });
    await l.forget({ factId: secret.fact.factId, actor: "dpo", reason: "request" });
    await db.query("CHECKPOINT");
    await db.close();
    expect((await findInFiles(dataDir, "SSN-111-22-3333")).some((p) => p.includes("base"))).toBe(true);
  });

  it("refuses a table name that is not a plain identifier", () => {
    expect(() => new PostgresStore(new PGlite(), { table: "events; DROP TABLE events" })).toThrow(/plain identifier/);
  });

  it("a postgres:// URL opens a store whose location names the host and table but never the password, or says to install pg", async () => {
    // Bun installs the optional pg peer here; a consumer without it gets the message instead of a resolution error.
    let store: ReturnType<typeof openStore>;
    try {
      store = openStore("postgres://user:hunter2@db.example.com:5432/custody?table=custody.events&vacuum=false&sslmode=require");
    } catch (e) {
      expect(String(e)).toMatch(/npm install pg/);
      return;
    }
    expect(store.kind).toBe("postgres");
    expect(store.location).toBe("postgres://user@db.example.com:5432/custody table custody.events");
    expect(store.location).not.toContain("hunter2");
    await store.close(); // the pool was never connected; ending it must not try to
  });
});

/** Files under a directory whose bytes contain the needle. */
async function findInFiles(root: string, needle: string): Promise<string[]> {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.isFile() && readFileSync(p, "latin1").includes(needle)) out.push(p);
    }
  };
  walk(root);
  return out;
}
