// The ledger exists so a wrong belief can be found, dated, and undone without losing what the agent believed at the time.
// Every test here is a question a platform owner asks after a memory incident.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { Ledger } from "../src/ledger.ts";
import { PostgresStore, type EventStore } from "../src/storage.ts";

/** A clock the tests advance by hand, so transaction time is exact. */
function clock(start = "2026-09-01T00:00:00.000Z") {
  let t = new Date(start);
  return { now: () => t, set: (iso: string) => (t = new Date(iso)) };
}

/** Postgres runs in-process through PGlite, the real engine compiled to WebAssembly, one table per test; the same SQL a pg Pool would run. */
let pg: PGlite | null = null;
let tables = 0;
afterAll(async () => {
  await pg?.close();
});

const backends: [string, () => string | EventStore][] = [
  ["jsonl", () => join(mkdtempSync(join(tmpdir(), "state-ledger-")), "ledger.jsonl")],
  ["sqlite", () => join(mkdtempSync(join(tmpdir(), "state-ledger-")), "ledger.sqlite")],
  ["postgres", () => new PostgresStore((pg ??= new PGlite()), { table: `ledger_${++tables}` })],
];

describe.each(backends)("fact ledger on %s", (name, file) => {
  it("answers what is believed now, filtered by space, subject and predicate", async () => {
    const l = new Ledger(file(), clock());
    await l.assert({ subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support" });
    await l.assert({ subject: "acct:42", predicate: "owner", value: "dana", space: "org", actor: "agent:support" });
    await l.assert({ subject: "acct:42", predicate: "plan", value: "trial", space: "user:me", actor: "user:me" });
    expect((await l.asOf({ space: "org" })).map((f) => f.value)).toEqual(["pro", "dana"]);
    expect((await l.asOf({ subject: "acct:42", predicate: "plan" })).map((f) => f.space)).toEqual(["org", "user:me"]);
  });

  it("records the repair of a store entry the ledger has no fact for, under that entry's fact id, and refuses one it has", async () => {
    const l = new Ledger(file(), clock());
    const kept = await l.assert({ subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support" });
    const ev = await l.repair({ factId: "orphan-1", store: "vec", externalId: "row-1", actor: "ops", reason: "append failed" });
    expect(await l.history("orphan-1")).toEqual([ev]);
    expect(await l.get("orphan-1")).toBeUndefined();
    expect((await l.asOf()).map((f) => f.factId)).toEqual([kept.fact.factId]);
    await expect(l.repair({ factId: kept.fact.factId, store: "vec", externalId: "row-2", actor: "ops", reason: "x" })).rejects.toThrow(/is in the ledger/);
  });

  it("lets the first record of a fact id win: a repair then blocks a late assert, and a repair of the same entry adds no second event", async () => {
    const l = new Ledger(file(), clock());
    const first = await l.repair({ factId: "orphan-2", store: "vec", externalId: "row-1", actor: "ops", reason: "append failed" });
    expect(await l.repair({ factId: "orphan-2", store: "vec", externalId: "row-1", actor: "ops", reason: "again" })).toEqual(first);
    await expect(l.assert({ factId: "orphan-2", subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support" })).rejects.toThrow(/claimed by a repair/);
    expect(await l.history("orphan-2")).toEqual([first]);
    expect(await l.get("orphan-2")).toBeUndefined();
  });

  it("keeps one outcome when an assert and a repair of the same fact id start together", async () => {
    const l = new Ledger(file(), clock());
    const input = { factId: "race-1", subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support" };
    const results = await Promise.allSettled([l.assert(input), l.repair({ factId: "race-1", store: "vec", externalId: "row-1", actor: "ops", reason: "x" })]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await l.history("race-1")).toHaveLength(1);
  });

  it("superseding a fact ends its validity where the replacement begins, so the old value is still true for its own interval", async () => {
    const c = clock();
    const l = new Ledger(file(), c);
    const a = await l.assert({ subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support", validFrom: "2026-08-01T00:00:00.000Z" });
    c.set("2026-09-10T00:00:00.000Z");
    await l.assert({ subject: "acct:42", predicate: "plan", value: "enterprise", space: "org", actor: "agent:sales", supersedes: a.fact.factId, validFrom: "2026-09-10T00:00:00.000Z" });
    expect((await l.asOf({ validAt: "2026-08-15T00:00:00.000Z" })).map((f) => f.value)).toEqual(["pro"]);
    expect((await l.asOf({ validAt: "2026-09-10T00:00:00.000Z" })).map((f) => f.value)).toEqual(["enterprise"]);
    expect((await l.asOf({ validAt: "2026-09-10T00:00:00.000Z" }))[0]!.actor).toBe("agent:sales");
  });

  it("distinguishes when a fact was true from when the ledger learned it", async () => {
    const c = clock("2026-09-05T00:00:00.000Z");
    const l = new Ledger(file(), c);
    // Learned on the 5th that the contract had been signed on the 1st.
    await l.assert({ subject: "deal:7", predicate: "status", value: "signed", space: "org", actor: "agent:ops", validFrom: "2026-09-01T00:00:00.000Z" });
    // On the 3rd the deal was signed, but nobody knew yet.
    expect(await l.asOf({ validAt: "2026-09-03T00:00:00.000Z", txAt: "2026-09-03T00:00:00.000Z" })).toEqual([]);
    expect((await l.asOf({ validAt: "2026-09-03T00:00:00.000Z" })).map((f) => f.value)).toEqual(["signed"]);
  });

  it("retracting a wrong fact removes it from now but not from what was believed before the retraction", async () => {
    const c = clock();
    const l = new Ledger(file(), c);
    const bad = await l.assert({ subject: "acct:42", predicate: "owner", value: "mallory", space: "org", actor: "agent:intern", source: { receiptId: "r-1" } });
    c.set("2026-09-02T00:00:00.000Z");
    const r = await l.retract({ factId: bad.fact.factId, actor: "user:admin", reason: "poisoned by a tool result" });
    expect(await l.asOf()).toEqual([]);
    expect((await l.asOf({ validAt: "2026-09-01T12:00:00.000Z", txAt: "2026-09-01T12:00:00.000Z" })).map((f) => f.value)).toEqual(["mallory"]);
    expect((await l.history(bad.fact.factId)).map((e) => e.kind)).toEqual(["assert", "retract"]);
    expect(r.reason).toBe("poisoned by a tool result");
  });

  it("retracting the replacement restores the fact it superseded", async () => {
    const c = clock();
    const l = new Ledger(file(), c);
    const good = await l.assert({ subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support" });
    c.set("2026-09-02T00:00:00.000Z");
    const bad = await l.assert({ subject: "acct:42", predicate: "plan", value: "free", space: "org", actor: "agent:intern", supersedes: good.fact.factId });
    expect((await l.asOf()).map((f) => f.value)).toEqual(["free"]);
    c.set("2026-09-03T00:00:00.000Z");
    await l.retract({ factId: bad.fact.factId, actor: "user:admin", reason: "wrong" });
    expect((await l.asOf()).map((f) => f.value)).toEqual(["pro"]);
    // and the restored fact can be superseded again, by a better write this time
    c.set("2026-09-04T00:00:00.000Z");
    await l.assert({ subject: "acct:42", predicate: "plan", value: "enterprise", space: "org", actor: "agent:sales", supersedes: good.fact.factId });
    expect((await l.asOf()).map((f) => f.value)).toEqual(["enterprise"]);
  });

  it("refuses to supersede a fact that is unknown, already superseded, or retracted, and refuses a replacement that starts earlier", async () => {
    const c = clock();
    const l = new Ledger(file(), c);
    const a = await l.assert({ subject: "s", predicate: "p", value: 1, space: "org", actor: "x", validFrom: "2026-09-01T00:00:00.000Z" });
    await expect(l.assert({ subject: "s", predicate: "p", value: 2, space: "org", actor: "x", supersedes: "nope" })).rejects.toThrow(/unknown fact/);
    await expect(l.assert({ subject: "s", predicate: "p", value: 2, space: "org", actor: "x", supersedes: a.fact.factId, validFrom: "2026-08-01T00:00:00.000Z" })).rejects.toThrow(/cannot start before/);
    c.set("2026-09-02T00:00:00.000Z");
    const b = await l.assert({ subject: "s", predicate: "p", value: 2, space: "org", actor: "x", supersedes: a.fact.factId });
    await expect(l.assert({ subject: "s", predicate: "p", value: 3, space: "org", actor: "x", supersedes: a.fact.factId })).rejects.toThrow(/already superseded/);
    await l.retract({ factId: b.fact.factId, actor: "x", reason: "wrong" });
    await expect(l.assert({ subject: "s", predicate: "p", value: 3, space: "org", actor: "x", supersedes: b.fact.factId })).rejects.toThrow(/is retracted/);
    await expect(l.retract({ factId: b.fact.factId, actor: "x", reason: "again" })).rejects.toThrow(/already retracted/);
  });

  it("persists every event as one JSON line and reopens to the same beliefs", async () => {
    const c = clock();
    const f = file();
    const l = new Ledger(f, c);
    const a = await l.assert({ subject: "s", predicate: "p", value: 1, space: "org", actor: "x", source: { receiptId: "r-9" } });
    c.set("2026-09-02T00:00:00.000Z");
    await l.assert({ subject: "s", predicate: "p", value: 2, space: "org", actor: "y", supersedes: a.fact.factId });
    if (name === "jsonl") {
      const lines = readFileSync(f as string, "utf8").trim().split("\n");
      expect(lines).toHaveLength(2);
      expect(JSON.parse(lines[0]!).fact.source).toEqual({ receiptId: "r-9" });
    }
    const reopened = new Ledger(f, c);
    expect(await reopened.count()).toBe(2);
    expect(await reopened.asOf()).toEqual(await l.asOf());
    expect((await reopened.asOf({ validAt: "2026-09-01T12:00:00.000Z" })).map((x) => x.value)).toEqual([1]);
  });

  it("a claimed fact is quarantined until an attested party confirms it, and the confirmation has its own transaction time", async () => {
    const c = clock();
    const f = file();
    const l = new Ledger(f, c);
    const claimed = await l.assert({ subject: "acct:42", predicate: "owner", value: "dana", space: "org", actor: "sdk-bot" });
    const attested = await l.assert({ subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "support-agent", provenance: "attested", source: { receiptId: "r-1" } });
    expect((await l.asOf({ include: "attested" })).map((f) => f.factId)).toEqual([attested.fact.factId]);
    expect((await l.asOf()).map((f) => f.provenance)).toEqual(["claimed", "attested"]);
    c.set("2026-09-02T00:00:00.000Z");
    const ok = await l.confirm({ factId: claimed.fact.factId, actor: "support-agent", source: { receiptId: "r-2" } });
    expect(ok.kind).toBe("confirm");
    expect((await l.asOf({ include: "attested" })).map((f) => f.factId).sort()).toEqual([claimed.fact.factId, attested.fact.factId].sort());
    // before the confirmation was recorded, the fact was still in quarantine
    expect((await l.asOf({ include: "attested", validAt: "2026-09-01T12:00:00.000Z", txAt: "2026-09-01T12:00:00.000Z" })).map((f) => f.factId)).toEqual([attested.fact.factId]);
    expect((await l.history(claimed.fact.factId)).map((e) => e.kind)).toEqual(["assert", "confirm"]);
    await expect(l.confirm({ factId: claimed.fact.factId, actor: "x" })).rejects.toThrow(/already attested/);
    await expect(l.confirm({ factId: attested.fact.factId, actor: "x" })).rejects.toThrow(/already attested/);
    await expect(l.confirm({ factId: "nope", actor: "x" })).rejects.toThrow(/unknown fact/);
    await l.retract({ factId: claimed.fact.factId, actor: "x", reason: "wrong" });
    await expect(l.confirm({ factId: claimed.fact.factId, actor: "x" })).rejects.toThrow(/is retracted/);
    const reopened = new Ledger(f, c);
    expect(await reopened.count()).toBe(4);
  });

  it("forgetting erases the value from the file, keeps its digest, stops believing it, and survives reopening", async () => {
    const c = clock();
    const f = file();
    const l = new Ledger(f, c);
    const secret = await l.assert({ subject: "person:1", predicate: "ssn", value: "123-45-6789", space: "org", actor: "intake", provenance: "attested", source: { receiptId: "r-1" } });
    await l.assert({ subject: "person:1", predicate: "plan", value: "pro", space: "org", actor: "intake" });
    c.set("2026-09-03T00:00:00.000Z");
    const ev = await l.forget({ factId: secret.fact.factId, actor: "user:dpo", reason: "deletion request 4471", source: { receiptId: "r-9" } });
    expect(ev.kind).toBe("forget");
    expect(ev.valueDigest).toMatch(/^[0-9a-f]{64}$/);
    if (typeof f === "string") {
      const raw = readFileSync(f, "latin1");
      expect(raw).not.toContain("123-45-6789");
      expect(raw).toContain(ev.valueDigest);
    }
    expect((await l.asOf({ subject: "person:1" })).map((x) => x.predicate)).toEqual(["plan"]);
    expect((await l.history(secret.fact.factId)).map((e) => e.kind)).toEqual(["assert", "forget"]);
    expect((await l.facts()).find((x) => x.factId === secret.fact.factId)).toMatchObject({ value: null, forgotten: { valueDigest: ev.valueDigest, at: "2026-09-03T00:00:00.000Z" } });
    // what was believed before the erasure still answers, without the value
    expect((await l.asOf({ subject: "person:1", validAt: "2026-09-02T00:00:00.000Z", txAt: "2026-09-02T00:00:00.000Z" })).map((x) => [x.predicate, x.value])).toEqual([["ssn", null], ["plan", "pro"]]);
    const reopened = new Ledger(f, c);
    expect(await reopened.count()).toBe(3);
    expect(await reopened.asOf({ subject: "person:1" })).toHaveLength(1);
    await expect(l.forget({ factId: secret.fact.factId, actor: "x", reason: "again" })).rejects.toThrow(/already forgotten/);
    await expect(l.forget({ factId: "nope", actor: "x", reason: "x" })).rejects.toThrow(/unknown fact/);
  });

  it("provenance is ranked: include verified leaves out attested, include attested leaves out claimed", async () => {
    const l = new Ledger(file(), clock());
    await l.assert({ subject: "s", predicate: "a", value: 1, space: "org", actor: "x" });
    await l.assert({ subject: "s", predicate: "b", value: 2, space: "org", actor: "x", provenance: "attested" });
    await l.assert({ subject: "s", predicate: "c", value: 3, space: "org", actor: "x", provenance: "verified" });
    expect((await l.asOf({ include: "verified" })).map((f) => f.predicate)).toEqual(["c"]);
    expect((await l.asOf({ include: "attested" })).map((f) => f.predicate)).toEqual(["b", "c"]);
    expect((await l.asOf()).map((f) => f.predicate)).toEqual(["a", "b", "c"]);
    const v = (await l.asOf({ include: "verified" }))[0]!;
    await expect(l.confirm({ factId: v.factId, actor: "x" })).rejects.toThrow(/already attested/);
  });

  it("a legal hold refuses forget and sweep until released; a sweep forgets what was learned before the cutoff", async () => {
    const c = clock("2026-09-01T00:00:00.000Z");
    const l = new Ledger(file(), c);
    const old = await l.assert({ subject: "p:1", predicate: "email", value: "a@x", space: "org", actor: "x" });
    const kept = await l.assert({ subject: "p:2", predicate: "email", value: "b@x", space: "org", actor: "x" });
    const other = await l.assert({ subject: "p:3", predicate: "email", value: "c@x", space: "team", actor: "x" });
    c.set("2026-09-10T00:00:00.000Z");
    const recent = await l.assert({ subject: "p:4", predicate: "email", value: "d@x", space: "org", actor: "x" });
    await l.hold({ factId: kept.fact.factId, actor: "legal", reason: "litigation 12" });
    expect(await l.held(kept.fact.factId)).toBe(true);
    await expect(l.forget({ factId: kept.fact.factId, actor: "x", reason: "request" })).rejects.toThrow(/legal hold/);
    await expect(l.hold({ factId: kept.fact.factId, actor: "legal", reason: "again" })).rejects.toThrow(/already on hold/);
    const r = await l.sweep({ before: "2026-09-05T00:00:00.000Z", space: "org", actor: "retention", reason: "90 days" });
    expect(r.forgotten.map((e) => e.factId)).toEqual([old.fact.factId]);
    expect(r.held).toEqual([kept.fact.factId]);
    expect((await l.facts()).find((f) => f.factId === other.fact.factId)?.forgotten).toBeUndefined();
    expect((await l.facts()).find((f) => f.factId === recent.fact.factId)?.forgotten).toBeUndefined();
    await l.release({ factId: kept.fact.factId, actor: "legal", reason: "matter closed" });
    expect(await l.held(kept.fact.factId)).toBe(false);
    await expect(l.release({ factId: kept.fact.factId, actor: "legal", reason: "twice" })).rejects.toThrow(/not on hold/);
    expect((await l.forget({ factId: kept.fact.factId, actor: "x", reason: "request" })).kind).toBe("forget");
    expect((await l.history(kept.fact.factId)).map((e) => e.kind)).toEqual(["assert", "hold", "release", "forget"]);
  });

  it("a forget key turns the kept digest into an HMAC, and keepDigest false keeps nothing", async () => {
    const f1 = file();
    const a = new Ledger(f1, { ...clock(), forgetKey: "secret-one" });
    const b = new Ledger(file(), { ...clock(), forgetKey: "secret-two" });
    const plain = new Ledger(file(), clock());
    const write = async (l: Ledger) => (await l.assert({ subject: "p:1", predicate: "email", value: "dana@example.com", space: "org", actor: "x" })).fact.factId;
    const ea = await a.forget({ factId: await write(a), actor: "dpo", reason: "request" });
    const eb = await b.forget({ factId: await write(b), actor: "dpo", reason: "request" });
    const ep = await plain.forget({ factId: await write(plain), actor: "dpo", reason: "request" });
    expect(ea.digestKind).toBe("hmac-sha256");
    expect(eb.digestKind).toBe("hmac-sha256");
    expect(ep.digestKind).toBe("sha256");
    expect(ea.valueDigest).not.toBe(eb.valueDigest);
    expect(ea.valueDigest).not.toBe(ep.valueDigest);
    if (typeof f1 === "string") expect(readFileSync(f1, "utf8")).not.toContain("dana@example.com");
    // the same secret reproduces the digest, which is how the ledger proves what it erased to someone shown the key
    const again = new Ledger(file(), { ...clock(), forgetKey: "secret-one" });
    expect((await again.forget({ factId: await write(again), actor: "dpo", reason: "request" })).valueDigest).toBe(ea.valueDigest);
    const none = new Ledger(file(), { ...clock(), forgetKey: "secret-one" });
    const en = await none.forget({ factId: await write(none), actor: "dpo", reason: "request", keepDigest: false });
    expect(en).toMatchObject({ digestKind: "none", valueDigest: null });
    expect((await none.facts())[0]?.forgotten).toMatchObject({ digestKind: "none", valueDigest: null });
    expect((await none.sweep({ before: new Date(Date.now() + 1000).toISOString(), actor: "r", reason: "r", keepDigest: false })).forgotten).toEqual([]);
  });
});
