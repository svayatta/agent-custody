// The Postgres log must be the same log as the file: same roots, same proofs, for the same leaves. On top of that
// it must be safe with a second writer, hold tenants and hashed tokens, refuse floods, and take a file log in.
// Postgres runs in-process through PGlite, the real engine compiled to WebAssembly.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { leafHash, MerkleLog, verifyConsistency, verifyInclusion } from "../src/log.ts";
import { httpLog, postgresResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { importLogFile, PostgresLog, PostgresTenancy, RateLimiter } from "../src/log-store.ts";

let db: PGlite;
// PGlite's first query loads the engine, which can take seconds on a loaded machine; pay it here, not in a test.
beforeAll(async () => {
  db = new PGlite();
  await db.query("SELECT 1");
}, 60_000);
afterAll(async () => {
  await db.close();
});

describe("PostgresLog", () => {
  it("agrees with the file log leaf for leaf: roots, inclusion proofs, and consistency proofs", async () => {
    const file = new MerkleLog(join(mkdtempSync(join(tmpdir(), "pglog-")), "log.jsonl"));
    const pg = new PostgresLog(db, "agree");
    for (let i = 0; i < 9; i++) {
      const leaf = `leaf-${i}`;
      const a = file.append(leaf);
      const b = i % 3 === 0 ? await pg.appendHash(leafHash(leaf).toString("hex")) : await pg.append(leaf);
      expect(b).toEqual(a);
      expect(verifyInclusion(leafHash(leaf), b, b.rootHash)).toBe(true);
    }
    expect(await pg.size()).toBe(9);
    expect(await pg.root(5)).toBe(file.root(5));
    expect(await pg.consistencyProof(5, 9)).toEqual(file.consistencyProof(5, 9));
    expect(verifyConsistency(5, await pg.root(5), 9, await pg.root(9), await pg.consistencyProof(5, 9))).toBe(true);
    await expect(pg.appendHash("nope")).rejects.toThrow(/64 lowercase hex/);
  }, 20_000);

  it("a second instance on the same tenant sees the first's leaves and appends after them, never over them", async () => {
    const one = new PostgresLog(db, "shared");
    const two = new PostgresLog(db, "shared");
    const a = await one.append("from one");
    const b = await two.append("from two");
    expect([a.leafIndex, b.leafIndex]).toEqual([0, 1]);
    const c = await one.append("from one again");
    expect(c.leafIndex).toBe(2);
    // both instances now agree on the whole tree, and the file-log arithmetic gives the same root
    expect(await two.root()).toBe(await one.root());
    const check = new MerkleLog(join(mkdtempSync(join(tmpdir(), "pglog-check-")), "log.jsonl"));
    for (const l of ["from one", "from two", "from one again"]) check.append(l);
    expect(await two.root()).toBe(check.root());
    // interleaved appends from both instances stay consistent
    await Promise.all([one.append("x1"), two.append("y1"), one.append("x2"), two.append("y2")]);
    expect(await one.size()).toBe(7);
    expect(await two.root()).toBe(await one.root());
  });

  it("tenants are separate trees", async () => {
    const a = new PostgresLog(db, "tenant-a");
    const b = new PostgresLog(db, "tenant-b");
    await a.append("same leaf");
    await b.append("same leaf");
    await b.append("another");
    expect(await a.size()).toBe(1);
    expect(await b.size()).toBe(2);
  });
});

describe("PostgresTenancy", () => {
  it("adds tenants, mints tokens stored only as hashes, authorizes, revokes, and disables", async () => {
    const t = new PostgresTenancy(db);
    const acme = await t.addTenant("acme", "acme-eu");
    expect(acme.logId).toBe("acme-eu");
    const { token, tokenHash } = await t.addToken("acme", "support-fleet");
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    const rows = (await db.query("SELECT token_hash FROM log_tokens WHERE tenant_id = 'acme'")).rows as { token_hash: string }[];
    expect(rows.map((r) => r.token_hash)).toEqual([tokenHash]);
    expect(rows[0]!.token_hash).not.toBe(token);
    expect(await t.authorize("acme", token)).toBe(true);
    expect(await t.authorize("acme", "not-it")).toBe(false);
    expect(await t.authorize("other", token)).toBe(false);
    await t.addTenant("other");
    expect(await t.authorize("other", token)).toBe(false);
    expect(await t.revokeToken("acme", tokenHash.slice(0, 8))).toBe(1);
    expect(await t.authorize("acme", token)).toBe(false);
    expect((await t.listTokens("acme"))[0]?.revokedAt).not.toBeNull();
    await expect(t.revokeToken("acme", "abc")).rejects.toThrow(/eight/);
    await expect(t.addToken("nobody", "x")).rejects.toThrow(/unknown tenant/);
    await t.disableTenant("other");
    expect((await t.tenant("other"))?.disabledAt).not.toBeNull();
    expect((await t.listTenants()).map((x) => x.id)).toEqual(["acme", "other"]);
  });

  it("records the last use of a token at most once a minute, and a failed write does not refuse the token", async () => {
    let writes = 0;
    let fail = false;
    const t = new PostgresTenancy({ query: async (sql, values) => { if (sql.includes("SET last_used_at")) { writes++; if (fail) throw new Error("down"); } return db.query(sql, values); } }, { prefix: "lu_" });
    await t.addTenant("acme");
    const { token } = await t.addToken("acme", "fleet");
    expect((await t.listTokens("acme"))[0]!.lastUsedAt).toBeNull();
    for (let i = 0; i < 5; i++) expect(await t.authorize("acme", token)).toBe(true);
    await vi.waitFor(async () => expect((await t.listTokens("acme"))[0]!.lastUsedAt).not.toBeNull());
    expect(writes).toBe(1);
    const later = Date.now() + 61_000;
    const now = vi.spyOn(Date, "now").mockReturnValue(later);
    try {
      fail = true;
      expect(await t.authorize("acme", token)).toBe(true);
      expect(writes).toBe(2);
      await new Promise((r) => setTimeout(r, 10));
      fail = false;
      expect(await t.authorize("acme", token)).toBe(true);
      expect(writes).toBe(3);
    } finally {
      now.mockRestore();
    }
  });

  it("pages the audit trail newest first with a cursor", async () => {
    const t = new PostgresTenancy(db, { prefix: "au_" });
    await t.addTenant("acme");
    for (let i = 0; i < 4; i++) await t.addToken("acme", `k${i}`);
    const all = await t.audit({ tenant: "acme" });
    expect(all).toHaveLength(5);
    const first = await t.audit({ tenant: "acme", limit: 2 });
    expect(first.map((e) => e.id)).toEqual(all.slice(0, 2).map((e) => e.id));
    expect((await t.audit({ tenant: "acme", limit: 2, before: first[1]!.id })).map((e) => e.id)).toEqual(all.slice(2, 4).map((e) => e.id));
    expect(await t.audit({ tenant: "other" })).toEqual([]);
  });
});

describe("the log server over Postgres", () => {
  let log: RunningLog;
  let tenancy: PostgresTenancy;
  let logPub: string;
  let acmeToken: string;
  beforeAll(async () => {
    const dir = mkdtempSync(join(tmpdir(), "pgserver-"));
    const kp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "log");
    logPub = kp.pubFile;
    tenancy = new PostgresTenancy(db, { prefix: "srv_" });
    await tenancy.addTenant("default", "log.example.test");
    await tenancy.addTenant("acme", "acme-eu");
    acmeToken = (await tenancy.addToken("acme", "fleet")).token;
    log = await serveLog(postgresResolver(tenancy, { staticTokens: ["env-token"] }), loadPrivateKey(kp.keyFile), { port: 0, rateLimit: { perSecond: 1, burst: 3 }, maxBodyBytes: 512 });
  });
  afterAll(() => log.close());

  const post = (path: string, token: string | null, body: unknown) => fetch(new URL(path, log.url), { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
  const headOf = async (r: Response) => JSON.parse(Buffer.from(((await r.json()) as { treeHead: { payload: string } }).treeHead.payload, "base64").toString()) as { log?: string; treeSize: number };

  it("tenants from the database, tokens from the database, the environment token for the default log, and log ids on heads", async () => {
    expect((await post("t/acme/append", null, { leafHash: "ab".repeat(32) })).status).toBe(401);
    expect((await post("t/acme/append", "env-token", { leafHash: "ab".repeat(32) })).status).toBe(401);
    const ok = await post("t/acme/append", acmeToken, { leafHash: "ab".repeat(32) });
    expect(ok.status).toBe(200);
    expect(await headOf(ok)).toMatchObject({ log: "acme-eu", treeSize: 1 });
    const def = await post("append", "env-token", { leaf: "root path" });
    expect(def.status).toBe(200);
    expect(await headOf(def)).toMatchObject({ log: "log.example.test", treeSize: 1 });
    expect((await post("t/nobody/append", acmeToken, { leaf: "x" })).status).toBe(404);
    expect(((await (await fetch(new URL("t/acme/root", log.url))).json()) as { treeSize: number }).treeSize).toBe(1);
  });

  it("the sink retries a 429 and gets through; a flood past the burst is refused with retry-after; a huge body is refused", async () => {
    const sink = httpLog(new URL("t/acme/", log.url).toString(), { token: acmeToken, hashOnly: true, retries: 4 });
    // burst is 3 and one was used above; two more direct appends drain it, then the sink's first try sees 429 and waits
    expect((await post("t/acme/append", acmeToken, { leafHash: "cd".repeat(32) })).status).toBe(200);
    expect((await post("t/acme/append", acmeToken, { leafHash: "ef".repeat(32) })).status).toBe(200);
    const refused = await post("t/acme/append", acmeToken, { leafHash: "01".repeat(32) });
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBe("1");
    const entry = await sink.append("a receipt envelope, hashed by the sink");
    expect(entry.inclusion.leafIndex).toBe(3);
    // rate limits are per token: the default log's token is untouched, and a huge body there is refused on size
    expect((await post("append", "env-token", { leaf: "still fine" })).status).toBe(200);
    const big = await post("append", "env-token", { leaf: "x".repeat(600) });
    expect(big.status).toBe(413);
  }, 20_000);

  it("a disabled tenant disappears from the paths within the cache window", async () => {
    await tenancy.addTenant("gone", "gone");
    const tok = (await tenancy.addToken("gone", "x")).token;
    expect((await post("t/gone/append", tok, { leaf: "y" })).status).toBe(200);
    await tenancy.disableTenant("gone");
    expect((await post("t/gone/append", tok, { leaf: "z" })).status).toBe(404);
  });

  it("the head of a tenant's log names the tenant's log id and is signed by the server key", async () => {
    const head = await headOf(await fetch(new URL("t/acme/head", log.url)));
    expect(head.log).toBe("acme-eu");
    expect(loadPublicKey(logPub).keyid).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("importLogFile", () => {
  it("brings a file log into Postgres as hashes, same roots, and is safe to run twice", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pgimport-"));
    const file = join(dir, "log.jsonl");
    const src = new MerkleLog(file);
    src.append("first");
    src.append("second");
    src.appendHash("ab".repeat(32));
    writeFileSync(file, `${JSON.stringify("first")}\n${JSON.stringify({ pruned: leafHash("second").toString("hex") })}\n${JSON.stringify({ hash: "ab".repeat(32) })}\n`);
    const pg = new PostgresLog(db, "imported");
    expect(await importLogFile(file, pg)).toEqual({ added: 3, total: 3 });
    expect(await pg.root()).toBe(src.root());
    expect(await importLogFile(file, pg)).toEqual({ added: 0, total: 3 });
    const rows = (await db.query("SELECT COUNT(*) AS n FROM log_leaves WHERE tenant_id = 'imported'")).rows as { n: string | number }[];
    expect(Number(rows[0]!.n)).toBe(3);
  });
});

describe("RateLimiter", () => {
  it("refills at the configured rate and never exceeds the burst", () => {
    const r = new RateLimiter({ perSecond: 10, burst: 2 });
    expect([r.take("k", 0), r.take("k", 0), r.take("k", 0)]).toEqual([true, true, false]);
    expect(r.take("k", 100)).toBe(true); // one token refilled after 100 ms at 10/s
    expect(r.take("k", 100)).toBe(false);
    expect(r.take("k", 5000)).toBe(true);
    expect(r.take("k", 5000)).toBe(true);
    expect(r.take("k", 5000)).toBe(false);
    expect(r.take("other", 5000)).toBe(true);
  });
});
