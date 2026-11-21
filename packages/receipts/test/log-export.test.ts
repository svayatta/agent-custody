// A tenant's export is theirs to take: with their own token they get every leaf hash, the signed head, the keys,
// the checkpoints, and their usage, and the export checks that it all adds up before it is written. The leaves
// become a log file the verifier reads directly. Another tenant's token gets nothing.
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { dsseSign, generateKeyPair } from "../src/crypto.ts";
import { dirCheckpoints } from "../src/checkpoints.ts";
import { MerkleLog } from "../src/log.ts";
import { exportLog, formatExport } from "../src/log-export.ts";
import { CheckpointPublisher, fileResolver, httpLog, postgresResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { fileBackend, PostgresTenancy } from "../src/log-store.ts";
import { TREEHEAD_TYPE } from "../src/receipt.ts";
import { localSigner } from "../src/signer.ts";

let db: PGlite;
let log: RunningLog;
let acmeToken: string;
let otherToken: string;

beforeAll(async () => {
  db = new PGlite();
  await db.query("SELECT 1");
  const tenancy = new PostgresTenancy(db, { prefix: "exp_" });
  await tenancy.addTenant("default", "log.example.test");
  await tenancy.addTenant("acme", "acme-eu");
  await tenancy.addTenant("other", "other-eu");
  acmeToken = (await tenancy.addToken("acme", "fleet")).token;
  await tenancy.addPolicy("acme", "refunds-v1", "permit(principal, action, resource);\n", "test");
  otherToken = (await tenancy.addToken("other", "fleet")).token;
  const cpDir = mkdtempSync(join(tmpdir(), "export-cp-"));
  log = await serveLog(postgresResolver(tenancy), generateKeyPair(), { port: 0, checkpoints: dirCheckpoints(cpDir) });
}, 60_000);

afterAll(async () => {
  await log?.close();
  await db?.close();
});

describe("a tenant's export", () => {
  it("fetches every leaf in pages, verifies the head and checkpoints against the published keys, writes a log copy the verifier reads, and reports usage", async () => {
    const sink = httpLog(`${log.url}t/acme/`, { token: acmeToken, hashOnly: true });
    for (let i = 0; i < 7; i++) await sink.append(`leaf ${i}`);
    const out = join(mkdtempSync(join(tmpdir(), "export-")), "acme");
    // a page size of two exercises the paging; the CLI uses ten thousand
    const paged: typeof fetch = (url, init) => fetch(String(url).replace("limit=10000", "limit=2"), init);
    const r = await exportLog({ logUrl: log.url, tenant: "acme", token: acmeToken, outDir: out, fetch: paged, months: [new Date().toISOString().slice(0, 7)] });
    expect(r.problems).toEqual([]);
    expect(r).toMatchObject({ logId: "acme-eu", treeSize: 7, rootHash: expect.any(String) });
    expect(r.usage).toMatchObject([{ month: new Date().toISOString().slice(0, 7), appends: 7, totalLeaves: 7, liveTokens: 1, plan: "free", quota: 10_000 }]);
    for (const f of ["log.jsonl", "head.json", "keys.json", "checkpoints.json", "usage.json", "audit.json", "policies.json", "export.json"]) expect(existsSync(join(out, f)), f).toBe(true);
    // the tenant's administrative history travels with the export: the tenant's creation and the token minted for it
    const audit = JSON.parse(readFileSync(join(out, "audit.json"), "utf8")) as { action: string; tenantId: string }[];
    expect(audit.map((e) => e.action)).toEqual(["policy.add", "token.add", "tenant.add"]);
    const policies = JSON.parse(readFileSync(join(out, "policies.json"), "utf8")) as { name: string; text: string }[];
    expect(policies).toHaveLength(1);
    expect(policies[0]).toMatchObject({ name: "refunds-v1", text: "permit(principal, action, resource);\n" });
    expect(r.policies).toBe(1);
    expect(audit.every((e) => e.tenantId === "acme")).toBe(true);
    expect(r.audit).toBe(3);
    // the exported log file is a copy the verifier reads: same size, same root as the head it was exported under
    const copy = new MerkleLog(join(out, "log.jsonl"));
    expect(copy.size).toBe(7);
    expect(copy.root()).toBe(r.rootHash);
    expect(JSON.parse(readFileSync(join(out, "head.json"), "utf8")).treeHead.payloadType).toMatch(/treehead/);
    expect(formatExport(r)).toMatch(/RESULT: EXPORT VERIFIED/);
  });

  it("another tenant's token, or none, gets nothing; and the export names what does not add up rather than hiding it", async () => {
    const out = mkdtempSync(join(tmpdir(), "export-bad-"));
    await expect(exportLog({ logUrl: log.url, tenant: "acme", token: otherToken, outDir: out })).rejects.toThrow(/refused the token/);
    expect((await fetch(`${log.url}t/acme/leaves`)).status).toBe(401);
    expect((await fetch(`${log.url}t/acme/usage`)).status).toBe(401);
    // a server that hands back the wrong leaves: the root will not match the signed head
    const lying: typeof fetch = async (url, init) => {
      const res = await fetch(url, init);
      if (!String(url).includes("/leaves")) return res;
      const body = (await res.json()) as { since: number; size: number; leaves: string[] };
      body.leaves = body.leaves.map(() => "00".repeat(32));
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    };
    const r = await exportLog({ logUrl: log.url, tenant: "acme", token: acmeToken, outDir: out, fetch: lying, months: [] });
    expect(r.problems.join("\n")).toMatch(/is not the head's/);
    expect(formatExport(r)).toMatch(/EXPORT DOES NOT ADD UP/);
  });

  it("the leaves route validates its window and caps the page", async () => {
    const h = { authorization: `Bearer ${acmeToken}` };
    expect((await fetch(`${log.url}t/acme/leaves?since=99`, { headers: h })).status).toBe(400);
    expect((await fetch(`${log.url}t/acme/leaves?limit=20000`, { headers: h })).status).toBe(400);
    const page = (await (await fetch(`${log.url}t/acme/leaves?since=5&limit=10`, { headers: h })).json()) as { since: number; size: number; leaves: string[] };
    expect(page).toMatchObject({ since: 5, size: 7 });
    expect(page.leaves).toHaveLength(2);
    expect((await fetch(`${log.url}t/acme/usage?month=2026-13`, { headers: h })).status).toBe(400);
  });
});

// The same leaves and export, on a file-backed log: the reference server as it was, one JSONL file per log.
describe("leaves and export on a file-backed log", () => {
  const fileServers: RunningLog[] = [];
  const leaves = (n: number) => Array.from({ length: n }, (_, i) => `leaf ${i}`);

  async function startFileLog(n: number) {
    const d = mkdtempSync(join(tmpdir(), "export-file-"));
    const file = join(d, "log.jsonl");
    const log = new MerkleLog(file);
    for (const leaf of leaves(n)) log.append(leaf);
    log.close();
    const kp = generateKeyPair();
    const store = dirCheckpoints(mkdtempSync(join(tmpdir(), "export-file-cp-")));
    const resolver = fileResolver(file, { logId: "file-log" });
    const server = await serveLog(resolver, kp, { port: 0, checkpoints: store });
    fileServers.push(server);
    return { dir: d, file, kp, store, resolver, server };
  }

  afterAll(async () => {
    for (const s of fileServers) await s.close();
  });

  it("/leaves on a file log equals the MerkleLog hashes, in pages and in full", async () => {
    const { file, server } = await startFileLog(7);
    const want = new MerkleLog(file).leafHashes(0);
    const got: string[] = [];
    let since = 0;
    while (since < want.length) {
      const page = (await (await fetch(`${server.url}leaves?since=${since}&limit=2`)).json()) as { since: number; size: number; leaves: string[] };
      expect(page).toMatchObject({ since, size: 7 });
      expect(page.leaves).toEqual(want.slice(since, since + 2));
      got.push(...page.leaves);
      since += page.leaves.length;
    }
    expect(got).toEqual(want);
    const full = (await (await fetch(`${server.url}leaves`)).json()) as { leaves: string[] };
    expect(full.leaves).toEqual(want);
    const root = (await (await fetch(`${server.url}root`)).json()) as { treeSize: number; rootHash: string };
    expect(root).toEqual({ treeSize: 7, rootHash: new MerkleLog(file).root() });
  });

  it("out-of-range leaf-hash bounds clamp instead of throwing", async () => {
    const { file } = await startFileLog(7);
    const log = new MerkleLog(file);
    const all = log.leafHashes(0);
    expect(log.leafHashes(-3, 999)).toEqual(all);
    expect(log.leafHashes(2, 5)).toEqual(all.slice(2, 5));
    expect(log.leafHashes(5, 3)).toEqual([]);
    expect(log.leafHashes(99, 200)).toEqual([]);
    const backend = fileBackend(file);
    expect(await backend.leafHashes(-1, 999)).toEqual(all);
    expect(await backend.leafHashes(6, 99)).toEqual(all.slice(6));
    expect(await backend.leafHashes(7, 9)).toEqual([]);
  });

  it("an export of a file log rebuilds the same log, names what the file server does not keep, and counts a good checkpoint", async () => {
    const ctx = await startFileLog(7);
    await new CheckpointPublisher(ctx.resolver, localSigner(ctx.kp), ctx.store, 60_000).publishOnce();
    const out = join(mkdtempSync(join(tmpdir(), "export-file-")), "out");
    const r = await exportLog({ logUrl: ctx.server.url, token: "any-token", outDir: out, months: [] });
    expect(r).toMatchObject({ logId: "file-log", treeSize: 7, checkpoints: 1 });
    expect(r.rootHash).toBe(new MerkleLog(ctx.file).root());
    const copy = new MerkleLog(join(out, "log.jsonl"));
    expect(copy.size).toBe(7);
    expect(copy.root()).toBe(r.rootHash);
    expect(copy.leafHashes(0)).toEqual(new MerkleLog(ctx.file).leafHashes(0));
    // a file log keeps no usage, audit trail, or policies: the export says so rather than hiding it
    expect(r.problems).toContain("audit trail: 404 from /audit");
    expect(r.problems).toContain("policies: 404 from /policies");
    expect(formatExport(r)).toMatch(/EXPORT DOES NOT ADD UP/);
  });

  it("with no months given, the export asks for the current month and the previous one", async () => {
    const ctx = await startFileLog(3);
    const out = join(mkdtempSync(join(tmpdir(), "export-file-")), "out");
    const r = await exportLog({ logUrl: ctx.server.url, token: "any-token", outDir: out });
    const now = new Date();
    const thisMonth = now.toISOString().slice(0, 7);
    const prevMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)).toISOString().slice(0, 7);
    expect(r.usage).toEqual([]);
    expect(r.problems.join("\n")).toContain(`usage for ${thisMonth}: 404 from /usage`);
    expect(r.problems.join("\n")).toContain(`usage for ${prevMonth}: 404 from /usage`);
  });

  it("a failing usage, audit, or policies endpoint is reported as a problem, not hidden", async () => {
    const ctx = await startFileLog(5);
    const failing = (part: string): typeof fetch => async (url, init) => (String(url).includes(part) ? new Response("boom", { status: 500 }) : fetch(url, init));
    const month = new Date().toISOString().slice(0, 7);
    const outU = join(mkdtempSync(join(tmpdir(), "export-file-")), "u");
    const outA = join(mkdtempSync(join(tmpdir(), "export-file-")), "a");
    const outP = join(mkdtempSync(join(tmpdir(), "export-file-")), "p");
    const ru = await exportLog({ logUrl: ctx.server.url, token: "t", outDir: outU, fetch: failing("/usage"), months: [month] });
    expect(ru.problems).toContain(`usage for ${month}: 500 from /usage`);
    const ra = await exportLog({ logUrl: ctx.server.url, token: "t", outDir: outA, fetch: failing("/audit"), months: [] });
    expect(ra.problems).toContain("audit trail: 500 from /audit");
    const rp = await exportLog({ logUrl: ctx.server.url, token: "t", outDir: outP, fetch: failing("/policies"), months: [] });
    expect(rp.problems).toContain("policies: 500 from /policies");
    expect(existsSync(join(outU, "log.jsonl"))).toBe(true);
  });

  it("a 401, a non-OK answer, or an empty page from /leaves rejects instead of exporting", async () => {
    const ctx = await startFileLog(7);
    const out = join(mkdtempSync(join(tmpdir(), "export-file-")), "out");
    const base = { logUrl: ctx.server.url, token: "t", outDir: out, months: [] as string[] };
    const refused: typeof fetch = async (url, init) => (String(url).includes("/leaves") ? new Response("no", { status: 401 }) : fetch(url, init));
    await expect(exportLog({ ...base, fetch: refused })).rejects.toThrow(/refused the token for \/leaves/);
    const broken: typeof fetch = async (url, init) => (String(url).includes("/leaves") ? new Response("boom", { status: 500 }) : fetch(url, init));
    await expect(exportLog({ ...base, fetch: broken })).rejects.toThrow(/500 from \/leaves/);
    const empty: typeof fetch = async (url, init) => {
      if (!String(url).includes("/leaves")) return fetch(url, init);
      return new Response(JSON.stringify({ since: 0, size: 7, leaves: [] }), { status: 200, headers: { "content-type": "application/json" } });
    };
    await expect(exportLog({ ...base, fetch: empty })).rejects.toThrow(/returned no leaves past 0 of 7/);
  });

  it("a checkpoint that does not verify, and one whose root the leaves belie, are both reported", async () => {
    const ctx = await startFileLog(7);
    const log = new MerkleLog(ctx.file);
    await new CheckpointPublisher(ctx.resolver, localSigner(ctx.kp), ctx.store, 60_000).publishOnce();
    const other = generateKeyPair();
    await ctx.store.save({ tenant: "default", logId: "file-log", treeSize: 3, rootHash: log.root(3), signedAt: new Date().toISOString(), envelope: dsseSign(TREEHEAD_TYPE, { treeSize: 3, rootHash: log.root(3), timestamp: new Date().toISOString(), log: "file-log" }, other) });
    await ctx.store.save({ tenant: "default", logId: "file-log", treeSize: 5, rootHash: "00".repeat(32), signedAt: new Date().toISOString(), envelope: dsseSign(TREEHEAD_TYPE, { treeSize: 5, rootHash: "00".repeat(32), timestamp: new Date().toISOString(), log: "file-log" }, ctx.kp) });
    const out = join(mkdtempSync(join(tmpdir(), "export-file-")), "out");
    const r = await exportLog({ logUrl: ctx.server.url, token: "t", outDir: out, months: [] });
    expect(r.checkpoints).toBe(3);
    expect(r.problems.join("\n")).toMatch(/checkpoint at 3 does not verify/);
    expect(r.problems.join("\n")).toMatch(/checkpoint at 5 has root 000000000000, the leaves give/);
  });
});
