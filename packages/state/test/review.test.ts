// The review page exists for the person who will not open a terminal. It must list every receipt with a verdict,
// show the ten answers and the report on each, serve the receipt itself, and write the same as files for a case
// file. Receipts come from a real gateway in front of the memory server.
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createDelegation, createGateway, generateKeyPair, loadPublicKey, publicKeyFromPem, RECEIPT_META_KEY, writeKeyPair, loadConfig, type ReceiptBundle } from "@agent-custody/receipts";
import { decodeStatement } from "../src/explain.ts";
import { Ledger } from "../src/ledger.ts";
import { listReceipts, serveReview, writeReview } from "../src/review.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");

describe("the review page", () => {
  it("lists every receipt with its verdict, shows the ten answers and the report per receipt, serves the bundle, and writes the same as files", async () => {
    const dir = mkdtempSync(join(tmpdir(), "review-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action == Action::"memory.write", resource) when { context.args.space == "org" };\npermit(principal, action == Action::"memory.read", resource);\n`);
    const ledgerFile = join(dir, "ledger.jsonl");
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({ identity: { keyFile: "keys/gateway.key" }, upstream: { command: process.execPath, args: [cli, "serve", "--ledger", ledgerFile] }, grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl" }));
    const gw = await createGateway(loadConfig(join(dir, "gateway.json")));
    const w = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "enterprise", space: "org" } });
    const writeId = String(w._meta?.[RECEIPT_META_KEY]);
    await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:42" } });
    const denied = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:42", predicate: "note", value: "x", space: "user:me" } });
    expect(denied.isError).toBe(true);
    await gw.close();
    // a file that is not a receipt does not stop the index, and the index says that it could not read it
    writeFileSync(join(dir, "receipts", "notes.json"), "{}");

    const keys = { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))] };
    const ledger = new Ledger(ledgerFile);
    const o = { receiptsDir: join(dir, "receipts"), ledger, keys, title: "Support agents, September" };
    const rows = listReceipts(o);
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r.verified === true)).toBe(true);
    expect(rows.map((r) => r.status).sort()).toEqual(["denied", "executed", "executed"]);
    expect(rows[0]!.timestamp >= rows[2]!.timestamp).toBe(true);

    const running = await serveReview(o, { port: 0 });
    try {
      const index = await (await fetch(running.url)).text();
      expect(index).toContain("Support agents, September");
      expect(index).toContain("3 receipt(s)");
      expect(index).toContain("1 file(s) could not be read");
      expect(index).toContain(`href="/r/${writeId}"`);
      expect((index.match(/>verified</g) ?? []).length).toBe(3);
      const pageRes = await fetch(new URL(`r/${writeId}`, running.url));
      expect(pageRes.headers.get("content-security-policy")).toMatch(/default-src 'none'/);
      const html = await pageRes.text();
      expect(html).toContain("<dt>WHO</dt>");
      expect(html).toContain("support-agent (attested, named in a signed grant)");
      expect(html).toContain("<dt>DID ANYTHING DEPEND ON THIS</dt>");
      expect(html).toContain("RESULT: VERIFIED");
      expect(html).toContain(`href="/r/${writeId}.json"`);
      const raw = (await (await fetch(new URL(`r/${writeId}.json`, running.url))).json()) as { envelope: unknown; inclusion: unknown };
      expect(raw.envelope).toBeDefined();
      expect(raw.inclusion).toBeDefined();
      expect((await fetch(new URL("r/not-a-receipt-id", running.url))).status).toBe(404);
      expect((await fetch(new URL(`r/${"0".repeat(8)}-0000-0000-0000-000000000000`, running.url))).status).toBe(404);
    } finally {
      await running.close();
    }

    // without keys the page says so rather than pretending
    const bare = await serveReview({ receiptsDir: join(dir, "receipts") }, { port: 0 });
    try {
      const index = await (await fetch(bare.url)).text();
      expect(index).toContain("not checked");
      expect(index).toContain("no ledger");
    } finally {
      await bare.close();
    }

    // static files, and the CLI writing them
    const out = join(dir, "site");
    expect(await writeReview(o, out)).toEqual({ receipts: 3 });
    expect(existsSync(join(out, "index.html"))).toBe(true);
    expect(readdirSync(join(out, "r")).filter((f) => f.endsWith(".html") && !f.endsWith(".case.html"))).toHaveLength(3);
    expect(readFileSync(join(out, "index.html"), "utf8")).toContain(`href="r/${writeId}.html"`);
    expect(readFileSync(join(out, "r", `${writeId}.html`), "utf8")).toContain("<dt>WHAT IT DID</dt>");
    await ledger.close();
    const cliOut = join(dir, "site2");
    const run = await new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn(process.execPath, [cli, "review", "--receipts", join(dir, "receipts"), "--ledger", ledgerFile, "--issuer-key", join(dir, "keys", "gateway.pub"), "--principal-key", join(dir, "keys", "principal.pub"), "--out", cliOut], { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
      child.on("close", (status) => resolve({ status, stdout, stderr }));
    });
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toMatch(/wrote 3 receipt page\(s\)/);
  });
});

describe("a record that was changed after it was issued", () => {
  const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "../../receipts/vectors/receipts.json"), "utf8"));
  const vector = vectors.cases.find((c: { name: string }) => c.name === "gateway-precommit-executed");
  const key = (name: string) => publicKeyFromPem(vectors.keys[name].publicKeyPem);
  const keys = { issuerKeys: vector.issuerKeys.map(key), principalKeys: vector.principalKeys.map(key) };

  it("stays in the index and the export as NOT VERIFIED, and the header counts the files it cannot read", async () => {
    const bundle = structuredClone(vector.bundle) as ReceiptBundle;
    const statement = decodeStatement(bundle);
    const id = statement.predicate.receiptId;
    const dir = mkdtempSync(join(tmpdir(), "review-tamper-"));
    const o = { receiptsDir: dir, keys };
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(bundle));
    expect(listReceipts(o).map((r) => [r.receiptId, r.verified])).toEqual([[id, true]]);

    // Edit the id inside the signed payload. The file keeps its name.
    statement.predicate.receiptId = "00000000";
    bundle.envelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(bundle));
    writeFileSync(join(dir, "notes.json"), "{}");
    writeFileSync(join(dir, "broken.json"), "not json");
    // A copy under a name that is not an id has a row, and no link.
    writeFileSync(join(dir, "copy of receipt.json"), JSON.stringify(bundle));

    for (const withKeys of [o, { receiptsDir: dir }]) {
      const rows = listReceipts(withKeys);
      expect(rows).toHaveLength(2);
      expect(rows.map((r) => r.file).sort()).toEqual([id, "copy of receipt"]);
      for (const r of rows) {
        expect(r.verified).toBe(false);
        expect(r.problem).toBe("file name does not match receipt id");
      }
    }

    const running = await serveReview(o, { port: 0 });
    try {
      const index = await (await fetch(running.url)).text();
      expect(index).toContain("2 receipt(s)");
      expect(index).toContain("2 file(s) could not be read");
      expect(index).toContain(`<p id="no-results" hidden>`);
      expect((index.match(/NOT VERIFIED/g) ?? []).length).toBe(2);
      expect(index).toContain("file name does not match receipt id");
      expect(index).toContain(`href="/r/${id}"`);
      expect(index).not.toContain("copy%20of");
      const page = await (await fetch(new URL(`r/${id}`, running.url))).text();
      expect(page).toContain("RESULT: NOT VERIFIED");
      expect(page).toContain("FAIL  file name matches receipt id");
    } finally {
      await running.close();
    }
    // The page also fails without keys, because the name check needs none.
    const bare = await serveReview({ receiptsDir: dir }, { port: 0 });
    try {
      expect(await (await fetch(new URL(`r/${id}`, bare.url))).text()).toContain("RESULT: NOT VERIFIED");
    } finally {
      await bare.close();
    }

    const out = join(dir, "site");
    expect(await writeReview(o, out)).toEqual({ receipts: 2 });
    const index = readFileSync(join(out, "index.html"), "utf8");
    expect(index).toContain("2 file(s) could not be read");
    expect(index).toContain("NOT VERIFIED");
    expect(readFileSync(join(out, "r", `${id}.html`), "utf8")).toContain("RESULT: NOT VERIFIED");
    expect(JSON.parse(readFileSync(join(out, "r", `${id}.case.json`), "utf8")).verification.ok).toBe(false);
    expect(readdirSync(join(out, "r")).filter((f) => f.endsWith(".html") && !f.endsWith(".case.html"))).toEqual([`${id}.html`]);
  });

  it("does not abort the export or answer 500 for a record that lacks a part that the pages read", async () => {
    const dir = mkdtempSync(join(tmpdir(), "review-malformed-"));
    const save = (name: string, change: (predicate: Record<string, any>) => void, unsigned?: (bundle: Record<string, any>) => void) => {
      const bundle = structuredClone(vectors.cases.find((c: { name: string }) => c.name === name).bundle) as ReceiptBundle;
      const statement = decodeStatement(bundle);
      change(statement.predicate as unknown as Record<string, any>);
      bundle.envelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
      unsigned?.(bundle as unknown as Record<string, any>);
      writeFileSync(join(dir, `${statement.predicate.receiptId}.json`), JSON.stringify(bundle));
      return statement.predicate.receiptId as string;
    };
    const good = save("gateway-precommit-executed", () => {});
    const noReasons = save("gateway-executed", (p) => { delete p.policy.reasons; });
    const wrongType = save("gateway-executed-proto-key", (p) => { p.timestamp = { not: "a time" }; });
    // Parts that the spec requires and the pages read: the policy digest, an authorization's proof, an attested principal's key id.
    const noDigest = save("gateway-denied", (p) => { delete p.policy.policyDigest; });
    const noInclusion = save("gateway-precommit-spliced", (p) => { delete p.authorization.inclusion; });
    const noKeyid = save("gateway-executed-private", (p) => { delete p.principal.keyid; });
    // The tree head and the proof sit beside the signed payload, so a bundle can lose them and keep a valid predicate.
    const noTreeHead = save("gateway-executed", (p) => { p.receiptId = randomUUID(); }, (b) => { delete b.treeHead; });
    const noProof = save("gateway-denied", (p) => { p.receiptId = randomUUID(); }, (b) => { delete b.inclusion; });
    const damaged = [noReasons, wrongType, noDigest, noInclusion, noKeyid, noTreeHead, noProof];
    // A timestamp that is a string but not a date breaks nothing that a page reads, so the record is not damaged.
    const oddTime = save("gateway-private-clear-result-upstream-attested", (p) => { p.timestamp = "not a date"; });
    const o = { receiptsDir: dir, keys };

    const out = join(dir, "site");
    expect(await writeReview(o, out)).toEqual({ receipts: 9 });
    expect(readFileSync(join(out, "r", `${good}.html`), "utf8")).toContain("RESULT: VERIFIED");
    const odd = readFileSync(join(out, "r", `${oddTime}.html`), "utf8");
    expect(odd).toContain("RESULT: NOT VERIFIED");
    expect(odd).not.toContain("the record has the parts of a receipt");
    expect(existsSync(join(out, "r", `${oddTime}.case.json`))).toBe(true);
    for (const id of damaged) expect(existsSync(join(out, "r", `${id}.case.json`))).toBe(false);
    for (const id of damaged) {
      const page = readFileSync(join(out, "r", `${id}.html`), "utf8");
      expect(page).toContain("RESULT: NOT VERIFIED");
      expect(page).toContain("FAIL  the record has the parts of a receipt");
      expect(readFileSync(join(out, "r", `${id}.json`), "utf8")).toContain("payload");
    }

    const running = await serveReview(o, { port: 0 });
    try {
      for (const id of damaged) {
        const res = await fetch(new URL(`r/${id}`, running.url));
        expect(res.status).toBe(200);
        expect(await res.text()).toContain("RESULT: NOT VERIFIED");
      }
      expect((await fetch(new URL(`r/${good}`, running.url))).status).toBe(200);
    } finally {
      await running.close();
    }
  });

  it.each([
    ["an outage", new Error("connect ECONNREFUSED 127.0.0.1:5432")],
    ["a TypeError from the adapter", new TypeError("Cannot read properties of undefined (reading 'rows')")],
  ])("keeps %s in the ledger an error: the export fails and the live page answers 500, never a NOT VERIFIED page", async (_name, failure) => {
    const dir = mkdtempSync(join(tmpdir(), "review-outage-"));
    const bundle = structuredClone(vector.bundle) as ReceiptBundle;
    const id = decodeStatement(bundle).predicate.receiptId;
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(bundle));
    const down = () => Promise.reject(failure);
    const ledger = { get: down, facts: down, history: down } as unknown as Ledger;
    const o = { receiptsDir: dir, keys, ledger };

    await expect(writeReview(o, join(dir, "site"))).rejects.toThrow(failure.message);
    expect(existsSync(join(dir, "site", "r", `${id}.html`))).toBe(false);
    const running = await serveReview(o, { port: 0 });
    try {
      const res = await fetch(new URL(`r/${id}`, running.url));
      expect(res.status).toBe(500);
      expect(await res.text()).toContain(failure.message);
    } finally {
      await running.close();
    }
  });

  it("keeps a receipt with a value too large to search in the list, marked, when an id filter would drop it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "review-partial-"));
    const bundle = structuredClone(vector.bundle) as ReceiptBundle;
    const statement = decodeStatement(bundle);
    const id = statement.predicate.receiptId;
    // A list larger than 64 KiB held as text, as an MCP result can be. The id sits at the end.
    const text = JSON.stringify({ data: [...Array.from({ length: 4000 }, (_, i) => ({ note: `padding ${i}` })), { refund_id: "re_far_away" }] });
    Object.assign(statement.predicate.execution, { result: { content: [{ type: "text", text }] } });
    bundle.envelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(bundle));
    const o = { receiptsDir: dir };

    const rows = listReceipts(o, { transaction: "re_far_away" });
    expect(rows.map((r) => [r.file, r.truncated])).toEqual([[id, true]]);
    expect(listReceipts(o, { transaction: "re_far_away", agent: "nobody" })).toEqual([]);
    const running = await serveReview(o, { port: 0 });
    try {
      const index = await (await fetch(new URL("?transaction=re_far_away", running.url))).text();
      expect(index).toContain("1 receipt(s)");
      expect(index).toContain("partially indexed");
    } finally {
      await running.close();
    }
  });
});
