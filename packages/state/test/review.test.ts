// The review page exists for the person who will not open a terminal. It must list every receipt with a verdict,
// show the ten answers and the report on each, serve the receipt itself, and write the same as files for a case
// file. Receipts come from a real gateway in front of the memory server.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createDelegation, createGateway, generateKeyPair, loadPublicKey, RECEIPT_META_KEY, writeKeyPair, loadConfig } from "@agent-custody/receipts";
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
    // a file that is not a receipt is skipped, not fatal
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
