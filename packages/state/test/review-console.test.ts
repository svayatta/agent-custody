// The reviewer's path: find a disputed refund, read the gateway's checks and its principal's grant, hand over
// the case, and verify it after the receipts directory has gone away. No endpoint outside this fixture is used.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runInNewContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { createDelegation, createGateway, generateKeyPair, loadConfig, loadPublicKey, writeKeyPair, type ReceiptBundle } from "@agent-custody/receipts";
import { listReceipts, serveReview, writeReview } from "../src/review.ts";
import { verifyCaseFile, type CaseFile } from "../src/case-file.ts";

const cli = resolve(import.meta.dirname, "../src/cli.ts");

describe("the review console", () => {
  it("finds a refund by exact transaction, customer, agent and time; exports a case for an offline handoff", async () => {
    const dir = mkdtempSync(join(tmpdir(), "review-console-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principal = generateKeyPair();
    writeKeyPair(principal, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principal, {
      version: "0.1", principal: "support-lead", agent: "refund-agent", scopes: ["stripe.refund", "customer.lookup"],
      issuedAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString(),
    })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= 100000 && context.facts.customer.verified };\n`);
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({
      identity: { keyFile: "keys/gateway.key" },
      upstream: { command: process.execPath, args: [resolve(import.meta.dirname, "../../receipts/scripts/fake-stripe.ts")] },
      grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar",
      facts: [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.refund"] }],
      precommit: ["stripe.refund"], receiptsDir: "receipts", logFile: "log.jsonl",
    }));
    const gw = await createGateway(loadConfig(join(dir, "gateway.json")));
    let refundId: string;
    let receiptId: string;
    try {
      const refund = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
      refundId = JSON.parse((refund.content[0] as { text: string }).text).refund_id;
      receiptId = String(refund._meta?.["agent-custody/receipt"]);
      await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 500000 } });
    } finally { await gw.close(); }
    const keys = { issuerKeys: [loadPublicKey(join(dir, "keys/gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys/principal.pub"))] };
    const o = { receiptsDir: join(dir, "receipts"), keys, title: 'Refunds <script>alert("x")</script>' };
    expect(listReceipts(o)).toHaveLength(2); // the separately written authorization is not a second receipt
    expect(listReceipts(o, { transaction: refundId! }).map((r) => r.receiptId)).toEqual([receiptId!]);
    expect(listReceipts(o, { customer: "cust_123", agent: "refund-agent" })).toHaveLength(2);
    expect(listReceipts(o, { customer: "cust_12" })).toHaveLength(0);
    const row = listReceipts(o, { transaction: refundId! })[0]!;
    expect(listReceipts(o, { from: row.timestamp, to: row.timestamp, transaction: refundId! })).toHaveLength(1);

    const running = await serveReview(o, { port: 0 });
    let file: CaseFile;
    try {
      const query = new URL(running.url);
      query.search = new URLSearchParams({ transaction: refundId!, customer: "cust_123", agent: "refund-agent" }).toString();
      const index = await (await fetch(query)).text();
      expect(index).toContain('name="transaction"');
      expect(index).toContain("1 receipt(s)");
      expect(index).toContain(`href="/r/${receiptId!}"`);
      expect(index).toContain("&lt;script&gt;");
      expect(index).not.toContain('<script>alert("x")</script>');
      query.search = new URLSearchParams({ transaction: refundId!, customer: "", agent: "", from: "", to: "" }).toString();
      const submitted = await fetch(query);
      expect(submitted.status).toBe(200);
      expect(await submitted.text()).toContain("1 receipt(s)");
      expect(await (await fetch(new URL("?customer=missing", running.url))).text()).toContain("No receipts match");
      expect((await fetch(new URL("?from=not-a-date", running.url))).status).toBe(400);
      expect((await fetch(new URL("?from=2026-10-15T00:00:00Z&to=2026-10-14T00:00:00Z", running.url))).status).toBe(400);
      const html = await (await fetch(new URL(`r/${receiptId!}`, running.url))).text();
      expect(html).toContain("support-lead, grant signed by key");
      expect(html).toContain("customer.lookup");
      expect(html).toContain("authorization committed as leaf");
      expect(html).toContain("RESULT: VERIFIED");
      expect(html).toContain(`href="/r/${receiptId!}.case.html"`);
      const download = await fetch(new URL(`r/${receiptId!}.case.html`, running.url));
      expect(download.headers.get("content-disposition")).toContain(`${receiptId!}.case.html`);
      const offlineHtml = await download.text();
      expect(offlineHtml).toContain("default-src 'none'");
      expect(offlineHtml).toContain("crypto");
      for (const script of offlineHtml.matchAll(/<script(?: [^>]*)?>([\s\S]*?)<\/script>/g)) {
        if (script[0].includes('type="application/json"')) continue;
        expect(() => new Script(script[1]!)).not.toThrow();
      }
      file = await (await fetch(new URL(`r/${receiptId!}.case.json`, running.url))).json() as CaseFile;
      expect(verifyCaseFile(file, keys).ok).toBe(true);
      const raw = await (await fetch(new URL(`r/${receiptId!}.json`, running.url))).json() as ReceiptBundle;
      expect(file.pack.receipt).toEqual(raw);
    } finally { await running.close(); }

    const exported = join(dir, "review");
    expect(await writeReview({ ...o, search: { transaction: refundId! } }, exported)).toEqual({ receipts: 1 });
    const indexHtml = readFileSync(join(exported, "index.html"), "utf8");
    expect(indexHtml).toContain(`href="r/${receiptId!}.html"`);
    const script = [...indexHtml.matchAll(/<script>([\s\S]*?)<\/script>/g)][0]![1]!;
    // Run the actual static filter in a browser-shaped DOM, including exact IDs and no-match feedback.
    const fields = Object.fromEntries(["transaction", "customer", "agent", "from", "to"].map((name) => [name, { value: "" }]));
    const handlers: Record<string, (e: { preventDefault(): void }) => void> = {};
    const domRow = { dataset: { transactions: JSON.stringify([refundId!]), customers: '["cust_123"]', agent: "refund-agent", timestamp: row.timestamp }, hidden: false };
    const count = { textContent: "" }, empty = { hidden: true }, error = { textContent: "" };
    const form = { elements: { namedItem: (name: string) => fields[name] }, addEventListener: (name: string, fn: typeof handlers[string]) => { handlers[name] = fn; } };
    runInNewContext(script, { document: { getElementById: (id: string) => ({ "receipt-search": form, "receipt-count": count, "no-results": empty, "search-error": error })[id], querySelectorAll: () => [domRow] } });
    fields.transaction!.value = refundId!;
    handlers.submit!({ preventDefault() {} });
    expect(domRow.hidden).toBe(false);
    fields.customer!.value = "cust_12";
    handlers.submit!({ preventDefault() {} });
    expect(domRow.hidden).toBe(true);
    expect(empty.hidden).toBe(false);
    expect(count.textContent).toBe("0 receipt(s)");
    fields.from!.value = "2026-02-30T00:00:00Z";
    handlers.submit!({ preventDefault() {} });
    expect(error.textContent).toContain("ISO 8601 date-time");

    // Exporting a single case and a filtered static console are also available without running a server.
    for (const extension of ["html", "json"]) {
      const destination = join(dir, `single.case.${extension}`);
      const made = spawnSync(process.execPath, [cli, "review", "--receipts", o.receiptsDir, "--case", receiptId!, "--out", destination, "--issuer-key", join(dir, "keys/gateway.pub"), "--principal-key", join(dir, "keys/principal.pub")], { encoding: "utf8", timeout: 60_000 });
      expect(made.status, made.stderr).toBe(0);
      const artifact = readFileSync(destination, "utf8");
      if (extension === "json") expect(verifyCaseFile(JSON.parse(artifact), keys).ok).toBe(true);
      else {
        expect(artifact).toContain("Fresh browser verification");
        // The page cannot check itself. The command line reads the HTML file and applies the same checks as for the JSON.
        const verifyArgs = ["review", "--verify-case", destination, "--issuer-key", join(dir, "keys/gateway.pub"), "--principal-key", join(dir, "keys/principal.pub")];
        const fromHtml = spawnSync(process.execPath, [cli, ...verifyArgs], { encoding: "utf8", timeout: 60_000 });
        expect(fromHtml.status, fromHtml.stdout + fromHtml.stderr).toBe(0);
        expect(fromHtml.stdout).toContain("RESULT: VERIFIED");
        const forged = join(dir, "forged.case.html");
        writeFileSync(forged, artifact.replaceAll("support-lead", "cfo_alice"));
        const forgedRun = spawnSync(process.execPath, [cli, ...verifyArgs.map((arg) => (arg === destination ? forged : arg))], { encoding: "utf8", timeout: 60_000 });
        expect(forgedRun.status, forgedRun.stdout + forgedRun.stderr).toBe(1);
        expect(forgedRun.stdout).toContain("FAIL  ten answers match the signed receipt");
        // Only the visible answer changes: the data, the script, and the CSP hash are the genuine ones.
        const visible = artifact.replace(/(WHO AUTHORIZED IT\s+)[^\n<]*/, "$1cfo_alice (manual sign-off)");
        expect(visible).not.toBe(artifact);
        // The genuine data hides in a comment, and the real element holds forged data.
        const data = artifact.match(/<script id="case-data" type="application\/json">[\s\S]*?<\/script>/)![0];
        const smuggled = artifact.replace("<body>", `<body><!--${data}-->`).replace(/(<script id="case-data" type="application\/json">)([\s\S]*?)(<\/script><script>)/, (_all, open: string, json: string, close: string) => `${open}${json.replace("support-lead", "cfo_alice")}${close}`);
        // The file name declares the format. Genuine case JSON with HTML in a string field, saved as .html, is not a page that renders its data. A page saved as .json is not JSON.
        const hybrid = JSON.stringify({ note: "<style>body{font-size:0}</style><h1>RESULT: VERIFIED</h1>", ...file! });
        for (const [name, content] of [["hybrid.case.html", hybrid], ["page.case.json", artifact]] as const) {
          const declared = join(dir, name);
          writeFileSync(declared, content);
          const run = spawnSync(process.execPath, [cli, ...verifyArgs.map((arg) => (arg === destination ? declared : arg))], { encoding: "utf8", timeout: 60_000 });
          expect(run.status, name + run.stdout + run.stderr).toBe(1);
          expect(run.stdout, name).not.toContain("RESULT: VERIFIED");
        }
        for (const [name, page] of [["visible", visible], ["smuggled", smuggled]] as const) {
          const tampered = join(dir, `${name}.case.html`);
          writeFileSync(tampered, page);
          const run = spawnSync(process.execPath, [cli, ...verifyArgs.map((arg) => (arg === destination ? tampered : arg))], { encoding: "utf8", timeout: 60_000 });
          expect(run.status, name + run.stdout + run.stderr).toBe(1);
          expect(run.stdout, name).toContain("FAIL  page is exactly what its case data renders");
          expect(run.stdout, name).toContain("THE TEN ANSWERS, rebuilt from the signed receipt");
        }
      }
    }
    const selected = spawnSync(process.execPath, [cli, "review", "--receipts", o.receiptsDir, "--transaction", refundId!, "--out", join(dir, "filtered-cli")], { encoding: "utf8", timeout: 60_000 });
    expect(selected.status, selected.stderr).toBe(0);
    expect(selected.stdout).toContain("wrote 1 receipt page(s)");

    const caseJson = join(exported, "r", `${receiptId!}.case.json`);
    // Neither re-verification nor a new recipient needs the original receipt directory, log, ledger, or server.
    renameSync(o.receiptsDir, join(dir, "receipts-unavailable"));
    const checked = spawnSync(process.execPath, [cli, "review", "--verify-case", caseJson, "--issuer-key", join(dir, "keys/gateway.pub"), "--principal-key", join(dir, "keys/principal.pub")], { encoding: "utf8", timeout: 60_000 });
    expect(checked.status, checked.stdout + checked.stderr).toBe(0);
    expect(checked.stdout).toContain("RESULT: VERIFIED");
    file!.pack.receipt.envelope.payload += "tampered";
    writeFileSync(join(dir, "tampered.json"), JSON.stringify(file!));
    const bad = spawnSync(process.execPath, [cli, "review", "--verify-case", join(dir, "tampered.json"), "--json"], { encoding: "utf8", timeout: 60_000 });
    expect(bad.status, bad.stderr).toBe(1);
    expect(JSON.parse(bad.stdout).ok).toBe(false);
  });
});
