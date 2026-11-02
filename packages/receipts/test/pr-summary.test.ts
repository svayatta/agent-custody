// The table that the GitHub Action posts. The input is the signed vectors, so the test needs no gateway and no network.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { publicKeyFromPem } from "../src/crypto.ts";
import { formatSummaryMarkdown, receiptFiles, summarizeReceipts, SUMMARY_MARKER } from "../src/pr-summary.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";

const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "..", "vectors", "receipts.json"), "utf8"));
const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString("utf8")) as ReceiptStatement;
const vector = (name: string): ReceiptBundle => vectors.cases.find((c: { name: string }) => c.name === name).bundle;

/** A directory of bundles named by receipt id, as the gateway writes them, and the issuer and principal key files. */
function setup(bundles: ReceiptBundle[]) {
  const dir = mkdtempSync(join(tmpdir(), "pr-summary-"));
  const receipts = join(dir, "receipts");
  mkdirSync(receipts);
  for (const b of bundles) writeFileSync(join(receipts, `${decode(b).predicate.receiptId}.json`), JSON.stringify(b));
  writeFileSync(join(dir, "issuer.pub"), vectors.keys.gateway.publicKeyPem);
  writeFileSync(join(dir, "principal.pub"), vectors.keys.principal.publicKeyPem);
  return { dir, receipts };
}
const keys = { issuerKeys: [publicKeyFromPem(vectors.keys.gateway.publicKeyPem)], principalKeys: [publicKeyFromPem(vectors.keys.principal.publicKeyPem)] };
const good = () => [vector("gateway-executed-no-log-copy"), vector("gateway-denied")];

/** One character of the signed payload changes, so the signature no longer matches. */
function oneByteChanged(b: ReceiptBundle): ReceiptBundle {
  const copy = structuredClone(b);
  const payload = copy.envelope.payload;
  copy.envelope.payload = payload.slice(0, 40) + (payload[40] === "A" ? "B" : "A") + payload.slice(41);
  return copy;
}

describe("the pull request table", () => {
  it("lists a good bundle as verified with its tool and status", () => {
    const { receipts } = setup(good());
    const summary = summarizeReceipts(receiptFiles(receipts), keys);
    expect(summary.ok).toBe(true);
    expect(summary.rows.map((r) => [r.tool, r.status, r.result]).sort()).toEqual(
      good().map((b) => [decode(b).predicate.tool.name, decode(b).predicate.execution.status, "verified"]).sort(),
    );
    const md = formatSummaryMarkdown(summary);
    expect(md.startsWith(`${SUMMARY_MARKER}\n`)).toBe(true);
    expect(md).toContain("**Verified.** All 2 receipts verify.");
    expect(md).toContain("| Receipt | Tool | Status | Result |");
    expect(md).toContain("| denied | verified |");
  });

  it("names the failed check when one byte of a receipt changes, and lists that receipt first", () => {
    const [executed, denied] = good() as [ReceiptBundle, ReceiptBundle];
    const { receipts } = setup([executed]);
    // the changed bundle keeps the file name of the original receipt
    writeFileSync(join(receipts, `${decode(denied).predicate.receiptId}.json`), JSON.stringify(oneByteChanged(denied)));
    const summary = summarizeReceipts(receiptFiles(receipts), keys);
    expect(summary.ok).toBe(false);
    const bad = summary.rows.filter((r) => !r.ok);
    expect(bad).toHaveLength(1);
    expect(bad[0]!.receiptId).toBe(decode(denied).predicate.receiptId);
    expect(bad[0]!.result).toContain("receipt signature (issuer key)");
    const md = formatSummaryMarkdown(summary);
    expect(md).toContain("**Not verified.** 1 of 2 receipts do not verify.");
    expect(md).toContain("`receipt signature (issuer key)`");
    expect(md.indexOf(decode(denied).predicate.receiptId)).toBeLessThan(md.indexOf(decode(executed).predicate.receiptId));
  });

  it("fails a valid receipt under the file name of another receipt", () => {
    const [executed, denied] = good() as [ReceiptBundle, ReceiptBundle];
    const { receipts } = setup([executed]);
    writeFileSync(join(receipts, `${decode(denied).predicate.receiptId}.json`), JSON.stringify(executed));
    const summary = summarizeReceipts(receiptFiles(receipts), keys);
    expect(summary.ok).toBe(false);
    expect(summary.rows.filter((r) => !r.ok).map((r) => r.result)).toEqual(["file name matches receipt id"]);
  });

  it("fails when the directory holds no receipt, or does not exist", () => {
    const { dir, receipts } = setup([]);
    writeFileSync(join(receipts, `${"0".repeat(8)}-0000-0000-0000-000000000000.authorization.json`), "{}");
    for (const path of [receipts, join(dir, "missing")]) {
      const summary = summarizeReceipts(receiptFiles(path), keys);
      expect(summary.ok).toBe(false);
      expect(formatSummaryMarkdown(summary)).toContain("**Not verified.** No receipt bundles found.");
    }
  });

  it("keeps text from a receipt out of the table markup", () => {
    const { receipts } = setup([]);
    writeFileSync(join(receipts, "evil|<img>.json"), "not json at all `x` |");
    const md = formatSummaryMarkdown(summarizeReceipts(receiptFiles(receipts), keys));
    expect(md).not.toMatch(/<img>/);
    const row = md.split("\n").find((l) => l.includes("evil"))!;
    expect(row.split("|").length).toBe(6);
  });
});

describe("verify --markdown", () => {
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, "verify", "--markdown", ...args], { encoding: "utf8", timeout: 30_000 });

  it("prints the table and exits 0 for a good directory", () => {
    const { dir, receipts } = setup(good());
    const r = run(receipts, "--issuer-key", join(dir, "issuer.pub"), "--principal-key", join(dir, "principal.pub"));
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain("**Verified.** All 2 receipts verify.");
  });

  it("exits 1 when one receipt changed", () => {
    const { dir, receipts } = setup(good());
    const [executed] = good() as [ReceiptBundle];
    writeFileSync(join(receipts, `${decode(executed).predicate.receiptId}.json`), JSON.stringify(oneByteChanged(executed)));
    const r = run(receipts, "--issuer-key", join(dir, "issuer.pub"), "--principal-key", join(dir, "principal.pub"));
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("**Not verified.** 1 of 2 receipts do not verify.");
  });

  it("exits 1 for an empty directory, and refuses --json", () => {
    const { dir, receipts } = setup([]);
    const base = ["--issuer-key", join(dir, "issuer.pub")];
    expect(run(receipts, ...base).status).toBe(1);
    expect(run(receipts, ...base, "--json").stderr).toContain("does not combine");
  });
});
