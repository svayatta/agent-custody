import { createHash, webcrypto } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { createIssuer, generateKeyPair, publicKeyFromPem, type ReceiptBundle } from "@agent-custody/receipts";
import { buildCaseFile, parseCaseFile, renderCaseFile, verifyCaseFile, type CaseFile } from "../src/case-file.ts";
import { decodeStatement, formatExplain } from "../src/explain.ts";
import { Ledger } from "../src/ledger.ts";

const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "../../receipts/vectors/receipts.json"), "utf8"));
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

async function fixture(name = "gateway-precommit-executed", withLedger = false) {
  const vector = vectors.cases.find((c: any) => c.name === name);
  const bundle = structuredClone(vector.bundle) as ReceiptBundle;
  const id = decodeStatement(bundle).predicate.receiptId;
  const dir = mkdtempSync(join(tmpdir(), "custody-case-"));
  dirs.push(dir);
  writeFileSync(join(dir, `${id}.json`), JSON.stringify(bundle));
  const key = (name: string) => publicKeyFromPem(vectors.keys[name].publicKeyPem);
  const keys = { issuerKeys: vector.issuerKeys.map(key), principalKeys: vector.principalKeys.map(key), logKeys: vector.logKeys.map(key), upstreamKeys: (vector.upstreamKeys ?? []).map(key), ...(vector.logId ? { logId: vector.logId } : {}) };
  const ledger = withLedger ? new Ledger(join(dir, "ledger.jsonl")) : undefined;
  const file = await buildCaseFile({ receiptsDir: dir, keys, ...(ledger ? { ledger } : {}) }, id);
  return { file, keys, dir, id, ledger };
}

function scriptFrom(html: string): string {
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  expect(script).toBeTruthy();
  return script!;
}

async function runBrowser(html: string, dataOverride?: unknown): Promise<{ report: string; again: () => Promise<string> }> {
  const data = html.match(/<script id="case-data" type="application\/json">([\s\S]*?)<\/script>/)![1]!;
  let callback: (() => Promise<void>) | undefined;
  let resolve!: (value: string) => void;
  let pending = new Promise<string>((r) => { resolve = r; });
  const output = {
    set textContent(value: string) { if (value.includes("RESULT:")) resolve(value); },
  };
  const elements: Record<string, unknown> = {
    "case-data": { textContent: dataOverride === undefined ? data : JSON.stringify(dataOverride) },
    "fresh-report": output,
    verify: { addEventListener(_event: string, listener: () => Promise<void>) { callback = listener; } },
  };
  runInNewContext(scriptFrom(html), {
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, atob, btoa,
    document: { getElementById(id: string) { return elements[id]; } },
    // Network and DOM markup APIs are deliberately absent. The complete real script must run offline.
  }, { timeout: 2000 });
  const report = await pending;
  return { report, again: async () => { pending = new Promise<string>((r) => { resolve = r; }); await callback!(); return pending; } };
}

describe("offline case files", () => {
  it("bundles public keys, receipts, signed authorizations/proofs and ten answers without opening private capture", async () => {
    const { file, keys, dir, id } = await fixture();
    expect(file.verification.ok).toBe(true);
    expect(file.verification.trust).toBe("bundled");
    expect(file.verification.complete).toBe(false);
    expect(file.explanation).toMatch(/WHAT EVIDENCE\s+receipt/);
    expect(file.explanation).toContain("authorization committed as leaf");
    expect(file.explanation).toMatch(/WHAT NEEDS REVERSAL\s+unknown without a ledger/);
    expect(verifyCaseFile(file, keys).trust).toBe("independent");
    expect(verifyCaseFile(file, { issuerKeys: [generateKeyPair()], principalKeys: [] }).ok).toBe(false);
    // An issuer's adjacent private material and unsupported option properties are never read or serialized.
    mkdirSync(join(dir, "salts"));
    writeFileSync(join(dir, "salts", `${id}.json`), "LOCAL_SECRET_SALT");
    const another = await buildCaseFile({ receiptsDir: dir, keys: { ...keys, captureKey: Buffer.from("LOCAL_CAPTURE_KEY"), providerSecrets: { stripe: "LOCAL_PROVIDER_SECRET" } } as any }, id);
    expect(JSON.stringify(another)).not.toMatch(/LOCAL_SECRET_SALT|LOCAL_CAPTURE_KEY|LOCAL_PROVIDER_SECRET|PRIVATE KEY/);
    const captured = (await fixture("gateway-executed-private")).file;
    expect(decodeStatement(captured.pack.receipt).predicate.capture?.withheld.length).toBeGreaterThan(0);
    expect(captured.verification.receipts[captured.receiptId]!.checks.some((c) => c.detail?.includes("withheld"))).toBe(true);
    expect(captured.verification.complete).toBe(false);
  });

  it("treats missing keys as not checked and never trusts a saved successful report", async () => {
    const { file, dir, id } = await fixture();
    const bare = await buildCaseFile({ receiptsDir: dir }, id);
    expect(bare.verification.ok).toBe(false);
    expect(bare.verification.trust).toBe("none");
    expect(bare.verification.checks.find((c) => c.name === "issuer public keys supplied")?.detail).toContain("NOT CHECKED");
    file.pack.receipt.envelope.payload = "e30=";
    expect(file.verification.ok).toBe(true);
    expect(verifyCaseFile(file).ok).toBe(false);
    expect(renderCaseFile(file)).toContain("&quot;ok&quot;: false");
  });

  it.each(["receipt", "authorization", "proof", "authorization proof", "head", "authorization head"])("fails fresh verification after %s tampering", async (part) => {
    const { file, dir } = await fixture();
    const bundle = file.pack.receipt;
    if (part.startsWith("authorization")) {
      const statement = decodeStatement(bundle);
      const issuerKey = generateKeyPair();
      const issuer = createIssuer(issuerKey, dir, join(dir, "log.jsonl"));
      statement.predicate.issuer.keyid = issuerKey.keyid;
      const { execution: _execution, authorization: _authorization, ...authorizationPredicate } = statement.predicate;
      const auth = await issuer.authorize(authorizationPredicate);
      statement.predicate.authorization = auth;
      file.keys.issuerKeys = [{ keyid: issuerKey.keyid, pem: issuerKey.publicKey.export({ type: "spki", format: "pem" }).toString() }];
      file.pack.receipt = await issuer.issue(statement.predicate);
      // The saved answers belong to the old receipt. Rebuild them for the new one.
      file.explanation = formatExplain(file.pack, verifyCaseFile(file).receipts[file.receiptId] ?? null, file.withLedger);
      expect(verifyCaseFile(file).ok).toBe(true);
      if (part === "authorization") auth.envelope.signatures[0]!.sig = "AAAA";
      if (part === "authorization proof") auth.inclusion.leafIndex = 999;
      if (part === "authorization head") auth.treeHead.signatures[0]!.sig = "AAAA";
      file.pack.receipt = await issuer.issue(statement.predicate);
      const result = verifyCaseFile(file);
      const receiptResult = result.receipts[file.receiptId]!;
      // Re-sign and re-log the receipt after mutation: only the embedded authorization should fail.
      expect(receiptResult.checks.find((c) => c.name === "receipt signature (issuer key)")?.ok).toBe(true);
      expect(receiptResult.checks.some((c) => c.name.startsWith("authorization") && !c.ok)).toBe(true);
    } else if (part === "receipt") bundle.envelope.signatures[0]!.sig = "AAAA";
    else if (part === "proof") bundle.inclusion.leafIndex = 999;
    else bundle.treeHead.signatures[0]!.sig = "AAAA";
    expect(verifyCaseFile(file).ok).toBe(false);
    expect((await runBrowser(renderCaseFile(file))).report).toContain("RESULT: NOT VERIFIED");
  });

  it("fails when a saved answer is edited, in JSON and in HTML, and names the check", async () => {
    const { file, keys } = await fixture();
    const answers = (result: ReturnType<typeof verifyCaseFile>) => result.checks.find((c) => c.name === "ten answers match the signed receipt")!;
    expect(answers(verifyCaseFile(file)).ok).toBe(true);
    expect(answers(verifyCaseFile(file, keys)).ok).toBe(true);
    // Each edit keeps the receipts and the keys intact. Only the exporter's text changes.
    const edits: [RegExp, string][] = [[/^(WHO AUTHORIZED IT\s+).*$/m, "$1cfo_alice (manual sign-off)"], [/^(WHAT IT DID\s+\S+ ).*$/m, "$1{\"amount\":500} -> executed"], [/^(WHY\s+).*$/m, "$1the policy permitted it after human review"]];
    for (const [pattern, replacement] of edits) {
      const forged = structuredClone(file);
      forged.explanation = forged.explanation.replace(pattern, replacement);
      expect(forged.explanation).not.toBe(file.explanation);
      for (const result of [verifyCaseFile(forged), verifyCaseFile(forged, keys), verifyCaseFile(parseCaseFile(renderCaseFile(forged)))]) {
        expect(result.ok).toBe(false);
        expect(answers(result).ok).toBe(false);
        expect(result.receipts[file.receiptId]!.ok).toBe(true);
      }
    }
  });

  it("reads a rendered HTML case through the same checks, and tells a reader that the page does not check itself", async () => {
    const { file, keys } = await fixture();
    const html = renderCaseFile(file);
    expect(parseCaseFile(html)).toEqual(file);
    expect(parseCaseFile(JSON.stringify(file))).toEqual(file);
    expect(verifyCaseFile(parseCaseFile(html), keys).ok).toBe(true);
    expect(() => parseCaseFile("<!doctype html><p>nothing here</p>")).toThrow("no case-data script");
    expect(html).toContain("This page does not check itself independently");
    expect(html).toContain("--verify-case &lt;this file&gt;");
    expect((await runBrowser(html)).report).toContain("NOT CHECKED here: the ten answers");
    // A forged page that edits its data and its script together still fails the command.
    const forged = structuredClone(file);
    forged.explanation = forged.explanation.replace(/^(WHO AUTHORIZED IT\s+).*$/m, "$1cfo_alice");
    expect(forged.explanation).not.toBe(file.explanation);
    expect(verifyCaseFile(parseCaseFile(renderCaseFile(forged)), keys).ok).toBe(false);
  });

  it("checks every included receipt's signature and id, and marks absent cited evidence incomplete", async () => {
    const { file, ledger } = await fixture("gateway-precommit-executed", true);
    expect(file.verification.complete).toBe(true);
    const other = await fixture("sdk-executed");
    file.keys.issuerKeys.push(...other.file.keys.issuerKeys);
    file.pack.receipts[other.id] = other.file.pack.receipt;
    expect(verifyCaseFile(file).ok).toBe(true);
    file.pack.receipts[other.id]!.envelope.signatures[0]!.sig = "AAAA";
    expect(verifyCaseFile(file).ok).toBe(false);
    file.pack.receipts[other.id] = file.pack.receipt;
    expect(verifyCaseFile(file).checks.find((c) => c.name === `receipt ${other.id} matches its id`)?.ok).toBe(false);
    delete file.pack.receipts[other.id];
    file.pack.downstream.receipts.push({ receiptId: other.id, timestamp: "2026-01-01", status: "executed", tool: "test", consumed: [], consumedWithheld: false });
    const missing = verifyCaseFile(file);
    expect(missing.ok).toBe(false);
    expect(missing.complete).toBe(false);
    expect(missing.checks.find((c) => c.name === "all cited receipts included")?.ok).toBe(false);
    await ledger!.close();
  });

  it("includes consumed beliefs' source receipts and preserves unknown/missing evidence caveats", async () => {
    const { file, dir, ledger } = await fixture("sdk-executed", true);
    const source = await fixture("gateway-executed");
    writeFileSync(join(dir, `${source.id}.json`), JSON.stringify(source.file.pack.receipt));
    const { fact } = await ledger!.assert({ subject: "acct:42", predicate: "plan", value: "enterprise", space: "org", actor: "test", provenance: "attested", source: { receiptId: source.id } });
    const issuerKey = generateKeyPair();
    const issuer = createIssuer(issuerKey, dir, join(dir, "log.jsonl"));
    const predicate = decodeStatement(file.pack.receipt).predicate;
    predicate.issuer.keyid = issuerKey.keyid;
    predicate.consumed = { factIds: [fact.factId], provenance: "observed" };
    await issuer.issue(predicate);
    const keys = { issuerKeys: [issuerKey, ...source.keys.issuerKeys], principalKeys: source.keys.principalKeys };
    const built = await buildCaseFile({ receiptsDir: dir, ledger, keys }, file.receiptId);
    expect(Object.keys(built.pack.receipts)).toContain(source.id);
    expect(built.verification.ok).toBe(true);
    expect(built.verification.complete).toBe(true);
    built.pack.consumed.unknown.push("unknown-fact");
    expect(verifyCaseFile(built).complete).toBe(false);
    expect((await runBrowser(renderCaseFile(built))).report).toContain("INCOMPLETE");
    rmSync(join(dir, `${source.id}.json`));
    const missing = await buildCaseFile({ receiptsDir: dir, ledger, keys }, file.receiptId);
    expect(missing.pack.missingReceipts).toContain(source.id);
    expect(missing.verification.complete).toBe(false);
    expect(missing.verification.ok).toBe(false);
    expect((await runBrowser(renderCaseFile(missing))).report).toContain("RESULT: NOT VERIFIED");
    await ledger!.close();
  });

  it("rejects malformed artifacts, path-like ids, and mislabeled public keys", async () => {
    const { file, dir } = await fixture();
    for (const value of [null, {}, { ...file, pack: null }, { ...file, keys: { issuerKeys: [] } }, { ...file, receiptId: "../private-key" }]) {
      expect(verifyCaseFile(value as CaseFile).ok).toBe(false);
    }
    await expect(buildCaseFile({ receiptsDir: dir }, "../private-key")).rejects.toThrow("invalid receipt id");
    file.keys.issuerKeys[0]!.keyid = "0".repeat(64);
    expect(verifyCaseFile(file).ok).toBe(false);
    expect((await runBrowser(renderCaseFile(file))).report).toContain("fingerprint mismatch");
  });

  it("runs its exact embedded WebCrypto verifier offline, automatically and by button, under a matching CSP hash", async () => {
    const { file } = await fixture();
    file.explanation += '\n</script><img src="https://attacker.invalid" onerror="evil()">';
    const html = renderCaseFile(file);
    expect(html).toContain("default-src 'none'");
    expect(html).toContain(`script-src 'sha256-${createHash("sha256").update(scriptFrom(html)).digest("base64")}'`);
    expect(html).not.toMatch(/<img|<script[^>]+src=|<link[^>]+href=/);
    expect(html).toContain("\\u003c/script>");
    expect(html).toContain("&lt;img");
    expect(html).toContain("not independently attested");
    const browser = await runBrowser(html);
    expect(browser.report).toContain("RESULT: VERIFIED AGAINST BUNDLED KEYS");
    expect(browser.report).toContain("authorization signature (issuer key)");
    expect(browser.report).toContain("INCOMPLETE");
    expect(await browser.again()).toContain("RESULT: VERIFIED AGAINST BUNDLED KEYS");
    const changed = structuredClone(file);
    changed.receiptId = "f".repeat(36);
    expect((await runBrowser(html, changed)).report).toContain("RESULT: NOT VERIFIED");
  });
});
