// A portable evidence file. Its public keys travel with the evidence; their presence is not a trust anchor.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as nodeModule from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { keyidOf, publicKeyFromPem, publicKeyToPem, verifyBundle, type ReceiptBundle, type VerifyOptions, type VerifyResult } from "@agent-custody/receipts";
import { buildActionPack, formatExplain, type ActionPack, type ActionPackCheck } from "./explain.ts";
import type { Ledger } from "./ledger.ts";

export interface CaseFileOptions {
  receiptsDir: string;
  ledger?: Ledger;
  /** Public keys only. Capture keys, disclosures, salts, and provider secrets are deliberately unsupported. */
  keys?: Pick<VerifyOptions, "issuerKeys" | "principalKeys" | "approvalKeys" | "logKeys" | "upstreamKeys" | "logId">;
}

export interface CaseFileKey { keyid: string; pem: string }
export interface CaseFileKeys {
  issuerKeys: CaseFileKey[];
  principalKeys: CaseFileKey[];
  approvalKeys: CaseFileKey[];
  logKeys: CaseFileKey[];
  upstreamKeys: CaseFileKey[];
  logId?: string;
}
export interface CaseFileVerification {
  ok: boolean;
  /** False when receipts/beliefs are absent or unknown, consumed ids are withheld, or no ledger was supplied. */
  complete: boolean;
  trust: "bundled" | "independent" | "none";
  checks: ActionPackCheck[];
  receipts: Record<string, VerifyResult>;
  /** The ten answers rebuilt from the signed receipt and the file's ledger snapshot. A reader trusts these, never a saved copy. */
  answers?: string;
}
export interface CaseFile {
  version: "0.1";
  generatedAt: string;
  receiptId: string;
  withLedger: boolean;
  pack: ActionPack;
  keys: CaseFileKeys;
  /** Exporter snapshot, not a separately signed assertion about the ledger. */
  explanation: string;
  /** Informational export-time report. Verification always recomputes this. */
  verification: CaseFileVerification;
}

// Keep this pure and self-contained: the same validation function runs inside the offline page.
function caseProblem(file: any): string | null {
  const object = (v: any) => !!v && typeof v === "object" && !Array.isArray(v);
  const id = (v: any) => typeof v === "string" && /^[0-9a-f-]{36}$/.test(v);
  const fact = (f: any) => object(f) && typeof f.factId === "string" && object(f.source) && (f.source.receiptId === null || id(f.source.receiptId));
  const summary = (r: any) => object(r) && id(r.receiptId);
  if (!object(file) || file.version !== "0.1" || !id(file.receiptId) || typeof file.generatedAt !== "string" || typeof file.withLedger !== "boolean" || typeof file.explanation !== "string") return "malformed case file";
  const p = file.pack;
  if (!object(p) || p.version !== "0.1" || p.receiptId !== file.receiptId || !object(p.receipt) || !object(p.receipts)) return "case file and action pack must name the same receipt";
  if (!object(p.consumed) || !Array.isArray(p.consumed.facts) || !p.consumed.facts.every(fact) || !Array.isArray(p.consumed.unknown) || !p.consumed.unknown.every((v: any) => typeof v === "string") || typeof p.consumedWithheld !== "boolean" || !Array.isArray(p.written) || !p.written.every(fact) || !object(p.status)) return "malformed belief snapshot";
  const d = p.downstream;
  if (!object(d) || !Array.isArray(d.receipts) || !d.receipts.every(summary) || !Array.isArray(d.withheld) || !d.withheld.every(summary) || !Array.isArray(d.derivedFacts) || !d.derivedFacts.every(fact) || !Array.isArray(d.stillBelieved) || !d.stillBelieved.every(fact) || !Array.isArray(p.missingReceipts) || !p.missingReceipts.every(id)) return "malformed downstream snapshot";
  if (Object.keys(p.receipts).some((k) => !id(k)) || Object.values(p.receipts).some((b) => !object(b))) return "malformed receipt map";
  if (!object(file.keys)) return "malformed public key set";
  for (const role of ["issuerKeys", "principalKeys", "approvalKeys", "logKeys", "upstreamKeys"]) {
    if (!Array.isArray(file.keys[role]) || file.keys[role].some((k: any) => !object(k) || typeof k.keyid !== "string" || !/^[0-9a-f]{64}$/.test(k.keyid) || typeof k.pem !== "string" || !/^-----BEGIN PUBLIC KEY-----[\s\S]*-----END PUBLIC KEY-----\s*$/.test(k.pem))) return "malformed public keys (only public SPKI PEM is accepted)";
  }
  if (file.keys.logId !== undefined && typeof file.keys.logId !== "string") return "malformed log id";
  return null;
}

function citedIds(pack: ActionPack): string[] {
  return [...new Set([...pack.downstream.receipts.map((r) => r.receiptId), ...pack.downstream.withheld.map((r) => r.receiptId), ...[...pack.consumed.facts, ...pack.written, ...pack.downstream.derivedFacts].map((f) => f.source.receiptId).filter((id): id is string => !!id)])];
}

export async function buildCaseFile(options: CaseFileOptions, receiptId: string): Promise<CaseFile> {
  if (!/^[0-9a-f-]{36}$/.test(receiptId)) throw new Error("invalid receipt id");
  // No capture key is accepted here: the portable file preserves the issued private view.
  const pack = await buildActionPack(options.receiptsDir, receiptId, options.ledger);
  // A withheld consumed-id list still cites a receipt: include its signed evidence and keep the caveat.
  for (const id of citedIds(pack)) {
    if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error("invalid cited receipt id");
    if (id === receiptId || Object.hasOwn(pack.receipts, id)) continue;
    try {
      pack.receipts[id] = JSON.parse(readFileSync(join(options.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
      pack.missingReceipts = pack.missingReceipts.filter((missing) => missing !== id);
    } catch {
      if (!pack.missingReceipts.includes(id)) pack.missingReceipts.push(id);
    }
  }
  const keys: CaseFileKeys = { issuerKeys: [], principalKeys: [], approvalKeys: [], logKeys: [], upstreamKeys: [] };
  for (const role of ["issuerKeys", "principalKeys", "approvalKeys", "logKeys", "upstreamKeys"] as const) {
    keys[role] = (options.keys?.[role] ?? []).map((key) => {
      if (key.publicKey.type !== "public" || key.publicKey.asymmetricKeyType !== "ed25519" || keyidOf(key.publicKey) !== key.keyid) throw new Error(`invalid ${role} public key or fingerprint`);
      return { keyid: key.keyid, pem: publicKeyToPem(key.publicKey) };
    });
  }
  if (options.keys?.logId !== undefined) keys.logId = options.keys.logId;
  const file: CaseFile = {
    version: "0.1", generatedAt: new Date().toISOString(), receiptId, withLedger: !!options.ledger, pack, keys,
    explanation: "", verification: { ok: false, complete: false, trust: "none", checks: [], receipts: {} },
  };
  // The answers carry the receipt's verdict, and the verification checks the answers. Verify once to get the verdict.
  file.explanation = formatExplain(pack, verifyCaseFile(file).receipts[receiptId] ?? null, file.withLedger);
  file.verification = verifyCaseFile(file);
  return file;
}

/** Reads the case file from the `case-data` script of a rendered `.case.html`. It does not validate: `verifyCaseFile` does. */
export function parseCaseHtml(html: string): CaseFile {
  // The renderer escapes every "<" in the data, so the first closing tag ends the data.
  const data = /<script id="case-data" type="application\/json">([\s\S]*?)<\/script>/.exec(html)?.[1];
  if (data === undefined) throw new Error("this HTML file has no case-data script");
  return JSON.parse(data);
}

/** Checks signed receipts and their embedded authorizations/proofs afresh. The exporter report is never trusted. */
export function verifyCaseFile(file: CaseFile, trustedKeys?: CaseFileOptions["keys"]): CaseFileVerification {
  const checks: ActionPackCheck[] = [];
  const receipts: Record<string, VerifyResult> = Object.create(null);
  let complete = false;
  let rebuilt: string | undefined;
  let trust: CaseFileVerification["trust"] = "none";
  const add = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, ...(detail ? { detail } : {}) });
  try {
    const problem = caseProblem(file);
    add("case file structure", !problem, problem ?? undefined);
    if (problem) return { ok: false, complete, trust, checks, receipts };
    const imported = (role: "issuerKeys" | "principalKeys" | "approvalKeys" | "logKeys" | "upstreamKeys") => file.keys[role].map((key) => {
      const ref = publicKeyFromPem(key.pem);
      if (ref.publicKey.type !== "public" || ref.publicKey.asymmetricKeyType !== "ed25519" || ref.keyid !== key.keyid) throw new Error(`${role} public key fingerprint mismatch`);
      return ref;
    });
    const bundled = { issuerKeys: imported("issuerKeys"), principalKeys: imported("principalKeys"), approvalKeys: imported("approvalKeys"), logKeys: imported("logKeys"), upstreamKeys: imported("upstreamKeys"), ...(file.keys.logId === undefined ? {} : { logId: file.keys.logId }) };
    // Validate the supplied independent fingerprints too; don't silently accept a wrongly labelled trust anchor.
    const keys = trustedKeys ?? bundled;
    for (const role of ["issuerKeys", "principalKeys", "approvalKeys", "logKeys", "upstreamKeys"] as const) {
      for (const key of keys[role] ?? []) if (key.publicKey.type !== "public" || key.publicKey.asymmetricKeyType !== "ed25519" || keyidOf(key.publicKey) !== key.keyid) throw new Error(`${role} public key fingerprint mismatch`);
    }
    const hasKeys = keys.issuerKeys.length > 0;
    trust = !hasKeys ? "none" : trustedKeys ? "independent" : "bundled";
    add("issuer public keys supplied", hasKeys, hasKeys ? (trustedKeys ? "checked against independently supplied keys" : "bundled keys only; confirm fingerprints through an independent channel") : "NOT CHECKED: no issuer public keys supplied");
    for (const [id, bundle] of [[file.receiptId, file.pack.receipt], ...Object.entries(file.pack.receipts)] as [string, ReceiptBundle][]) {
      let result: VerifyResult;
      try { result = verifyBundle(bundle, keys); }
      catch { result = { ok: false, checks: [{ name: "well-formed receipt bundle", ok: false }], statement: null }; }
      receipts[id] = result;
      add(`receipt ${id} verifies`, result.ok, result.checks.filter((c) => !c.ok).map((c) => c.name).join(", "));
      add(`receipt ${id} matches its id`, result.statement?.predicate.receiptId === id);
    }
    // The saved answers are text from the exporter. Most of them come from signed data, so rebuild them from the receipt.
    // The exporter wrote the verdict line with the bundled keys, so rebuild it with the same keys.
    let own: VerifyResult | undefined = receipts[file.receiptId];
    if (trustedKeys) {
      try { own = verifyBundle(file.pack.receipt, bundled); }
      catch { own = undefined; }
    }
    let answers: string | null = null;
    try { answers = formatExplain(file.pack, own ?? null, file.withLedger); }
    catch { /* a receipt that cannot be decoded has no answers to compare */ }
    if (answers !== null) rebuilt = answers;
    // The belief, dependency and reversal answers come from the pack's ledger snapshot, which nobody signs. Say so in the name.
    add("ten answers match the signed receipt and the unsigned ledger snapshot", answers !== null && answers === file.explanation, answers === null ? "the receipt cannot be read" : answers === file.explanation ? "the lines on beliefs, dependencies and reversals come from the unsigned ledger snapshot in this file and are not attested" : "the saved answers differ from the answers that the signed receipt and the snapshot give");
    const missing = citedIds(file.pack).filter((id) => id !== file.receiptId && !Object.hasOwn(file.pack.receipts, id));
    add("all cited receipts included", !file.pack.missingReceipts.length && !missing.length, [...new Set([...file.pack.missingReceipts, ...missing])].join(", "));
    add("written beliefs cite this receipt", file.pack.written.every((f) => f.source.receiptId === file.receiptId));
    complete = !file.pack.missingReceipts.length && !missing.length && !file.pack.consumedWithheld && !file.pack.consumed.unknown.length && !file.pack.downstream.withheld.length && file.withLedger;
  } catch (error) {
    add("case file is readable", false, error instanceof Error ? error.message : "malformed artifact");
  }
  return { ok: checks.every((c) => c.ok), complete, trust, checks, receipts, ...(rebuilt === undefined ? {} : { answers: rebuilt }) };
}

/**
 * Checks a rendered `.case.html`. The data in the page is checked as for the JSON. The page itself is checked too: it must be
 * byte for byte what the data renders, so a changed visible answer, or a second copy of the data, fails. A page from another
 * build of this package fails as well; then the reader trusts the rebuilt `answers` and not the page.
 */
export function verifyCaseHtml(html: string, trustedKeys?: CaseFileOptions["keys"]): CaseFileVerification {
  const file = parseCaseHtml(html);
  const result = verifyCaseFile(file, trustedKeys);
  let same = false;
  try { same = renderCaseFile(file) === html; }
  catch { /* data that cannot be rendered is not what the page shows */ }
  const check = { name: "page is exactly what its case data renders", ok: same, ...(same ? {} : { detail: "the page differs from its data (an edit, a second copy of the data, or another build); do not trust the page, trust the answers printed here" }) };
  return { ...result, ok: result.ok && same, checks: [check, ...result.checks] };
}

let cachedBrowserSource: string | undefined;
function browserVerifierSource(): string {
  if (cachedBrowserSource !== undefined) return cachedBrowserSource;
  // Published packages include the compiled canonical verifier. Source checkouts use Node's native eraser.
  let source: string;
  try { source = readFileSync(fileURLToPath(new URL("./verify-web.js", import.meta.url)), "utf8"); }
  catch {
    const typescript = readFileSync(fileURLToPath(new URL("./verify-web.ts", import.meta.url)), "utf8");
    if (typeof nodeModule.stripTypeScriptTypes === "function") source = nodeModule.stripTypeScriptTypes(typescript, { mode: "strip" });
    else {
      const bun = (globalThis as unknown as { Bun?: { Transpiler: new (options: { loader: "ts"; target: "browser" }) => { transformSync(source: string): string } } }).Bun;
      if (!bun?.Transpiler) throw new Error("Build @agent-custody/state first, or render from source using Node 22.13+ or Bun");
      source = new bun.Transpiler({ loader: "ts", target: "browser" }).transformSync(typescript);
    }
  }
  cachedBrowserSource = source.replace(/^export\s+(?=(?:async\s+)?(?:function|const|let|class)\b)/gm, "").replace(/^export\s*\{\s*\};?\s*$/gm, "").replace(/^\/\/# sourceMappingURL=.*$/gm, "");
  return cachedBrowserSource;
}

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);

/** A single local HTML file: no server, fetch, imported scripts, fonts, images, secrets, or restored values. */
export function renderCaseFile(file: CaseFile): string {
  const report = verifyCaseFile(file);
  const problem = caseProblem(file);
  const data = JSON.stringify(file).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  // HTML normalizes CRLF before CSP hashing in the browser, including files exported on Windows.
  const script = `"use strict";\n${browserVerifierSource()}\nconst caseProblem = ${caseProblem.toString()};\n${BROWSER_CASE_SCRIPT}`.replace(/\r\n?/g, "\n");
  const hash = createHash("sha256").update(script).digest("base64");
  const text = (value: unknown) => escapeHtml(typeof value === "string" ? value : JSON.stringify(value, null, 2));
  const keyText = problem ? "Malformed public key set" : Object.entries(file.keys).filter(([role]) => role !== "logId").map(([role, keys]) => `${role}:\n${(keys as CaseFileKey[]).map((key) => `SHA-256 ${key.keyid}\n${key.pem}`).join("\n") || "(none)"}`).join("\n\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-${hash}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Custody case ${text(file?.receiptId ?? "invalid")}</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:1040px;margin:2rem auto;padding:0 1rem;color:#202020;background:#faf9f6}h1,h2{line-height:1.2}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;border:1px solid #ccc;border-radius:6px;padding:1rem}button{font:inherit;padding:.5rem 1rem;cursor:pointer}summary{cursor:pointer}#fresh-report{border-left:4px solid #a66c00}small{color:#555}</style></head><body><h1>Custody case file</h1><p>Receipt <code>${text(file?.receiptId ?? "invalid")}</code>. Saved ${text(file?.generatedAt ?? "unknown")}.</p><p>This file contains signed receipts, embedded signed authorizations, log heads and inclusion proofs, and public keys. It works offline when opened locally.</p><p><strong>Trust:</strong> bundled keys demonstrate internal consistency. Confirm each SHA-256 fingerprint with the issuer, principal, log operator, or upstream through an independent channel before trusting their identity. A signed receipt records a claim about execution; it does not by itself prove that an external side effect occurred.</p><p>Withheld values remain commitments; their hidden contents are not recomputed here. The ten answers and belief/ledger data are an exporter snapshot, not independently attested facts. The exporter report below is historical; the browser recomputes signatures, authorizations, digests and inclusion proofs.</p><h2>Fresh browser verification</h2><p><strong>This page does not check itself independently.</strong> Its result comes from the script in this same file, and whoever edits the file can edit the script and the answers too. This page does not compare the ten answers with the receipts. To check this file, run <code>agent-custody-memory review --verify-case &lt;this file&gt; --issuer-key &lt;issuer.pub&gt; --principal-key &lt;principal.pub&gt;</code>. The command reads this .html file and checks that the page is exactly what its data renders. It prints the ten answers that it rebuilds from the signed receipt. Trust the answers that the command prints, not the answers on this page.</p><button id="verify" type="button">Verify again offline</button><pre id="fresh-report" role="status" aria-live="polite">NOT CHECKED: waiting for WebCrypto verification. If this stays unchanged, this browser could not run the verifier.</pre><noscript><p>NOT CHECKED: JavaScript is disabled. Use the independent command-line verifier: <code>agent-custody-memory review --verify-case &lt;this file&gt; --issuer-key &lt;issuer.pub&gt; --principal-key &lt;principal.pub&gt;</code>.</p></noscript><h2>Ten answers (saved text, NOT CHECKED in this page)</h2><pre>${text(problem ?? file.explanation)}</pre><h2>Export-time verification (recomputed when rendering)</h2><pre>${text(report)}</pre><h2>Public keys and fingerprints</h2><pre>${text(keyText)}</pre><details><summary>All receipts, authorizations, proofs and ledger snapshot (JSON)</summary><pre>${text(file)}</pre></details><script id="case-data" type="application/json">${data}</script><script>${script}</script></body></html>`;
}

const BROWSER_CASE_SCRIPT = `
const caseFile = JSON.parse(document.getElementById("case-data").textContent);
async function verifyCaseOffline() {
  const output = document.getElementById("fresh-report");
  output.textContent = "CHECKING: fresh WebCrypto verification…";
  const lines = [];
  let good = true;
  const check = (name, ok, detail) => { if (!ok) good = false; lines.push((ok ? "PASS  " : "FAIL  ") + name + (detail ? "  (" + detail + ")" : "")); };
  try {
    const problem = caseProblem(caseFile);
    if (problem) throw new Error(problem);
    if (!globalThis.crypto || !globalThis.crypto.subtle) throw new Error("WebCrypto is unavailable in this browser. Verification was not performed.");
    const keys = {};
    for (const role of ["issuerKeys", "principalKeys", "approvalKeys", "logKeys", "upstreamKeys"]) {
      keys[role] = [];
      for (const ref of caseFile.keys[role]) {
        const key = await publicKeyFromPem(ref.pem);
        if (key.keyid !== ref.keyid) throw new Error(role + " public key fingerprint mismatch");
        keys[role].push(key);
      }
    }
    if (caseFile.keys.logId !== undefined) keys.logId = caseFile.keys.logId;
    check("issuer public keys supplied", keys.issuerKeys.length > 0, keys.issuerKeys.length ? "BUNDLED KEYS ONLY: confirm fingerprints independently" : "NOT CHECKED: no issuer public keys supplied");
    const pack = caseFile.pack;
    for (const [id, bundle] of [[caseFile.receiptId, pack.receipt], ...Object.entries(pack.receipts)]) {
      lines.push("", "Receipt " + id);
      let result;
      try { result = await verifyBundle(bundle, keys); }
      catch (error) { result = { ok: false, statement: null, checks: [{ name: "well-formed receipt bundle", ok: false, detail: String(error) }] }; }
      for (const c of result.checks) check(c.name, c.ok, c.detail);
      check("receipt matches its id", result.statement?.predicate.receiptId === id);
      if (!result.ok) good = false;
    }
    const cited = [...pack.downstream.receipts, ...pack.downstream.withheld].map(r => r.receiptId).concat([...pack.consumed.facts, ...pack.written, ...pack.downstream.derivedFacts].map(f => f.source.receiptId).filter(Boolean));
    const missing = cited.filter(id => id !== caseFile.receiptId && !Object.hasOwn(pack.receipts, id));
    check("all cited receipts included", pack.missingReceipts.length === 0 && missing.length === 0, [...new Set([...pack.missingReceipts, ...missing])].join(", "));
    check("written beliefs cite this receipt", pack.written.every(f => f.source.receiptId === caseFile.receiptId));
    const incomplete = missing.length || pack.missingReceipts.length || pack.consumedWithheld || pack.consumed.unknown.length || pack.downstream.withheld.length || !caseFile.withLedger;
    lines.push("", good ? "RESULT: VERIFIED AGAINST BUNDLED KEYS (confirm fingerprints independently)" : "RESULT: NOT VERIFIED");
    if (incomplete) lines.push("INCOMPLETE: missing evidence, withheld consumed ids, or no ledger. Dependency and reversal answers remain limited.");
    lines.push("This checks signed evidence, not external side effects or the exporter's ledger snapshot.");
    lines.push("NOT CHECKED here: the ten answers. They are the exporter's saved text. This result is not independent, because the script is in the same file as the data. Run: agent-custody-memory review --verify-case <this file> --issuer-key <issuer.pub> --principal-key <principal.pub>");
  } catch (error) { lines.push("RESULT: NOT VERIFIED / NOT CHECKED: " + String(error)); }
  output.textContent = lines.join("\\n");
}
document.getElementById("verify").addEventListener("click", verifyCaseOffline);
void verifyCaseOffline();
`;
