// The review page: the explain command for people who will not open a terminal. It serves, or writes as static
// files, one page per receipt with the ten answers and the verification report, and an index of every receipt in
// the directory. It runs where the receipts are, on the customer's machine, because nobody else holds them; the
// hosted log has only their hashes. No framework, no outside requests, and no authentication of its own: bind it
// to loopback, or put it behind whatever already guards the machine.
import { readdirSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { verifyBundle, type ReceiptBundle, type VerifyOptions, type VerifyResult } from "@agent-custody/receipts";
import { buildActionPack, decodeStatement, formatExplain, type ActionPack } from "./explain.ts";
import type { Ledger } from "./ledger.ts";
import { matchesReceiptSearch, receiptSearchTerms, validateReceiptSearch, type ReceiptSearch } from "./search.ts";
import { buildCaseFile, renderCaseFile } from "./case-file.ts";

export interface ReviewOptions {
  receiptsDir: string;
  ledger?: Ledger;
  /** with these, every receipt page carries its verification report */
  keys?: Pick<VerifyOptions, "issuerKeys" | "principalKeys" | "logKeys" | "upstreamKeys" | "logId">;
  /** shown in the page header, e.g. the team or the deployment */
  title?: string;
  /** Initial search; static exports include only the matching receipts. Only public receipt fields are searched. */
  search?: ReceiptSearch;
}

export interface ReceiptRow {
  receiptId: string;
  timestamp: string;
  tool: string;
  status: string;
  agent: string;
  principal: string | null;
  issuer: string;
  verified: boolean | null;
  transactionIds: string[];
  customerIds: string[];
}

const esc = (s: unknown) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

/** Every receipt in the directory, newest first, with its verdict when keys were given. Damaged files are skipped. */
export function listReceipts(o: ReviewOptions, query: ReceiptSearch = o.search ?? {}): ReceiptRow[] {
  validateReceiptSearch(query);
  const rows: ReceiptRow[] = [];
  for (const f of readdirSync(o.receiptsDir)) {
    if (!f.endsWith(".json") || f.endsWith(".authorization.json")) continue;
    try {
      const bundle = JSON.parse(readFileSync(join(o.receiptsDir, f), "utf8")) as ReceiptBundle;
      const p = decodeStatement(bundle).predicate;
      if (!/^[0-9a-f-]{36}$/.test(p.receiptId) || f !== `${p.receiptId}.json` || !matchesReceiptSearch(p, query)) continue;
      const verified = verifyOf(bundle, o)?.ok ?? null;
      rows.push({ receiptId: p.receiptId, timestamp: p.timestamp, tool: p.tool.name, status: p.execution.status, agent: p.agent.id, principal: p.principal.id, issuer: p.issuer.kind, verified, ...receiptSearchTerms(p) });
    } catch {
      // not a bundle; the index is of receipts
    }
  }
  return rows.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

const STYLE = `
  :root { color-scheme: light dark; --ink: #1b2430; --ink2: #5b6b7a; --line: #d7dfe5; --bg: #fafbfc; --panel: #ffffff; --accent: #0f6e63; --bad: #b3261e; --mono: ui-monospace, Menlo, monospace; }
  @media (prefers-color-scheme: dark) { :root { --ink: #e6ecf0; --ink2: #9fb0bd; --line: #27333c; --bg: #0e1418; --panel: #151d23; --accent: #4fc3b0; --bad: #ff8a80; } }
  body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 system-ui, sans-serif; }
  main { max-width: 74rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; } h2 { font-size: 1.05rem; margin: 1.75rem 0 .6rem; }
  .sub { color: var(--ink2); margin: 0 0 1.25rem; }
  a { color: var(--accent); }
  table { border-collapse: collapse; width: 100%; font-size: .93rem; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; white-space: nowrap; }
  th { font-size: .78rem; letter-spacing: .04em; text-transform: uppercase; color: var(--ink2); }
  code, pre, .mono { font-family: var(--mono); font-size: .88em; }
  pre { background: var(--panel); border: 1px solid var(--line); border-radius: 4px; padding: .9rem 1rem; overflow-x: auto; white-space: pre-wrap; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .45rem 1.25rem; margin: 0; }
  dt { font-size: .78rem; letter-spacing: .04em; text-transform: uppercase; color: var(--ink2); padding-top: .15rem; }
  dd { margin: 0; white-space: pre-wrap; }
  .ok { color: var(--accent); font-weight: 600; } .bad { color: var(--bad); font-weight: 600; } .muted { color: var(--ink2); }
  .wrap { overflow-x: auto; }
  form { display: flex; flex-wrap: wrap; gap: .8rem; padding: 1rem; border: 1px solid var(--line); margin-bottom: 1rem; }
  label { display: grid; gap: .25rem; font-size: .85rem; }
  input, button { font: inherit; padding: .45rem; color: var(--ink); background: var(--panel); border: 1px solid var(--line); border-radius: 3px; }
  button { cursor: pointer; align-self: end; }
  [hidden] { display: none !important; }
  @media (max-width: 40rem) { dl { grid-template-columns: 1fr; } }
`;

// Static exports filter their exported rows in the browser, including when opened from file://. Live pages use GET.
const SEARCH_SCRIPT = `
${validateReceiptSearch.toString()}
const form = document.getElementById('receipt-search');
form.addEventListener('submit', (event) => {
  event.preventDefault();
  const value = (name) => form.elements.namedItem(name).value.trim();
  const from = value('from'), to = value('to');
  const error = document.getElementById('search-error');
  try {
    validateReceiptSearch({ ...(from ? { from } : {}), ...(to ? { to } : {}) });
  } catch (problem) {
    error.textContent = problem.message;
    return;
  }
  error.textContent = '';
  let count = 0;
  for (const row of document.querySelectorAll('tbody tr')) {
    const data = row.dataset;
    const matches = (!value('transaction') || JSON.parse(data.transactions).includes(value('transaction')))
      && (!value('customer') || JSON.parse(data.customers).includes(value('customer')))
      && (!value('agent') || data.agent === value('agent'))
      && (!from || Date.parse(data.timestamp) >= Date.parse(from))
      && (!to || Date.parse(data.timestamp) <= Date.parse(to));
    row.hidden = !matches;
    if (matches) count++;
  }
  document.getElementById('receipt-count').textContent = count + ' receipt(s)';
  document.getElementById('no-results').hidden = count !== 0;
});
form.addEventListener('reset', () => {
  for (const input of form.querySelectorAll('input')) input.defaultValue = '';
  queueMicrotask(() => form.requestSubmit());
});
`.replace(/\r\n?/g, "\n");
const REVIEW_CSP = `default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-${createHash("sha256").update(SEARCH_SCRIPT).digest("base64")}'; img-src data:; form-action 'self'; base-uri 'none'`;

const page = (title: string, body: string, script = "") => `<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="content-security-policy" content="${esc(REVIEW_CSP)}">
<title>${esc(title)}</title>
<style>${STYLE}</style>
<main>${body}</main>
${script ? `<script>${script}</script>` : ""}
`;

/** The index: one row per receipt, newest first. */
export function renderIndex(rows: ReceiptRow[], o: ReviewOptions, link: (id: string) => string, staticPage = false): string {
  const withKeys = !!o.keys;
  const verdict = (r: ReceiptRow) => (r.verified === null ? '<span class="muted">not checked</span>' : r.verified ? '<span class="ok">verified</span>' : '<span class="bad">NOT VERIFIED</span>');
  const body = `
<h1>${esc(o.title ?? "Receipts")}</h1>
<p class="sub"><span id="receipt-count">${rows.length} receipt(s)</span> in ${esc(o.receiptsDir)}${withKeys ? ", each checked against the keys given" : ", not checked: start the review with the gateway's and principal's public keys to verify"}${o.ledger ? "; beliefs from the ledger" : "; no ledger, so what depended on a call is not known here"}.</p>
<form id="receipt-search" method="get">
${([['transaction', 'Transaction ID', 're_… / pi_… / charge ID'], ['customer', 'Customer ID', 'cust_…'], ['agent', 'Agent', 'support-agent'], ['from', 'From (inclusive)', '2026-10-14T00:00:00Z'], ['to', 'To (inclusive)', '2026-10-15T00:00:00Z']] as const).map(([name, label, placeholder]) => `<label>${label}<input name="${name}" value="${esc(o.search?.[name] ?? "")}" placeholder="${placeholder}"${name === 'from' || name === 'to' ? ' pattern="[0-9]{4}-[0-9]{2}-[0-9]{2}T.+(Z|[+-][0-9]{2}:[0-9]{2})"' : ''}></label>`).join("\n")}
<button type="submit">Search receipts</button>${staticPage ? '<button type="reset">Clear filters</button>' : '<a href="/?transaction=&amp;customer=&amp;agent=&amp;from=&amp;to=">Clear filters</a>'}
</form>
<p class="muted">Filters combine and match exact IDs. Search covers public arguments, results and gateway facts; identifiers withheld by a capture rule are unavailable.${staticPage ? ' This export searches only the receipts included here.' : ''}</p>
<p id="search-error" role="alert" class="bad"></p>
<p id="no-results"${rows.length ? ' hidden' : ''}>No receipts match these filters.</p>
<div class="wrap"><table><thead><tr><th>when</th><th>tool</th><th>outcome</th><th>transaction</th><th>customer</th><th>agent</th><th>principal</th><th>producer</th><th>verification</th><th>receipt</th></tr></thead><tbody>
${rows.map((r) => `<tr data-transactions="${esc(JSON.stringify(r.transactionIds))}" data-customers="${esc(JSON.stringify(r.customerIds))}" data-agent="${esc(r.agent)}" data-timestamp="${esc(r.timestamp)}"><td>${esc(r.timestamp.replace("T", " ").slice(0, 19))}</td><td><code>${esc(r.tool)}</code></td><td>${esc(r.status)}</td><td class="mono">${esc(r.transactionIds.join(', '))}</td><td class="mono">${esc(r.customerIds.join(', '))}</td><td>${esc(r.agent)}</td><td>${esc(r.principal ?? "")}</td><td>${esc(r.issuer)}</td><td>${verdict(r)}</td><td><a class="mono" href="${esc(link(r.receiptId))}">${esc(r.receiptId.slice(0, 8))}</a></td></tr>`).join("\n")}
</tbody></table></div>
<p class="muted">A gateway receipt was enforced outside the agent's process; an SDK receipt is the agent's own report. The verification column is the offline check any auditor can repeat with the same public keys.</p>`;
  return page(o.title ?? "Receipts", body, staticPage ? SEARCH_SCRIPT : "");
}

/** The explain text as a definition list: question, answer, continuation lines kept with their answer. */
function explainHtml(text: string): string {
  const items: { q: string; a: string[] }[] = [];
  for (const line of text.split("\n")) {
    const q = line.slice(0, 28).trim();
    const a = line.slice(28).trimEnd();
    if (q && /^[A-Z][A-Z ?]+$/.test(q)) items.push({ q, a: [a] });
    else if (items.length) items[items.length - 1]!.a.push(a);
  }
  return `<dl>${items.map((i) => `<dt>${esc(i.q)}</dt><dd>${esc(i.a.join("\n"))}</dd>`).join("")}</dl>`;
}

/** One receipt's page: the ten answers, the verification report, and the receipt itself. */
export function renderReceipt(pack: ActionPack, verification: VerifyResult | null, o: ReviewOptions, backLink: string, rawLink: string): string {
  const p = decodeStatement(pack.receipt).predicate;
  const report = verification ? verification.checks.map((c) => `${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`).join("\n") + `\n\nRESULT: ${verification.ok ? "VERIFIED" : "NOT VERIFIED"}` : "Not checked: start the review with --issuer-key and --principal-key to verify every receipt here.";
  const body = `
<p><a href="${esc(backLink)}">All receipts</a></p>
<h1>${esc(p.tool.name)} <span class="muted">${esc(p.execution.status)}</span></h1>
<p class="sub">${esc(p.timestamp.replace("T", " ").slice(0, 19))} · receipt <span class="mono">${esc(p.receiptId)}</span> · ${verification ? (verification.ok ? '<span class="ok">verified</span>' : '<span class="bad">NOT VERIFIED</span>') : '<span class="muted">not checked</span>'}</p>
<h2>What this action is</h2>
${explainHtml(formatExplain(pack, verification, !!o.ledger))}
<h2>Verification</h2>
<pre>${esc(report)}</pre>
<h2>The receipt</h2>
<p><a href="${esc(rawLink)}">The bundle as issued</a>, which any verifier checks with <code>agent-custody verify</code> and the public keys.</p>
<h2>Hand this case to another reviewer</h2>
<p><a download href="${esc(rawLink.replace(/\.json$/, '.case.html'))}">Download offline case file</a> · <a download href="${esc(rawLink.replace(/\.json$/, '.case.json'))}">Case data (JSON)</a></p>
<p>The case file contains the receipts, signed authorizations, public keys, log heads and verification report. Open it in a browser offline to repeat the cryptographic checks. Compare its public key fingerprints with a trusted source.</p>`;
  return page(`${p.tool.name} · ${p.receiptId.slice(0, 8)}`, body);
}

function verifyOf(bundle: ReceiptBundle, o: ReviewOptions): VerifyResult | null {
  return o.keys ? verifyBundle(bundle, o.keys) : null;
}

/** Serves the review on loopback: / is the index, /r/<id> a receipt, /r/<id>.json the bundle. */
export function reviewHandler(o: ReviewOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const send = (status: number, type: string, body: string, caseFile = false) => {
      res.writeHead(status, { "content-type": type, "cache-control": "no-store", "x-frame-options": "DENY", "x-content-type-options": "nosniff", ...(caseFile ? { "content-disposition": `attachment; filename="${url.pathname.split('/').at(-1)}"` } : { "content-security-policy": REVIEW_CSP }) });
      res.end(body);
    };
    try {
      if (url.pathname === "/") {
        const search = { ...o.search };
        for (const name of ['transaction', 'customer', 'agent', 'from', 'to'] as const) {
          if (!url.searchParams.has(name)) continue;
          const value = url.searchParams.get(name)!.trim();
          if (value) search[name] = value;
          else delete search[name];
        }
        try { validateReceiptSearch(search); } catch (e) { return send(400, "text/plain", e instanceof Error ? e.message : String(e)); }
        return send(200, "text/html; charset=utf-8", renderIndex(listReceipts(o, search), { ...o, search }, (id) => `/r/${id}`));
      }
      const m = /^\/r\/([0-9a-f-]{36})(\.case\.(?:html|json)|\.json)?$/.exec(url.pathname);
      if (!m) return send(404, "text/plain", "not found");
      if (m[2]?.startsWith('.case.')) {
        const file = await buildCaseFile(o, m[1]!);
        return send(200, m[2].endsWith('html') ? "text/html; charset=utf-8" : "application/json", m[2].endsWith('html') ? renderCaseFile(file) : JSON.stringify(file, null, 2), true);
      }
      if (m[2]) return send(200, "application/json", readFileSync(join(o.receiptsDir, `${m[1]}.json`), "utf8"));
      const pack = await buildActionPack(o.receiptsDir, m[1]!, o.ledger);
      return send(200, "text/html; charset=utf-8", renderReceipt(pack, verifyOf(pack.receipt, o), o, "/", `/r/${m[1]}.json`));
    } catch (e) {
      return send((e as NodeJS.ErrnoException).code === "ENOENT" ? 404 : 500, "text/plain", e instanceof Error ? e.message : String(e));
    }
  };
}

export interface RunningReview {
  url: string;
  close(): Promise<void>;
}

export function serveReview(o: ReviewOptions, opts: { port: number; host?: string }): Promise<RunningReview> {
  const host = opts.host ?? "127.0.0.1";
  const handler = reviewHandler(o);
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  return new Promise((resolve) => {
    server.listen(opts.port, host, () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://${host}:${port}/`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

/** Writes the same pages as static files: index.html, and r/<id>.html with r/<id>.json beside it. For a case file or a shared drive. */
export async function writeReview(o: ReviewOptions, outDir: string): Promise<{ receipts: number }> {
  mkdirSync(join(outDir, "r"), { recursive: true });
  const rows = listReceipts(o);
  writeFileSync(join(outDir, "index.html"), renderIndex(rows, o, (id) => `r/${id}.html`, true));
  for (const r of rows) {
    const file = await buildCaseFile(o, r.receiptId);
    const pack = file.pack;
    writeFileSync(join(outDir, "r", `${r.receiptId}.html`), renderReceipt(pack, verifyOf(pack.receipt, o), o, "../index.html", `${r.receiptId}.json`));
    writeFileSync(join(outDir, "r", `${r.receiptId}.json`), JSON.stringify(pack.receipt, null, 2));
    writeFileSync(join(outDir, "r", `${r.receiptId}.case.json`), JSON.stringify(file, null, 2));
    writeFileSync(join(outDir, "r", `${r.receiptId}.case.html`), renderCaseFile(file));
  }
  return { receipts: rows.length };
}
