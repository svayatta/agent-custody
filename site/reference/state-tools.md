# Explain, review, packs, blast radius, evals, retention

The commands that turn a receipts directory and a ledger into something a reviewer, counsel, or an auditor can hold. All in `@agent-custody/state`, as the `agent-custody-memory` command and as functions.

## `explain`

One action, answered from a receipt and, with a ledger, the beliefs around it.

```bash
agent-custody-memory explain --receipts receipts --receipt <receiptId> [--ledger ledger.sqlite] [--issuer-key gateway.pub] [--principal-key principal.pub] [--log-key log.pub] [--json]
agent-custody-memory explain … --out action.json --sign action.key      # the same as one signed action pack
agent-custody-memory explain --verify action.json --key action.pub [--issuer-key …] [--principal-key …] [--log-key …]
```

The text output is ten answers, one per line: `WHO`, `WHO AUTHORIZED IT`, `WHAT WAS ALLOWED`, `WHAT THE AGENT SAW`, `WHAT IT DID`, `WHY`, `WHAT EVIDENCE`, `CAN I VERIFY IT`, `DID ANYTHING DEPEND ON THIS`, `WHAT NEEDS REVERSAL`. Without a ledger the last two say so rather than pretending. The JSON, and the signed pack's payload:

```json
{ "version": "0.1", "generatedAt": "…", "receiptId": "…", "receipt": { "…": "the bundle" },
  "consumed": { "facts": [ {…} ], "unknown": ["<factId>"] },
  "written": [ {…} ], "status": { "<factId>": "believed" | "retracted" | "forgotten" | "superseded" },
  "downstream": { "receipts": [{ "receiptId", "timestamp", "tool", "status", "consumed": [] }], "derivedFacts": [ {…} ], "stillBelieved": [ {…} ] },
  "receipts": { "<receiptId>": { "…": "every downstream bundle" } }, "missingReceipts": [] }
```

In code: `buildActionPack(receiptsDir, receiptId, ledger?)`, `signActionPack(pack, key): Envelope` (type `https://agent-custody.dev/action-pack/v0.1`), `verifyActionPack(envelope, packKeys, receiptKeys?)` which checks the pack's signature, the receipt inside, and every downstream receipt, and `formatExplain(pack, verification, withLedger)`.

## `review`

Search receipts and read the ten answers in a browser, then export a portable case for another reviewer.

```bash
agent-custody-memory review --receipts receipts [--ledger ledger.sqlite] [--issuer-key …] [--principal-key …] [--log-key …] [--upstream-key …] [--log-id …] [--port 8791] [--host 127.0.0.1] [--title "Support agents, September"]
agent-custody-memory review … [--transaction re_123] [--customer cust_123] [--agent support-agent] [--from 2026-10-01T00:00:00Z] [--to 2026-10-31T23:59:59Z]
agent-custody-memory review … --out review-site/
agent-custody-memory review … --case <receiptId> --out refund.case.html
agent-custody-memory review … --case <receiptId> --out refund.case.json
agent-custody-memory review --verify-case <refund.case.json|refund.case.html> [--issuer-key …] [--principal-key …] [--log-key …] [--upstream-key …] [--log-id …] [--json]
```

Serves on `127.0.0.1` by default, with no login of its own. The pages load no outside content. The index shows when, tool, outcome, transaction and customer ids, agent, principal, producer, and verification verdict. Search filters combine with AND; ids and agent ids are exact and case sensitive. `from` and `to` are inclusive ISO 8601 date-times with `Z` or an explicit UTC offset, and an inverted or invalid range is rejected. Search reads only the public signed view: named identifiers in arguments, results (including complete JSON objects in MCP text), and gateway facts. It does not search prose or restore values withheld by a capture rule. Search stops at 64 levels of nesting and ignores JSON text longer than 64 KiB. A record whose receipt id differs from its file name is listed as NOT VERIFIED ("file name does not match receipt id") and linked by file name, and the header counts the files that cannot be read.

| route | response |
| --- | --- |
| `GET /` | receipt index and search form |
| `GET /?transaction=re_123&customer=cust_123&agent=support-agent&from=2026-10-01T00:00:00Z&to=2026-10-31T23:59:59Z` | matching receipt rows; each query parameter is optional |
| `GET /r/<receiptId>` | ten answers, verification report, bundle and case downloads |
| `GET /r/<receiptId>.json` | bundle as issued |
| `GET /r/<receiptId>.case.html` | standalone offline HTML case download |
| `GET /r/<receiptId>.case.json` | portable case data download |

`--out <dir>` writes `index.html`, `r/<id>.html`, `r/<id>.json`, `r/<id>.case.html`, and `r/<id>.case.json`. CLI filters decide which receipts enter an export; the static index filters only that exported set in the browser, including when opened locally. `--case <receiptId> --out <file.html|file.json>` exports one case directly.

A case carries the action pack's primary, belief-source, and downstream receipt bundles, embedded signed authorizations, log heads and inclusion proofs, the supplied public keys with SHA-256 fingerprints, the ten answers, and the ledger snapshot when provided. The HTML embeds the verifier and uses WebCrypto to check signatures, digests, authorizations, and inclusion proofs afresh when opened; it makes no external requests. Its historical export report is not accepted as verification evidence. The page result is not independent, because the script is in the same file as the data; the page says so, and it does not compare the ten answers with the receipts. Use `--verify-case` for that. Without a ledger, belief dependencies remain `unknown without a ledger`; withheld evidence and missing receipts remain explicit.

Confirm the public key fingerprints through an independent trusted source before relying on their identity: bundled keys prove internal consistency. `--verify-case` recomputes verification from the JSON or from the `case-data` script of a `.case.html`, uses bundled keys by default, and exits 1 on failure. It rebuilds the ten answers from the signed receipt and fails the check `ten answers match the signed receipt` when the saved `explanation` differs. Independent key flags replace the entire bundled trust set, so provide all issuer, principal, log, and upstream keys that the case requires; the key flags may be repeated for rotations. The JSON report includes `ok`, `complete`, `trust` (`bundled`, `independent`, or `none`), `checks`, and a verification report per receipt. `complete` requires a ledger and no missing receipts, unknown consumed beliefs, or withheld dependency evidence; it does not attest the ledger snapshot. The ledger data is an unsigned exporter assertion. The ten answers are checked against the signed receipt, but the belief answers still rest on that ledger data. Cryptographic verification establishes what the signed gateway record says and detects receipt tampering; it does not independently prove an external payment side effect. Export reads no private key, capture key, disclosure, or issuer salts file, and withheld values stay unavailable.

In code:

```ts
import { loadPublicKey } from "@agent-custody/receipts";
import { buildCaseFile, listReceipts, renderCaseFile, verifyCaseFile } from "@agent-custody/state";

const keys = {
  issuerKeys: [loadPublicKey("keys/gateway.pub")],
  principalKeys: [loadPublicKey("keys/principal.pub")],
};
const options = { receiptsDir: "receipts", keys }; // add ledger to answer belief dependency questions
const rows = listReceipts(options, { transaction: "re_123", customer: "cust_123" });
const file = await buildCaseFile(options, rows[0]!.receiptId);
const checked = verifyCaseFile(file, keys);
const html = renderCaseFile(file);
```

`ReviewOptions` accepts `receiptsDir`, optional `ledger`, `keys`, `title`, and `search: ReceiptSearch`. `keys` contains `issuerKeys`, `principalKeys`, and optional `logKeys`, `upstreamKeys`, and `logId`. `listReceipts(options, query = options.search ?? {})` returns newest-first rows with `transactionIds` and `customerIds` alongside the receipt fields and verdict. A row has `file` (the file name without `.json`, which links use) and, for a record that does not match its file name, `problem` and `verified: false`. `scanReceipts(options, query)` returns `{ rows, unreadable }`, where `unreadable` counts the files that could not be decoded. `ReceiptSearch` has optional string fields `transaction`, `customer`, `agent`, `from`, and `to`; `validateReceiptSearch(query)` rejects invalid filters, `receiptSearchTerms(predicate)` returns public `transactionIds` and `customerIds`, and `matchesReceiptSearch(predicate, query)` applies the combined filters.

`buildCaseFile({ receiptsDir, ledger?, keys? }, receiptId): Promise<CaseFile>` constructs the portable case. `verifyCaseFile(file, trustedKeys?): CaseFileVerification` reruns verification, `parseCaseFile(text): CaseFile` reads case JSON or a rendered `.case.html` (it does not validate; `verifyCaseFile` does), and `renderCaseFile(file): string` renders the standalone HTML. `CaseFile` contains `version`, `generatedAt`, `receiptId`, `withLedger`, `pack: ActionPack`, `keys` (public `{ keyid, pem }` arrays by role and optional `logId`), `explanation`, and the export-time `verification`. The page APIs remain `renderIndex(rows, options, link, staticPage?, unreadable?)`, `renderReceipt(pack, verification, options, backLink, rawLink)`, `serveReview(options, { port, host? })`, and `writeReview(options, outDir)`.

[The runnable review example](https://github.com/svayatta/agent-custody/blob/main/packages/state/examples/08-review-console.ts) makes a refund through a real gateway in front of the local fake Stripe server, searches its returned transaction id and customer, and exports and verifies the case without a payment provider.

## `pack`

Everything about one fact as one signed artefact.

```bash
agent-custody-memory pack --ledger ledger.sqlite --receipts receipts --fact <factId> --out pack.json --sign pack.key
agent-custody-memory pack --verify pack.json --key pack.pub [--issuer-key …] [--principal-key …]
```

Payload (type `https://agent-custody.dev/custody-pack/v0.1`): `{ "version": "0.1", "generatedAt", "factId", "fact", "history": [events], "receipts": { "<id>": bundle }, "missingReceipts": [], "blast": {…}, "forget": { "event", "receiptId", "verification", "removedFrom" } | null, "holds": [events] }`. Verification checks the pack's signature and every receipt inside it. In code: `buildPack`, `signPack`, `verifyPack`, `formatPack`.

## `blast`

Everything that relied on a fact: later calls that had been shown it, beliefs derived from it, and whether it was retracted.

```bash
agent-custody-memory blast --ledger ledger.sqlite --receipts receipts --fact <factId> [--capture-key-env NAME] [--json]
```

`{ "factId", "retracted": boolean, "consumers": [{ "receiptId", "timestamp", "tool", "status" }], "derived": [ facts ], "stillBelieved": [ facts ], "withheld": [ receipts ] }`. A receipt issued under a [capture rule](./gateway#private-evidence) withholds what the agent had been shown: such a call made since the ledger learned the fact (its assert's transaction time, not its validity) is listed under `withheld`, the text report says `INCOMPLETE` and lists it, and the sets above are incomplete while any is listed; `--capture-key-env` decrypts the ids of receipts in mode `encrypted` so the query sees through. In code: `blastRadius(ledger, loadReceipts(dir, { captureKey? }), factId)`; a summary carries `consumedWithheld`. `explain` and `pack` take `--capture-key-env` the same way: it opens the explained receipt's own consumed ids too, and without it the action pack's `consumedWithheld` is true and the report says so. An action pack's `downstream.withheld` and the custody pack's `blast.withheld` list the calls the query could not see, which `formatExplain` and `formatPack` print as `INCOMPLETE`. The authorization file beside a pre-committed receipt is not read as a second receipt.

## `eval`

Scores a memory system on stale reads, contradictions, blast radius, and correct reads over scripted incidents.

```bash
agent-custody-memory eval [--scenarios scenarios.json] [--baseline] [--json] [--sign eval.key --out report.json]
agent-custody-memory eval --verify report.json --key eval.pub
```

Report: `{ "scenarios": [{ "name", "reads", "staleReads", "contradictions", "blastRadius", "correctReads", "failures": [] }], "totals": {…} }`; `--baseline` scores a naive overwrite store beside the ledger; exit 1 if the ledger regresses. In code: `runAll(system, scenarios)`, `runScenario`, `formatReport`.

## `sweep` and `export`

```bash
agent-custody-memory sweep --via gateway.json --reason "90-day retention" [--before <ISO>] [--space team:support] [--no-digest]
agent-custody-memory sweep --ledger ledger.sqlite --before <ISO> --reason "…" [--space …] [--actor …] [--forget-key-env NAME] [--no-digest]
agent-custody-memory export --ledger ledger.sqlite --out ledger.jsonl
```

`--via` runs `memory.sweep` through a gateway as the principal in its grant, so the sweep is a receipted call; put it on a timer. The ledger-only form is for ledgers with nothing in front of them. `export` writes the auditable JSONL of any ledger, one event per line, which is also the feed for a warehouse.
