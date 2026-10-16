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

The explain output as pages for the reviewer who will not open a terminal.

```bash
agent-custody-memory review --receipts receipts [--ledger ledger.sqlite] [--issuer-key …] [--principal-key …] [--log-key …] [--log-id …] [--port 8791] [--host 127.0.0.1] [--title "Support agents, September"]
agent-custody-memory review … --out review-site/
```

Serves, on loopback with no login of its own, `/` (an index of every receipt: when, tool, outcome, agent, principal, producer, verdict) and `/r/<receiptId>` (the ten answers, the verification report, the bundle at `/r/<receiptId>.json`). `--out` writes the same as `index.html` and `r/<id>.html` beside `r/<id>.json`. In code: `listReceipts`, `renderIndex`, `renderReceipt`, `serveReview`, `writeReview`.

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

`{ "factId", "retracted": boolean, "consumers": [{ "receiptId", "timestamp", "tool", "status" }], "derived": [ facts ], "stillBelieved": [ facts ], "withheld": [ receipts ] }`. A receipt issued under a [capture rule](./gateway#private-evidence) withholds what the agent had been shown: such a call made since the fact existed is listed under `withheld`, the text report says `INCOMPLETE` and lists it, and the sets above are incomplete while any is listed; `--capture-key-env` decrypts the ids of receipts in mode `encrypted` so the query sees through. In code: `blastRadius(ledger, loadReceipts(dir, { captureKey? }), factId)`; a summary carries `consumedWithheld`.

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
