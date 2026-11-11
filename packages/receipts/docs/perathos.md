# Reading a Perathos log

[Perathos](https://github.com/perathos-protocol/perathos) records an agent's tool calls from hooks inside the agent's host (Claude Code, Cursor, or its MCP proxy), hash-chains them into a session log, and seals turns with Ed25519 checkpoints. `agent-custody verify-perathos` checks such a log against the verification rules of the Perathos receipt spec (`docs/specs/RECEIPT_V1.md` in their repository), so an auditor can check either project's records with one tool. The reader was written from that spec alone, not from Perathos code.

The two formats record different things, and the report says which one it read. This page lists what the reader checks, what a valid log proves, and how the fields of the two formats correspond.

## Run it

```bash
agent-custody verify-perathos .perathos/sessions/<session>.jsonl \
  --key <recorder public key, 64 hex> \
  --head .perathos/sessions/<session>.head.json
```

```text
PASS  every line is a JSON object
PASS  format is perathos.receipt/v1 with a known kind
PASS  seq is 1, 2, 3, ... in file order
PASS  prev_hash chains each receipt to the one before
PASS  receipt_hash recomputes
PASS  one session, and time never goes back
PASS  checkpoint signatures verify
PASS  every checkpoint is signed
PASS  every signer is a trusted key
PASS  the head witness's checkpoint is in the log

RESULT: VALID

session         replay
receipts        7 (3 tool calls, 2 checkpoints)
sealed          through seq 7
signers         be58168fa007
time            2026-11-04T08:19:00.000000Z to 2026-11-04T08:19:06.000000Z (host clock)
denied          1 call(s) stopped by the guard

PROVENANCE: perathos.receipt/v1, recorded by hooks inside the agent's host (claude-code); the checkpoint key is held on that host, so a valid log shows that the key holder sealed this sequence, not that an enforcement point outside the agent saw each call; times are the host's clock, and RFC 3161 anchors were not checked
```

| flag | effect |
| --- | --- |
| `--key <hex>` | pins the recorder's Ed25519 public key (repeatable); a checkpoint signed by any other key fails |
| `--head <file>` | the head witness, `{ "seq", "receipt_hash" }` of the latest checkpoint; a log cut back to an earlier checkpoint fails |
| `--allow-unsigned` | accepts a log with no checkpoint, or an unsigned one, and reports each as a warning |
| `--json` | the report as JSON |

It exits 0 when the log is valid and 1 when it is not. Receipts after the last checkpoint are reported as an unsealed tail, not an error, because the session may still be running. From code: `verifyPerathosLog(text, { trustedKeys?, allowUnsigned?, head? })` and `formatPerathosReport(report)`.

## What it checks

Rules 1 to 9 of the spec:

1. Every line is a JSON object, `v` is `perathos.receipt/v1`, and `kind` is `pre`, `post`, or `checkpoint`.
2. `seq` runs 1, 2, 3, and so on in file order.
3. Each `prev_hash` is the previous receipt's `receipt_hash`, and the first is 64 zeros.
4. Each `receipt_hash` recomputes: SHA-256 of the canonical JSON of every field except `receipt_hash` and `signature`, known fields or not.
5. One `session_id` throughout, and `ts` never goes back.
6. Every checkpoint signature verifies: Ed25519 over the 32 raw bytes of `receipt_hash`, by the key in `signer`, which `signature.verify_key` must equal.
7. At least one checkpoint, and every checkpoint signed. A checkpoint with `signer_error` is named as a signer failure, which explains a missing signature and does not excuse it.
8. With `--key`, every signer is a pinned key.
9. With `--head`, the log holds the head witness's checkpoint.

## What a valid log proves

The holder of the checkpoint key sealed this exact sequence, and nothing up to the last checkpoint was edited, removed, inserted, or reordered since. Whoever holds a call's arguments or result can show that they match the recorded hash.

It does not prove that an enforcement point outside the agent saw each call. The recorder runs in the agent's host and the key sits there, so the log is as trustworthy as that host. Times are the host's clock. The `model` field is self-reported. The spec lists the rest, including a recorder that was not running for part of a session.

## How the two formats correspond

| Perathos `receipt/v1` | agent-custody receipt | note |
| --- | --- | --- |
| `agent` | `issuer.kind` | Perathos names the recording integration; agent-custody names the issuer kind and what it is worth ([verification](verification.md)) |
| `session_id`, `tool_use_id` | `session.id`, `session.toolUseId` | both are the host's correlation ids; agent-custody marks them `claimed` |
| `seq`, `prev_hash` | leaf index in the RFC 9162 log | a per-session hash chain against one Merkle log; agent-custody proves inclusion with an inclusion proof, Perathos by walking the chain |
| `receipt_hash` | the leaf hash of the DSSE envelope | both SHA-256 over canonical JSON |
| `checkpoint` with `signature` | the signed tree head in each bundle | Perathos signs checkpoints only; agent-custody signs every receipt and every tree head |
| `pre` / `post` | one receipt with `request` and `outcome` | Perathos writes a call as two receipts linked by `tool_use_id` |
| `tool`, `args_hash`, `result_hash` | `tool.name`, `request.argsDigest`, `outcome.resultDigest` | agent-custody can also carry the arguments, or withhold a field behind a salted commitment or an encrypted value ([private evidence](usage.md#private-evidence)) |
| `status` | `outcome.status` | `ok` or `error` against `executed`, `failed`, `denied`, `error`, or `withheld` |
| `model` | `model.id` | self-reported in both; agent-custody marks it `claimed` |
| `guard.decision`, `guard.rule` | `policy.decision`, `policy.reasons`, `policy.policyDigest` | a guard rule against a Cedar or Rego policy pinned by its digest |
| `guard.precondition` (a person-signed safety check) | `delegation` (a principal-signed grant) and `approval` (a payload-bound approval) | both are authority signed by someone other than the agent |
| `perathos.anchor/v1` (RFC 3161) | the log's checkpoints, witness, and chain anchor ([anchoring](anchoring.md)) | independent time against an independent copy of the log head |

Both use Ed25519, SHA-256, and canonical JSON with sorted keys that matches RFC 8785 for these bodies. The structures differ, so a shared schema would lose detail on both sides. The common ground both can map to is IETF SCITT ([aligning with SCITT](scitt.md)).

## Not read yet

- RFC 3161 anchors (`perathos.anchor/v1`): verifying a timestamp token means parsing the authority's signed response and chaining it to a pinned root certificate.
- Perathos evidence packs, which bundle logs, anchors, and preconditions.
- Signed preconditions (`perathos.precondition/v1`) and Gate approvals.

The tests in `test/perathos.test.ts` write logs from the spec. Example 45 does the same and shows a cut log caught by its head witness and an edited guard decision caught by the chain.
