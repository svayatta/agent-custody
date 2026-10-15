# Verify, audit, export

A receipt is verified with public keys alone: no server, no account, no trust in whoever handed it over. The [verification guide](https://agent-custody.dev/receipts/verification) explains what each check proves; this page is the interface.

## `verify`

```bash
agent-custody verify receipts/<id>.json --issuer-key keys/gateway.pub --principal-key keys/principal.pub [--log-key log.pub | --log-url https://log.example.com/] [--log-id acme] [--upstream-key upstream.pub] [--stripe-secret-env NAME] [--github-secret-env NAME] [--log log.jsonl] [--disclose disclosure.json] [--capture-key-env NAME] [--json]
```

| option | meaning |
| --- | --- |
| `--issuer-key` (repeatable) | keys trusted to issue receipts: gateway keys, SDK application keys. `--gateway-key` is an alias |
| `--principal-key` (repeatable) | keys whose grants are accepted; may be omitted for SDK receipts |
| `--log-key` / `--log-url` | the key of a log run by someone else, given as a file or fetched from the log's key document and pinned by keyid |
| `--log-id` | every tree head must name this log |
| `--upstream-key` | an upstream that signs its results; the execution then verifies as attested |
| `--stripe-secret-env`, `--github-secret-env` | shared secrets for provider deliveries carried in the receipt |
| `--log` | a copy of the log file; the root is recomputed at the receipt's tree size and compared |
| `--disclose` | a disclosure file, `{ "receiptId", "args"?, "result"?, "facts"?: { "<name>": { "value"?, "args"? } }, "upstreamRawBody"? }`, holding the values a capture rule withheld, as `reveal` writes it or as the party that holds them hands it over; each value is checked against its commitment and the digests are recomputed from it |
| `--capture-key-env` | the environment variable holding the customer's capture key; encrypted fields are decrypted, checked against their commitments, and the digests recomputed |
| `--json` | machine-readable output |

Exit 0 when every check passes, 1 otherwise. The text report is one line per check, `PASS`/`FAIL`, the name, and a detail, ending in `RESULT: VERIFIED` or `RESULT: NOT VERIFIED`. The JSON:

```json
{ "ok": true, "checks": [{ "name": "receipt signature (issuer key)", "ok": true, "detail": "keyid 9d442884f3d4" }, { "name": "delegation signature (principal key)", "ok": true, "detail": "signed by 19b2d2a2a213" }, …], "statement": { "…": "the decoded statement" } }
```

In code: `verifyBundle(bundle, { issuerKeys, principalKeys, logKeys?, upstreamKeys?, providerSecrets?, logFile?, logId?, disclosed?, captureKey? }): { ok, checks, statement }` and `formatReport(result): string`. Keys are `PublicKeyRef`s from `loadPublicKey(path)` or `publicKeyFromPem(pem)`; `fetchLogKeys(url)` returns `{ doc, keys }` from a key document.

### The checks

| check | proves |
| --- | --- |
| receipt signature (issuer key) | the bundle was signed by a trusted issuer key; nothing else is decided if this fails |
| receipt payload type | it is an in-toto statement with the receipt predicate type |
| issuer kind is known, issuer keyid matches signer | the receipt says who issued it and the signature agrees |
| gateway receipt carries a delegation, carries a policy decision | gateway receipts embed both |
| delegation signature (principal key) | the grant was signed by a trusted principal key |
| delegation chain to the principal | only for chained grants: every link signed by the key its parent names, no scope escalation, nested windows, one principal |
| delegation binds principal and agent, valid at receipt time | the grant is for this principal and agent and the receipt's time is inside its window |
| executed tool within delegated scope | if the tool ran, the grant covered it |
| principal is claimed, not attested | SDK receipts: the principal is a config string and labelled so |
| request args digest | the arguments match their digest and the statement's subject: recomputed when they are in clear, disclosed with `--disclose`, or decrypted with `--capture-key-env`; when fields are withheld and neither is given it passes as committed, the detail saying "committed, not recomputed" and how many fields are withheld; a disclosure that contradicts a commitment fails it with the field named |
| execution result digest | executed and failed calls: the result matches `execution.resultDigest`, under the same rules; a provider delivery withheld with the result is restored first |
| fact `<name>` value, fact `<name>` args | a captured fact's commitments hold against the disclosed or decrypted value, or pass as committed when neither is given |
| upstream signature (upstream key), upstream signature (provider secret) | the upstream's signature over the result verifies when a key is given; a Stripe or GitHub delivery verifies when its secret is given |
| upstream signature not checked | only when the result is withheld and a key or secret was given: the signature cannot be checked against a result the verifier cannot see, so this passes with a note in place of the signature check |
| policy decision consistent with execution | an enforced `deny` never sits beside `executed`; a `deny` with `enforced: false` (observe mode) may, and the detail says so |
| authorization … (five checks) | pre-committed calls: the authorization verifies, names this call, was allowed, is included in the log, and precedes the receipt leaf |
| tree head signature, tree head names the expected log | the head was signed by an issuer or log key, and by the log the verifier expected |
| log inclusion proof | the leaf is in the tree the head describes |
| log file root matches | with `--log`, the copy's root at that size equals the head's |

## `reveal`

The values a receipt withheld under a capture rule in mode `encrypted`, as a disclosure file for `verify --disclose`. Needs the customer's capture key.

```bash
agent-custody reveal receipts/<id>.json --capture-key-env AGENT_CUSTODY_CAPTURE_KEY [--out disclosure.json]
```

| option | meaning |
| --- | --- |
| `--capture-key-env` | the environment variable holding the 32-byte key, 64 hex characters or base64; never the key itself |
| `--out` | where to write the disclosure; without it, stdout |

Output, `{ "receiptId", "args"?, "result"?, "facts"? }`, every encrypted part decrypted and checked against its commitment:

```json
{ "receiptId": "36c85dc9-…", "args": { "customer_id": "cust_123", "amount": 2500, "reason": "customer called from +44 20 7946 0000 about the card ending 4242" }, "facts": { "customer": { "id": "cust_123", "email": "alex@example.com", "verified": true } } }
```

A part withheld as a digest only carries no value to reveal: it is left out of the file, and the command says which (`Not revealed, withheld without a value: result; only the party that holds them can disclose them`). A key other than the one a part was encrypted under reveals nothing of it, and the part is listed the same way; a decrypted value that does not match its commitment is an error. Exit 0; with `--out` the command prints where the file went and the `verify --disclose` option that reads it. In code: `restore(view, disclosed?, key?)` and `reveal(commitment, key)`, on the [SDK](./sdk-typescript#private-evidence) page.

## `audit`

Proves that nothing between two receipts was rewritten: the newer receipt's tree head extends the older one's.

```bash
agent-custody audit --older receipts/<earlier>.json --newer receipts/<later>.json (--log log.jsonl | --log-url <url>) [--issuer-key <pub>] [--log-key <pub>] [--log-id <id>] [--witness-key <pub> | --witness-url <url>] [--json]
```

`--older` and `--newer` accept receipt bundles or checkpoint files. With `--log-url` the consistency proof is fetched from `GET /consistency` and the keys from the key document; with `--log` both come from the file. With a witness key or URL the newer head must also carry the witness's countersignature. JSON: `{ "ok", "checks", "older": <tree head>, "newer": <tree head> }`. In code: `auditExtends(olderEnvelope, newerEnvelope, proofHashes, keys, logId?, { witnessKeys? })`.

## In the browser

[agent-custody.dev/verify](https://agent-custody.dev/verify) runs the same checks in the page with the Web Crypto API; a receipt dropped on it never leaves the browser. `/verify?sample=<vector name>` loads that conformance vector with its keys and verifies it on arrival; `/verify?receipt=<id>` opens one of the site's own receipts from `/custody/<id>.json` with the agent's key and the log's key and verifies it at once; only that path on that origin is ever fetched. It passes every published [conformance vector](https://agent-custody.dev/receipt/vectors), as the package does.

## `log-check`

The outside monitor, on the [log API page](./log-api#monitoring).

## `log-export`

A tenant's own log, with their token, self-checked:

```bash
agent-custody log-export --log-url https://log.example.com/ --tenant acme --token-env AGENT_CUSTODY_LOG_TOKEN --out custody-export/ [--month 2026-09]… [--json]
```

| file | contents |
| --- | --- |
| `log.jsonl` | every leaf hash as `{"hash":"…"}` lines: a log copy `verify --log` and `audit --log` read with no server |
| `head.json` | the signed head and its decoded fields |
| `keys.json` | the log's key document at export time |
| `checkpoints.json` | every published checkpoint for the tenant |
| `usage.json` | appends per month, plan, quota, live keys |
| `audit.json` | every administrative action on the tenant |
| `policies.json` | the policy versions the tenant published, each with its name, text, and the digest receipts carry |
| `export.json` | the summary: `{ "exportedAt", "logUrl", "tenant", "logId", "treeSize", "rootHash", "keyid", "checkpoints", "audit", "usage", "problems": [] }` |

Before writing, the export checks that the head verifies against the published keys, that the leaves fetched hash to the head's root, and that every checkpoint verifies and matches the leaves at its size. Anything that does not add up is listed under `problems`, the command exits 1, and the report ends `RESULT: EXPORT DOES NOT ADD UP`. In code: `exportLog({ logUrl, tenant?, token, outDir, months?, fetch? }): Promise<ExportResult>` and `formatExport(result)`.
