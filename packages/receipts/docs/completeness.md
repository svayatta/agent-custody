# Completeness: matching the provider's records against the receipts

A verified receipt proves what went through the gateway. Nothing on the gateway's side can see an action that never went through it: whoever holds the Stripe key can issue a refund straight through Stripe's API. The provider's own record is the only place that action shows. `agent-custody completeness` lets an auditor check it, with a read-only key of their own.

## What it reports

For a window and a set of tools, it lists the provider's objects and matches each to a verified receipt by the provider's object id, which the receipt's result carries.

| section | meaning | what to do |
| --- | --- | --- |
| provider actions with no receipt | an object the provider created in the window that no verified receipt names | the finding this command exists for: an action taken outside the gateway, or by a gateway whose receipts you were not given |
| receipts the provider does not have | an executed receipt in the window whose object the provider has no record of | a receipt for something that did not happen at the provider, or an object in another account or mode |
| mismatches | a matched pair whose amount, currency (ignoring case), or a beneficiary field differs | the receipt and the provider disagree about what happened |
| forwarded without an outcome receipt | a call committed to the log before it was forwarded (`precommit`) whose outcome receipt is missing | the gateway stopped after forwarding; this explains a provider object that has no receipt, without guessing which one |
| unmatchable | a verified, executed receipt whose provider id cannot be read, usually because a capture rule withholds the result | match it by hand against the values disclosed with `agent-custody reveal` |
| not verified | a receipt file that failed verification | it is not matched, so its provider object shows as having no receipt |

The result is `COMPLETE` only when every section but the matches is empty, and the command exits 1 otherwise.

Only receipts that verify against the keys you give are matched. A forged or edited receipt file cannot cover for a provider action, because it fails verification and its object then appears as having no receipt. Denied, withheld, and failed calls are not expected to have a provider object, and reconciliation receipts are skipped, because the original receipt is the one that names the object.

The provider is listed fifteen minutes either side of the window (`marginMs` in code), so a receipt signed just inside the window still finds an object created just outside it. Only objects and receipts inside the window are reported.

## Running it

```bash
export STRIPE_AUDIT_KEY=rk_live_...   # a restricted key with read access to refunds, held by the auditor
agent-custody completeness --receipts ./receipts --issuer-key gateway.pub --principal-key principal.pub \
  --log log.jsonl --provider stripe --object refunds --key-env STRIPE_AUDIT_KEY \
  --tool stripe.refund --since 2026-10-01T00:00:00Z --until 2026-11-01T00:00:00Z
```

| flag | default | meaning |
| --- | --- | --- |
| `--receipts <dir>` | | the auditor's copy of the receipts directory, authorization files included |
| `--issuer-key`, `--principal-key`, `--approval-key`, `--log-key`, `--log`, `--log-id` | | how each receipt is verified, as for `verify` |
| `--provider stripe` | | the provider; Stripe is the only one so far |
| `--object` | `refunds` | `refunds`, `payouts`, or `transfers` |
| `--key-env NAME` | | the environment variable holding the read-only key; never a flag value |
| `--tool <name>` | | each tool whose executed calls create provider objects; repeatable |
| `--since`, `--until` | | the window, ISO times; `--until` is exclusive |
| `--id-path` | `id` | where the provider's object id sits in the JSON of the result's first text item; Stripe's own response uses `id` |
| `--amount-field`, `--currency-field` | `amount`, `currency` | the call arguments compared with the provider's amount and currency |
| `--beneficiary <arg>=<field>` | | a call argument that must equal a provider field, such as `charge=charge` or `customer_id=metadata.customer_id`; repeatable |
| `--json` | | the full report as JSON |

Use a restricted Stripe key with read-only access to the objects you check. The command only lists objects: it never creates, retries, or reconciles anything. The operator's `reconcile` command is a different thing: it settles one financial operation through the gateway and writes a receipt.

## Limits

- **The receipts you were given.** The check proves completeness against those receipts. A second gateway, or a second receipts directory, that issued receipts you were not handed shows up as provider actions with no receipt, which is the correct finding.
- **One provider account and mode per run.** Test-mode and live-mode objects are separate lists.
- **The id must be readable.** A capture rule that withholds the result also withholds the object id inside it, and such receipts are reported as unmatchable, never as matched or missing. Reading the id from disclosed values is still to come.
- **Stripe first.** Other providers, and on-chain transfers from an agent's wallet, are `ProviderSource` implementations still to come.

In code, `checkCompleteness({ receiptsDir, verify, source, tools, sinceMs, untilMs })` returns the report, `stripeSource({ secretKey, object })` lists Stripe objects, and `formatCompleteness(report)` prints it. Example 35 runs the whole check against a stand-in for Stripe's list API.
