# Completeness

A verified receipt proves what went through the gateway. Nothing on the gateway's side can see an action that never went through it: whoever holds the Stripe key can issue a refund straight through Stripe's API. The provider's own record is the only place that action shows. `agent-custody completeness` lets an auditor check it, with a read-only key of their own. It supports two providers: Stripe and GitHub.

## What it reports

For a window and a set of tools, it lists the provider's objects and matches each to a verified receipt. A gateway receipt matches by the provider's object id, which the receipt's result carries. A door receipt matches by its own receipt id, which the provider object carries (see [Door receipts](#door-receipts)). Each match names the kind of the receipt: `gateway`, `sdk`, or `door`.

| section | meaning | what to do |
| --- | --- | --- |
| provider actions with no receipt | an object the provider created in the window that no verified receipt names, or a second object with an id that a receipt already accounts for | the finding this command exists for: an action taken outside the gateway, or by a gateway whose receipts you were not given |
| receipts the provider does not have | an executed gateway receipt in the window whose object the provider has no record of; a door receipt is never listed here | a receipt for something that did not happen at the provider, or an object in another account or mode |
| mismatches | a matched pair whose amount, currency (ignoring case), or a beneficiary field differs | the receipt and the provider disagree about what happened |
| one provider object, several receipts | more than one verified receipt names the same provider object; each is still compared with it | one action recorded twice, or receipts that contradict each other |
| forwarded without an outcome receipt | a call committed to the log before it was forwarded (`precommit`) whose outcome receipt is missing | the gateway stopped after forwarding; this explains a provider object that has no receipt, without guessing which one |
| unmatchable | a verified, executed receipt whose provider id cannot be read, or whose amount, currency, or beneficiary argument cannot be compared, because a capture rule withholds it | match it by hand against the values disclosed with `agent-custody reveal` |
| not verified | a receipt file that failed verification, or a valid receipt or authorization stored under a name that is not its signed receipt id | it is not matched, so its provider object shows as having no receipt |

The result is `COMPLETE` only when every section but the matches is empty, and the command exits 1 otherwise.

Only receipts that verify against the keys you give are matched. A forged or edited receipt file cannot cover for a provider action, because it fails verification and its object then appears as having no receipt. Denied, withheld, and failed calls are not expected to have a provider object, and reconciliation receipts are skipped, because the original receipt is the one that names the object.

The provider is listed fifteen minutes either side of the window (`marginMs` in code), so a receipt signed just inside the window still finds an object created just outside it. The margin does not widen the period reported on: a pair is reported only when its receipt or its object falls inside the window, and a call forwarded without an outcome only when its authorization was signed inside it.

An authorization is tied to its outcome by the receipt id both of them sign, never by the file name. A valid receipt copied under the name of a missing outcome therefore hides nothing: it is reported as not verified, and the call is still listed as forwarded without an outcome.

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
| `--provider` | | `stripe` or `github` |
| `--object` | `refunds` for Stripe, `pushes` for GitHub | Stripe: `refunds`, `payouts`, or `transfers`. GitHub: `pushes`, `merges`, or `releases` |
| `--repo <owner>/<name>` | | GitHub only: the repository to list |
| `--key-env NAME` | | the environment variable holding the read-only key or token; never a flag value |
| `--tool <name>` | | each tool whose executed calls create provider objects, or each door route that relays them; repeatable |
| `--since`, `--until` | | the window, ISO times; `--until` is exclusive |
| `--id-path` | `id` | where the provider's object id sits in the JSON of the result's first text item, a string or an integer; Stripe's own response uses `id` |
| `--receipt-id-path` | `metadata.agent_custody_receipt` | where a provider object carries the id of the door receipt that relayed its request |
| `--amount-field`, `--currency-field` | `amount`, `currency` | the call arguments compared with the provider's amount and currency; for a door receipt, fields of the JSON request body |
| `--beneficiary <arg>=<field>` | | a call argument that must equal a provider field, such as `charge=charge` or `customer_id=metadata.customer_id`; repeatable |
| `--json` | | the full report as JSON |

Use a restricted Stripe key with read-only access to the objects you check. The command only lists objects: it never creates, retries, or reconciles anything. The operator's `reconcile` command is a different thing: it settles one financial operation through the gateway and writes a receipt.

## Door receipts

A payment can reach Stripe through a site behind the door, and not through the gateway. The door relays the request to the origin, and the origin calls Stripe. The door receipt records the origin's answer only by its size and digest, so it does not hold the Stripe object id. The door sends its receipt id to the origin in the `x-agent-custody-receipt` header. The origin copies that value into the Stripe object:

```js
await stripe.refunds.create({ charge, amount, metadata: { agent_custody_receipt: req.headers["x-agent-custody-receipt"] } });
```

Then give the door route as a tool:

```bash
agent-custody completeness --receipts ./receipts --issuer-key gateway.pub --issuer-key door.pub --principal-key principal.pub \
  --log log.jsonl --provider stripe --object refunds --key-env STRIPE_AUDIT_KEY \
  --tool stripe.refund --tool refund --since 2026-10-01T00:00:00Z --until 2026-11-01T00:00:00Z
```

A refund made through the gateway matches its gateway receipt. A refund made through the door matches its door receipt. A refund made directly against Stripe's API has no tag, and the report shows it as a provider action with no receipt.

What a matched door receipt proves:

- The door received a request on that route, the policy decided it, and the door relayed it to the origin. The arrival fact records who the caller was and how the door checked it.
- The origin answered with a status below 500.
- The Stripe object holds the receipt id. That id is a random UUID that the door made for that one request.

What a matched door receipt does not prove:

- **That the request caused the refund.** The link between them is the origin's word: the origin copies the tag. An origin can put a valid receipt id on a refund that it made for another reason. A second object with an id that is already matched shows as a provider action with no receipt.
- **The amount, without a capture rule.** By default the door withholds the request body, and the comparison is unmatchable. Keep `body` in clear for the route (`capture: { refund: { args: { mode: "digest", clear: ["method", "path", "body"] } } }`) and the amount, currency, and beneficiary fields are compared with the body. These are the body's field names, not Stripe's.
- **That a relayed request made a refund.** A door receipt names no Stripe object, so a door receipt with no matching object is not a finding. The report does not list it as a receipt that the provider does not have.

## GitHub

```bash
export GITHUB_AUDIT_TOKEN=github_pat_...   # a fine-grained token with read-only access to Contents, held by the auditor
agent-custody completeness --receipts ./receipts --issuer-key gateway.pub --principal-key principal.pub \
  --log log.jsonl --provider github --repo acme/shop --object merges --key-env GITHUB_AUDIT_TOKEN \
  --tool github.merge_pull_request --id-path sha --since 2026-10-01T00:00:00Z --until 2026-11-01T00:00:00Z
```

Each run checks one repository and one object kind. Run the command one time for each kind that the agents can do.

| `--object` | what GitHub lists | the id that the receipt must carry | `--id-path` for GitHub's own response |
| --- | --- | --- | --- |
| `pushes` | each push, each force push, and each branch creation, from the repository's activity list | the commit that the branch moved to (`after`) | `object.sha` for a created or updated ref, `commit.sha` for a written file |
| `merges` | each merged pull request, merge queue included, from the same activity list | the commit that the branch moved to: the merge commit | `sha` |
| `releases` | each release, by its publication time, or by its creation time while it is a draft | the release's numeric id | `id` |

GitHub objects have no amount and no currency, so those comparisons do not run. `--beneficiary` compares a call argument with a field of the listed object, for example `--beneficiary tag_name=tag_name` for releases.

Limits that apply to GitHub only:

- **Deleted branches are not supported.** GitHub answers a branch deletion with an empty body, so a receipt carries no identifier that the activity list also has.
- **A branch creation is a push.** GitHub lists a push that creates a branch only as a branch creation, so `pushes` includes each branch creation. A branch that someone creates in the GitHub web interface is listed too.
- **A commit identifies a push.** The id is the commit, not the branch. A receipt accounts for one listed action with its id. When the same commit goes to a second branch, or a force push moves a branch back to it, the report lists that action as a provider action with no receipt. This is correct for an action outside the gateway. When an agent moves two branches to the same commit through the gateway, two receipts name one id: the report lists them under "one provider object, several receipts", and you compare them by hand.
- **GitHub records some pushes twice.** Entries with the same branch, the same two commits, and the same time are read as one push.
- **Releases are slow on a large repository.** GitHub gives no time order for releases, so each run reads every page of them.
- **A push of several commits has one id.** The id is the last commit, which is the commit that the tool's result must carry.
- **Draft releases.** GitHub shows a draft release only to a token with write access. A read-only token lists published releases.
- **Tags are not listed.** The activity list covers branches.

## Limits

- **The receipts you were given.** The check proves completeness against those receipts. A second gateway, or a second receipts directory, that issued receipts you were not handed shows up as provider actions with no receipt, which is the correct finding.
- **One provider account and mode per run.** Test-mode and live-mode objects are separate lists.
- **The id must be readable.** A capture rule that withholds the result content also withholds the object id inside it, and such receipts are reported as unmatchable, never as matched or missing. A rule that keeps `content` in clear (`result: { mode: "digest", clear: ["content"] }`) leaves the id readable. Likewise, keep the amount, currency, and beneficiary arguments in clear, or those comparisons are reported as unmatchable. Reading values from disclosures is still to come.
- **Door receipts are matched from the provider's side only.** See [Door receipts](#door-receipts).
- **Stripe and GitHub.** Other providers, and on-chain transfers from an agent's wallet, are `ProviderSource` implementations still to come.

In code, `checkCompleteness({ receiptsDir, verify, source, tools, sinceMs, untilMs, receiptIdPath })` returns the report, `stripeSource({ secretKey, object })` lists Stripe objects, `githubSource({ token, repo, object })` lists GitHub objects, and `formatCompleteness(report)` prints it. Example 35 runs the whole check against a stand-in for Stripe's list API, and example 53 runs it against a stand-in for GitHub's activity list.
