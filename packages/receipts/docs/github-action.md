# Verifying receipts on a pull request

A pull request is where a team reviews the work of an agent. The GitHub Action in this repository verifies the receipts of that work and puts the result on the pull request. A reviewer sees the result and installs nothing.

The action runs `agent-custody verify --markdown` on a directory of receipt bundles. It writes one table to the job summary. On a pull request it also posts the same table as one comment, and it edits that comment on each later push.

## The workflow file

Copy this file to `.github/workflows/receipts.yml`.

```yaml
name: receipts
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - uses: svayatta/agent-custody@<commit sha of the release> # 0.14.0
        with:
          path: .custody/receipts
          issuer-key: .custody/keys/agent.pub
```

Pin the action to the commit of a release, as you pin every other action. A moving tag lets a third party change what runs with your token.

## The inputs

| input | meaning | default |
| --- | --- | --- |
| `path` | a directory of receipt bundles; the action reads the `.json` files in it, not `<id>.authorization.json` files and not subdirectories | `.custody/receipts` |
| `issuer-key` | the public key files of the issuers you trust, one path on each line (required) | |
| `principal-key` | the public key files of the principals whose grants a gateway receipt carries, one path on each line; SDK and Claude Code hook receipts need none | |
| `log-url` | the URL of the log; the action fetches the log key from it (`verify --log-url`) | |
| `log-id` | the id that every tree head must name (`verify --log-id`) | |
| `version` | the `@agent-custody/receipts` version that `npx` runs | `0.14.0` |
| `github-token` | a token that can write pull request comments | `github.token` |

## What the action does

1. It sets up Node 22 and runs `npx @agent-custody/receipts@<version> verify --markdown <path> --issuer-key ...`.
2. It writes the table to `$GITHUB_STEP_SUMMARY`.
3. On a `pull_request` event, it looks for an earlier comment that starts with `<!-- agent-custody -->` and edits it. When there is none, it posts a new comment.
4. It fails the step when one receipt does not verify, and when the directory holds no receipt.

When the token cannot write a comment, the action prints a warning and keeps the job summary. This is the case for a pull request from a fork, where GitHub gives the `pull_request` event a read-only token. The step does not fail for that reason. Do not switch to `pull_request_target` to get the comment. That event gives a write token to a workflow that handles code from the fork.

The table has one row for each receipt. The failed rows come first.

| Receipt | Tool | Status | Result |
| --- | --- | --- | --- |
| `981d2afd-63f2-49ed-854a-83fc1bf1c035` | - | - | `receipt signature (issuer key)` |
| `6e2de8f3-4e51-43e5-af8b-a2b283dd7709` | `stripe.refund` | executed | verified |

- `Status` is the execution status in the signed receipt: `executed`, `denied`, `failed`, `error`, or `withheld`. When the signature does not verify, the table shows `-`, because nothing in that receipt is trusted.
- `Result` is `verified`, or the names of the checks that failed. [Verifying a receipt](verification.md#what-each-check-means) explains each check.
- A file whose name is not `<receipt id>.json` fails with `file name matches receipt id`. A valid receipt under the name of another receipt could hide that receipt.
- The table shows 200 rows at most. Every failed row is in it.

## What the table proves, and what it does not

A `verified` row proves that the issuer key you gave signed the receipt, that the receipt has not changed since, and that its checks hold. It does not prove that the receipts are all the calls the agent made. The author of the pull request chooses which receipts to commit. [Completeness](completeness.md) answers that question from the provider's side.

Keep the key files out of reach of the pull request. With the `pull_request` event, the workflow checks out the merge of the pull request. An author who changes `.custody/keys/agent.pub` in the same pull request can sign a receipt with a key of their own. Protect the key path with a code owner rule, or keep the key in a repository that the author cannot change.

## How receipts get into the pull request

Receipts stay on the machine of the developer today, in the `receiptsDir` of the gateway or the SDK. The action reads a directory in the checkout, so the receipts you want reviewed must be in the branch. There is no export command yet. To commit receipts, copy the `<id>.json` files of the session into `.custody/receipts/` by hand.

### A committed receipt publishes the call

By default a receipt carries the call in plain text. It holds the arguments the agent sent and the result the tool returned. For a `Bash` call that is the command and its output. For a file tool it is the content of the file. Anyone who can read the repository can read these values. If the repository is public, everyone can.

Before you commit a receipt, check these four points.

1. Set a capture rule. A `capture` rule in the gateway config or the SDK config withholds a side of the call. With mode `digest`, the receipt holds one commitment over the fields you do not list in `clear`. With mode `encrypted`, it holds the same commitment and the value encrypted under a key that only you hold (`captureKeyEnv`). The rule applies to the receipt, to the log, and to every exporter. [Private evidence](usage.md#private-evidence) has the full rules.

   ```json
   "capture": {
     "*": { "args": { "mode": "digest" }, "result": { "mode": "digest" }, "facts": { "mode": "digest" } }
   }
   ```

2. Commit the `<id>.json` files only. Never commit `salts/`, `outbox/`, `*.authorization.json`, or a local `log.jsonl`. The salts let a reader confirm a guess of a withheld value. The action does not read the other files, and the authorization files and the log hold the call data as well.
3. Keep the capture key out of the repository and out of the workflow. The action needs no key. A receipt with withheld values verifies as committed, and the table still shows the tool and the status, because those parts stay in clear.
4. Read one committed receipt before the first push. Run `agent-custody verify <file> --issuer-key <pub>` and read the `args` and `execution` rows.

A reviewer who needs a withheld value asks the owner of the key for a disclosure (`agent-custody reveal`), and verifies it with `verify --disclose`.

An agent that runs inside the CI job needs no transport. Write its receipts in the job and run the action in the same job.
