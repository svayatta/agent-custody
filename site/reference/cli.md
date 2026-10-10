# Command line

Two commands, one per package. Both run on plain Node 22 or later. Exit code 0 on success, 1 when a check or an operation fails, 2 for usage errors. Everything diagnostic goes to stderr; stdout carries the result, so `--json` output can be piped.

## `agent-custody`

| command | what it does | page |
| --- | --- | --- |
| `keygen --dir <dir> --name <name>` | an Ed25519 key pair as `<name>.key` and `<name>.pub`; prints the keyid | [SDK](./sdk-typescript#keys) |
| `grant --key <principal.key> --principal <id> --agent <id> --scopes <a,b> [--ttl-hours 24] [--agent-key <agent.pub>] --out <file>` | a signed delegation | [gateway](./gateway#grants) |
| `delegate --key <agent.key> --parent <grant.json> --agent <sub> --scopes <a,b> [--ttl-hours N] [--agent-key <sub.pub>] --out <file>` | a narrower grant for a sub-agent | [gateway](./gateway#delegation-chains) |
| `gateway --config <gateway.json> [--http [--port 8790] [--host 127.0.0.1] [--idle-minutes 30]]` | the gateway over stdio, or shared over HTTP | [gateway](./gateway#running-it) |
| `gateway --config <gateway.json> --a2a [--port 8790] [--host 127.0.0.1]` | the gateway as an A2A agent in front of the config's one `a2a` upstream | [gateway](./gateway#running-it) |
| `hook [--config <sdk.json>]` | the Claude Code hook; the event on stdin | [Claude Code](./claude-code) |
| `serve --config <sdk.json> [--port 8788] [--host 127.0.0.1]` | the sidecar | [sidecar](./sidecar) |
| `verify <bundle.json> --issuer-key <pub> [--principal-key <pub>] [--log-key <pub> \| --log-url <url>] [--log-id <id>] [--upstream-key <pub>] [--stripe-secret-env NAME] [--github-secret-env NAME] [--log <log.jsonl>] [--json]` | checks one receipt | [verify](./verify#verify) |
| `audit --older <bundle> --newer <bundle> (--log <log.jsonl> \| --log-url <url>) [--issuer-key <pub>] [--log-key <pub>] [--log-id <id>] [--witness-key <pub> \| --witness-url <url>] [--json]` | proves the newer head extends the older | [verify](./verify#audit) |
| `prune --log <log.jsonl> --before <ISO> [--receipts <dir>]` | retention on a local log: older leaves become their hashes | [log API](./log-api#files) |
| `log --file <log.jsonl> --key <log.key> [--port 8787] [--host] [--token-env NAME] [--log-id <id>] [--tenants <file>]` | the log server over a file | [log API](./log-api#the-server) |
| `log --db-env NAME (--key <log.key> [--retired-key <pub>]… \| --signer-url <url> [--signer-token-env NAME]) [--checkpoint-dir <dir>] [--checkpoint-every 300] [--checkpoint-heartbeat 21600] [--admin-token-env NAME] [--public-url <url>] [--checkpoints-url <url>] [--trust-proxy]` | the log server over Postgres, with tenants, checkpoints, and the admin page | [log API](./log-api#the-server) |
| `signer --key <log.key> --port 8790 [--host] [--token-env NAME] [--retired-key <pub>]…` | the process that holds the log's key | [log API](./log-api#the-signer) |
| `witness --key <witness.key> --log-url <url> --checkpoints-url <url> --out <dir> [--tenant <name>]… [--every 300] [--once]` | a second signer on another operator's machine | [log API](./log-api#the-witness) |
| `log-check --log-url <url> [--checkpoints-url <url>] [--witness-url <url>] [--tenant <name>]… [--max-lag 900] [--json]` | the outside monitor | [log API](./log-api#monitoring) |
| `log-export --log-url <url> [--tenant <name>] --token-env NAME --out <dir> [--month YYYY-MM]… [--json]` | a tenant's own log, self-checked | [verify](./verify#log-export) |
| `portal --db-env NAME --secret-env NAME --public-url <url> [--checkpoints-url <url>] [--portal-url <url>] [--stripe-key-env NAME --stripe-webhook-env NAME --stripe-price-team <id>] [--mail-key-env NAME --mail-from <address> [--mail-notify <address>]] [--trust-proxy]` | the tenant portal; mail through Resend's API at registration | [hosted](./hosted#registering-the-portal) |
| `portal-followup --db-env NAME --mail-key-env NAME --mail-from <address> [--mail-notify <address>] [--portal-url <url>] [--dry-run]` | the founder's note to registrations an hour to a week old that have not had it, once each; run hourly from cron | [hosted](./hosted#registering-the-portal) |
| `log-admin --db-env NAME tenant add <id> [--log-id <id>] \| tenant list \| tenant disable <id> \| tenant plan <id> <free\|team\|enterprise>` | tenants | [hosted](./hosted#the-operators-side) |
| `log-admin --db-env NAME token add <tenant> --label <text> \| token list <tenant> \| token revoke <tenant> <hash-prefix>` | tokens; a minted token is printed once | [hosted](./hosted#the-operators-side) |
| `log-admin --db-env NAME audit [--tenant <id>]`, `log-admin --db-env NAME import --file <log.jsonl> [--tenant default]` | the audit trail; a file log brought into the database | [hosted](./hosted#the-operators-side) |
| `portal --db-env NAME --secret-env NAME --public-url <log url> [--checkpoints-url <url>] [--portal-url <url>] [--port 8792] [--host] [--stripe-key-env NAME --stripe-webhook-env NAME --stripe-price-team <id>] [--trust-proxy]` | the tenant portal | [hosted](./hosted#registering-the-portal) |

## `agent-custody-memory`

| command | what it does | page |
| --- | --- | --- |
| `serve --ledger <path> [--allow-direct] [--key <memory.key>] [--forget-key-env NAME] [--retention '<space>=<ISO duration>,…']` | the memory server over stdio | [memory](./memory#running-the-server) |
| `serve --ledger <path> --http [--port 8790] [--host] [--token-env NAME] [--allow-direct]` | the same over HTTP, shared | [memory](./memory#running-the-server) |
| `sweep --via <gateway.json> --reason <text> [--before <ISO>] [--space <space>] [--no-digest]` | retention as a receipted call | [state tools](./state-tools#sweep-and-export) |
| `sweep --ledger <path> --before <ISO> --reason <text> [--space] [--actor] [--forget-key-env NAME] [--no-digest]` | retention on the ledger alone | [state tools](./state-tools#sweep-and-export) |
| `eval [--scenarios <file>] [--baseline] [--json] [--sign <key> --out <report>]`, `eval --verify <report> --key <pub>` | the memory-mutation evals | [state tools](./state-tools#eval) |
| `pack --ledger <path> --receipts <dir> --fact <factId> --out <pack.json> --sign <key>`, `pack --verify <pack.json> --key <pub> [--issuer-key] [--principal-key]` | one fact's custody pack | [state tools](./state-tools#pack) |
| `explain --receipts <dir> --receipt <id> [--ledger <path>] [--issuer-key] [--principal-key] [--log-key] [--json]`, `explain … --out <file> --sign <key>`, `explain --verify <file> --key <pub>` | one action explained | [state tools](./state-tools#explain) |
| `review --receipts <dir> [--ledger <path>] [--issuer-key] [--principal-key] [--log-key] [--log-id] [--port 8791] [--host] [--title <text>]`, `review … --out <dir>` | the review pages | [state tools](./state-tools#review) |
| `export --ledger <path> --out <ledger.jsonl>` | any ledger as JSONL | [state tools](./state-tools#sweep-and-export) |
| `blast --ledger <path> --receipts <dir> --fact <factId> [--json]` | what relied on a fact | [state tools](./state-tools#blast) |
