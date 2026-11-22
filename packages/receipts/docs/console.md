# Gateway console

A small admin service for the person who runs a gateway. It shows what the gateway is configured to do and what it has done, validates and replays a policy change before it is saved, revokes a grant, and puts the gateway's approval requests in front of a person. It is a separate process from the gateway, behind a token, so the gateway never serves an admin page next to the agents' credentials.

It is deliberately limited. It holds **no principal or approver key and signs nothing**, so it cannot issue a grant, approve a call, or widen anyone's authority. Everything it shows is read from the gateway's own config, receipts, revocation file, and approval requests. The only things it changes are the policy file, the revocation file, and the approval requests, all of which the gateway reads. An approval is signed in the approver's browser, not by the console. [Example 32](../examples/32-console.ts) runs it end to end.

## Run it

```bash
export CONSOLE_TOKEN="$(openssl rand -hex 32)"            # the sign-in token; it is read from the environment (or a file), never from a flag
agent-custody console --config gateway.json --gateway-url http://127.0.0.1:8790
```

It listens on `127.0.0.1:8795` and prints the URL. Open it and sign in with the token.

| flag | meaning |
| --- | --- |
| `--config <gateway.json>` | the gateway's config, read again on every request, so an edit shows at once |
| `--token-env NAME` | the environment variable holding the token, default `CONSOLE_TOKEN`; the console refuses to start without one |
| `--token-file <path>` | read the token from a file instead, such as a container secret at `/run/secrets/console_token`; the contents are the secret, not the path |
| `--port`, `--host` | default `8795` on `127.0.0.1`; any other host prints a reminder to put TLS in front |
| `--gateway-url <url>` | the running gateway, for its health (reachable, open sessions); omit it and the console does not look |
| `--state-dir <dir>` | where the console keeps its audit file and the earlier versions of the policy; default `console/` beside the receipts directory |

**In the Docker image** it is the same image as the gateway, run as a second service: `docker compose --profile console up -d` in [deploy/gateway](https://github.com/svayatta/agent-custody/blob/main/deploy/gateway/README.md). The token is a **Docker secret mounted only in the console service** (`openssl rand -hex 32 > console-token`), not an entry in the `.env` file that the gateway reads, because the token can rewrite the policy and revoke grants and the gateway must not hold it. The console service is not given that `.env` either, so it holds none of the upstream credentials. It mounts `./config` read-write, because the policy file is what it edits, and the same data volume as the gateway; the gateway keeps its config read-only. Both run as the same user (`GATEWAY_UID`, `GATEWAY_GID`, default 10001), so what one writes the other can read: the gateway's key is mode 0600. On Kubernetes, run the same image with the argument `console`, the token as a Secret mounted as a file and given only to that pod, the same config and data volumes, and a Service that only your administrators can reach.

## What it shows and does

| tab | what it does |
| --- | --- |
| **Overview** | the gateway's health and key id, the mode, the upstreams and their kinds, the fact lookups, the log, `precommit`, the trusted principal keys, the number of revoked grants and of receipts, and the config check's result |
| **Check** | the same checks as `agent-custody check`, except that the credential variables are **not** checked: the console deliberately does not hold the gateway's credentials, so it cannot tell whether they are set where the gateway runs. "Connect" starts the upstreams and lists their tools only for a config that names no credentials; otherwise it says to run `agent-custody check --connect` where the gateway runs, for example `docker compose exec gateway agent-custody check --config /config/gateway.json --connect`. A connect check that does not finish in 60 seconds is stopped and the upstreams it started are closed ([configuration.md](configuration.md#check-it-before-you-start-it)) |
| **Policy** | the policy file in an editor. *Validate* asks Cedar to parse it. *Replay recorded calls* runs it against the verified receipts, using each call's own arguments and facts, and lists the decisions that would change, with their receipts. **A replay only re-decides calls that already happened**: a limit that no recorded call reached, or removing one, can show no change, so it is not a test of what a policy allows. *Save* writes it, keeping the previous version and recording the change |
| **Grants** | paste a grant to see whether the gateway would accept it (valid, expired, revoked, signed by a key it does not trust) and what it allows; *Revoke* adds its digest to the revocation file, and the gateway refuses it, and every grant delegated from it, on its next call. Lists the revoked digests |
| **Approvals** | the requests a gateway with `approvals.requests` left for protected calls that came with no approval: who asked, for which tool, and the exact arguments. *Sign and approve* reads the approver's key file in the browser, signs the call there with WebCrypto, and sends only the signature; the console stores it only if it verifies with one of the gateway's trusted approver keys over this exact call, inside `maxLifetimeSeconds`. Under a two-person rule the second approver's *Countersign* needs a different key, and is refused unless the first signature verifies with a trusted key over this call. *Deny* keeps that call refused until the request is deleted; the reason stays in the request and the audit, and is not repeated to the agent. [Approval requests](approvals.md#ask-a-person-approval-requests) |
| **Receipts** | the newest receipts with their agent, tool, decision, and outcome, each verified against the gateway key, the trusted principals, and the local log; a receipt that does not verify says which checks failed; the id in a row opens a summary of the statement, with the full statement behind *Raw JSON* |
| **Audit** | every change made through the console: who, when, and what, with the policy's digest before and after, and each approval signed (with the key id) or denied |

## Use the page

- **The tab is in the URL.** The hash is `#tab=policy`, `#tab=receipts`, and so on. Copy the URL to link to a tab. Back and Forward move between the tabs that you opened.
- **Results show beside the button.** The result of *Save* shows beside *Save*. The result of *Revoke* shows beside *Revoke*. Both are announced to a screen reader.
- **Unsaved policy edits are not lost without a warning.** A tab change with unsaved edits opens a dialog that asks you to discard them or to keep editing. Closing or reloading the page shows the browser's own warning.
- **Save and Revoke ask in the page.** The dialog names the policy file or the grant (the agent and the digest). Escape and *Cancel* do nothing. For *Revoke*, the focus starts on *Cancel*.
- **A receipt opens from its id.** The id in each row is a button, so the keyboard and a screen reader can open it. The detail shows the tool, the decision, the status, the time, the agent, the principal, whether a grant was presented, the digests, and whether the receipt verifies. The full statement is behind *Raw JSON*. The focus moves to the detail when it opens and returns to the id when you press *Close*.
- **Signing needs a secure page.** Browsers offer WebCrypto only on `https` or on `localhost`, so the console signs on its default `127.0.0.1` address, or behind TLS. The key file is read by the page and never sent; a browser without Ed25519 in WebCrypto says it cannot sign, and `agent-custody approvals approve` does the same from the command line.
- **Times show in your local time.** The UTC value shows when you hold the pointer over a time.

## What a saved policy does

A running gateway re-reads `policy.cedar` when it changes, so **a saved policy applies from the gateway's next call**, with no restart, and the gateway records the change in `receipts/policy-reloads.jsonl`. The save is guarded: Cedar must parse the text; and the operator must confirm a policy that has no `permit` rule (a `permit(` in a comment does not count), because every call would be denied, or a `permit` rule with **no action and no condition**, which allows every tool in a grant's scopes and which a replay cannot show. A save made from a copy that is no longer the file on disk is refused with `409`. The digest check, the history copy, and the write happen under one lock, in this process and, through a lock file in the state directory, across consoles that share it, so two administrators cannot overwrite each other. The previous version is kept under `console/policy-history/` and the change goes in the audit trail.

## How it is protected

- **A token on every API route.** It is compared in constant time. Five wrong tokens from one address lock it out for a minute. A request with no token is refused and does not count towards that.
- **Loopback by default.** The transport is plain HTTP. Anything beyond one machine needs TLS in front (a proxy or mesh) and a network only administrators can reach. The console has one shared token, not per-user accounts or roles.
- **No keys.** It never reads a principal's or an approver's private key. It reads the gateway's key file only to take the public half, so that it can verify receipts. An approver's key is read by the page in their browser to sign, and only the signature reaches the console, which checks it against the gateway's trusted approver keys before storing it. The console token therefore lets someone deny a request, not approve one. It does let them read each request's arguments in clear, including fields that a `capture` rule withholds from receipts, because the Approvals tab shows the approver the exact call.
- **The page cannot run what it shows.** Every value is written with `textContent`, never as markup, and the page is served with a content-security-policy that allows exactly its own script and style by hash and nothing else (no inline attributes, no outside requests). The page's own tests check both.
- **Bounded input.** A request body over a megabyte is refused, and a receipt id must be a UUID, so a path cannot be read through it.
- **Everything it changes is recorded**, in an append-only file in its state directory, and the policy it replaces is kept.

## Limits

- It does not issue grants. A grant is signed by a principal's key, which belongs where grants are issued ([configuration.md](configuration.md#the-principals-key)).
- It does not edit `gateway.json`: upstreams, facts, and `precommit` are changed in the file, and the gateway restarted. The Overview and Check tabs show them.
- The credential variables are not checked in the console, and an upstream that needs one is not started there.
- One token, no per-user accounts, and the audit records the address and not a person.
- An approval in the audit names the key that signed it. Which person holds that key is the operator's to know, as for `agent-custody approvals approve`.
- It reads the local receipts directory. With a remote log it verifies receipts against the keys but not the log's inclusion proofs.
- A shared gateway has one policy and one key for every agent on it, so the console edits one policy.

## API

Every route except `GET /` (the page) and `GET /healthz` needs `Authorization: Bearer <token>`.

| route | does |
| --- | --- |
| `GET /api/overview` | the configuration summary, the gateway's health, and the static check |
| `POST /api/check` `{ connect? }` | the check; `connect` starts the upstreams |
| `GET /api/policy` | the policy text, its digest, and the earlier versions kept |
| `POST /api/policy/validate` `{ text }` | does Cedar parse it, and which things need confirming (`issues`) |
| `POST /api/policy/simulate` `{ text }` | replay up to 1,000 verified receipts against it; the report counts reconciliation receipts (provider reads, no policy decision) in `reconciliations`, apart from `evaluated` |
| `PUT /api/policy` `{ text, expectDigest, confirm? }` | save it; `400` unless `confirm` is true when the policy has an issue the validate route reported; `409` if the file changed |
| `POST /api/grants/inspect` `{ grant }` | status, agent, scopes, window, digest |
| `POST /api/grants/revoke` `{ grant }` | add its digest to the revocation file |
| `GET /api/revocations` | the revoked digests |
| `GET /api/approvals` | `{ configured }`, and when requests are on: the pending requests, then up to 50 decided ones, with their exact arguments; `trustedKeyids` and `maxLifetimeSeconds` |
| `POST /api/approvals/prepare` `{ requestId, expiresInSeconds }` | the payload to sign and its DSSE bytes (`pae`), base64; the payload already signed once under a two-person rule. Nothing is written |
| `POST /api/approvals/sign` `{ requestId, payload, keyid, sig }` | stores the signature if it verifies with a trusted approver key and binds this request's call inside `maxLifetimeSeconds`; 409 otherwise |
| `POST /api/approvals/deny` `{ requestId, reason? }` | marks the request denied |
| `GET /api/receipts?limit=` | recent receipts with their verdicts; `GET /api/receipts/<id>` is one statement |
| `GET /api/audit` | the console's audit trail |

Programmatically: `serveConsole({ configFile, token, port?, host?, gatewayUrl?, stateDir? })` returns `{ url, close() }`.
