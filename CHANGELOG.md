# Changelog

All three packages, `@agent-custody/receipts`, `@agent-custody/state`, and `agent-custody` on PyPI, move in lockstep. The receipt format has stayed at v0.2 throughout; every addition to it is an optional field, so earlier receipts and the published conformance vectors remain valid.

## 0.6.19 — 2026-10-10

- **Receipts:** agents that delegate to agents. A fourth upstream shape, `{ "a2a": { "url", "headers"?, "headerEnv"?, "timeoutMs"?, "prefix"? } }`, is another agent reached over the A2A protocol: the gateway fetches its card at startup and offers `<prefix>.send`, which delegates a task, and `<prefix>.card`, the card as a fact a policy decides on; both the 1.0 and the 0.3 wire formats, the card choosing; a streamed delegation relayed once the agent finishes, with the final task on the receipt; `precommit` as for any consequential tool. And `gateway --a2a`, the gateway as an A2A agent in front of that upstream: it serves the remote agent's card at its own address, turns every `SendMessage` into a `<prefix>.send` call under the config's grant or the one in the request's grant header, answers an allowed delegation with the remote agent's task carrying the receipt id in `metadata`, a refused one as a rejected task with the reason and the receipt id that the remote agent never heard of, and forwards every other method untouched. A Google ADK `RemoteA2aAgent` pointed at the gateway's card needs no other change. Example 25 and `test/a2a.test.ts`, with stand-in agents in both formats.
- **Python:** a Google ADK adapter, `agent_custody.adk`: `adk_callbacks(client)` gives `before_tool_callback`, which records the denial and returns the error dict naming the receipt so ADK skips the tool and the model sees why, and `after_tool_callback`, which records the executed call. Extra `adk` (`google-adk[a2a]`). Tested against ADK's own runner with a scripted model in `tests/test_adk.py`, and `tests/test_adk_a2a.py` runs ADK's `to_a2a` remote agent and `RemoteA2aAgent` through `gateway --a2a`, both receipts verified.
- **State:** unchanged; released in step.

## 0.6.18 — 2026-09-29

- **Receipts:** the founder's note. `agent-custody portal-followup`, run hourly from cron (`deploy/followup.sh`), sends every registration between an hour and a week old a personal note from `MAIL_FROM`, once: which stack, an offer to do the integration, start in observe mode. `PortalStore.pendingFollowUps`/`markFollowedUp` (`portal_users.followed_up_at`), `founderNote`, `sendFollowUps`, and `deliverMail` shared with the portal's own mail. Accounts on the operator's own mail domains are skipped; a provider failure is retried next run.
- **State, Python:** unchanged; released in step.

## 0.6.17 — 2026-09-29

- **Receipts:** a DeepSeek Harness plugin, `@agent-custody/receipts/sdk/deepseek-harness`. The module is the plugin: list it by its package path with the SDK config file as its setting. `tools/pre-execute` denies an enforced policy deny with the receipt id in the reason the model sees and delegates otherwise; `tools/post-execute` records the executed or failed call with the harness's session and call ids. Typed from the harness's own tool types with no dependency; driven as the harness drives it in example 22 and a test. The harness's Claude Code hooks bridge runs the `hook` command unchanged as the out-of-process alternative.
- **State, Python:** unchanged; released in step.

## 0.6.16 — 2026-09-28

- **Receipts:** observe mode. `"mode": "observe"` in the gateway or SDK config forwards every call the grant allows and records the decision the policy would have made, with `enforced: false` on the receipt's `policy`; a deny is recorded, not acted on, in the gateway, `wrap`, and every hook adapter (Claude Code, Claude Agent SDK, OpenAI Agents, Vercel AI, OpenClaw), and the sidecar carries the flag so the Python adapters and Hermes plugin do the same. The verifier's consistency check accepts a not-enforced deny beside an executed call and names the mode; a receipt with the flag stripped fails. Two new conformance vectors, `gateway-observe-denied` and `resigned-observe-flag-stripped`; the browser verifier mirrors the check. The receipt format stays v0.2: the field is optional.
- **Python:** `denies(policy)` tells an enforced deny from a recorded one; the adapters use it.
- **State:** `explain` says when a call went through because the policy was in observe mode.

## 0.6.15 — 2026-09-28

- **Receipts:** an OpenClaw adapter, `@agent-custody/receipts/sdk/openclaw`: `openclawHooks(issuer)` gives `before_tool_call`, which blocks a policy-denied call with the denial receipt's id in the reason and returns nothing otherwise, and `after_tool_call`, which records the executed or failed call; `registerOpenClaw(api, issuer)` wires both in a plugin's `register(api)`. Driven against OpenClaw's documented hook types in example 21 and a test.
- **Python:** a Hermes Agent plugin, `agent_custody.hermes`: `pre_tool_call` blocks a denied call with the receipt id, `post_tool_call` records; `register(ctx)` is the plugin entry, and `packages/python/hermes-plugin/` is the drop-in directory with its `plugin.yaml`. Tested against the real sidecar.
- **State:** unchanged; released in step.

## 0.6.14 — 2026-09-28

- **Receipts:** registration in two steps: an account from an email and a password, or from a GitHub or Google sign-in, then the tenant on the next screen (name, company, tenant id, role, phone, Telegram), with the first key and the emails once the tenant exists. `POST /api/register` with only email and password creates the account; `POST /api/onboard` creates the tenant; the one-call register with everything still works for scripts. `GET /auth/github` and `GET /auth/google` run the OAuth web flow over fetch with a signed state cookie; a provider sign-in links to the account with the same verified email or creates one (`portal_identities`). `--github-client-id/--github-secret-env`, `--google-client-id/--google-secret-env`; `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` in the container.
- **State, Python:** unchanged; released in step.

## 0.6.13 — 2026-09-28

- **Receipts:** published policy versions. A tenant publishes each Cedar file it deploys under a name; the digest is the same SHA-256 the gateway writes into receipts as `policyDigest`, so a receipt's digest reads as a name on the portal's new Policies page, in its match-a-receipt tool, and in the export's `policies.json`. `PostgresTenancy.addPolicy/listPolicies/policy/policyByDigest/removePolicy`, audited as `policy.add` and `policy.remove`; `GET /t/<tenant>/policies` with the tenant token; portal routes under `/api/policies`. Enforcement is untouched: the gateway never reads any of it.
- **State, Python:** unchanged; released in step.

## 0.6.12 — 2026-09-28

- **Receipts:** listed in the MCP Registry as `io.github.svayatta/agent-custody`. The package carries `mcpName`, which the registry checks against the published npm package, and `packages/receipts/server.json` describes the entry: the gateway over stdio, run as `npx @agent-custody/receipts gateway --config <gateway.json>`. The repository moved to the `svayatta` organisation; links and the container image (`ghcr.io/svayatta/agent-custody-log`) follow it.
- **State, Python:** unchanged; released in step.

## 0.6.11 — 2026-09-27

- **Site:** a logo: a receipt with a torn edge, two ledger lines, and a tick, on the amber tile; `logo.svg`, `wordmark.svg`, and the PNG icons. The home page is laid out along the lines of dunetrace.com: a centred hero with three actions (Register for a free account, View GitHub, Verify a receipt) and the film under them, then the problem, how it works, denied at runtime, not a trace, a quick start with the commands, and where to go.
- **Receipts:** the portal and the Caddy hosts carry the new mark; `app.agent-custody.dev/#register` opens the portal on the registration form.
- **State, Python:** unchanged; released in step.

## 0.6.10 — 2026-09-27

- **Receipts, fix:** the portal and the admin page were blank on 0.6.8 and 0.6.9: a quote escaped once inside the page's template literal made the inline script fail to parse. Fixed, and both tests now compile every inline script. The pages' Content Security Policy allows the favicon (`img-src 'self'`).
- **State, Python:** unchanged; released in step.

## 0.6.9 — 2026-09-27

- **Receipts:** the portal and the admin page have a dark mode switch (a choice kept in the browser; unset, they follow the system) and carry the mark as their favicon; the portal serves `/favicon.svg`.
- **Deploy:** Caddy serves the mark as `/favicon.svg` and `/favicon.ico` on the log, checkpoints, portal, and admin hosts, and the log and checkpoints landing pages link it.
- **Site:** the home page has a light and dark switch in its top bar, sharing the docs' setting.
- **State, Python:** unchanged; released in step.

## 0.6.8 — 2026-09-27

- **Receipts:** the portal's welcome is five numbered steps with copy buttons (keep the key, point the gateway at the log, send the first receipt, what to hand a verifier, take your data), the log's addresses, and what the log does not do, instead of a monospaced sheet; the same page is under Setup in the dashboard whenever it is needed again. `/api/register` and `/api/overview` carry it as `setup`; the text `welcome` stays for scripts.
- **Receipts:** registration sends mail: a welcome to the person with the setup sheet and never the key, and, with `--mail-notify`, a note to the operator with the contact details. Through Resend's HTTP API with no dependency (`MailOptions`, `--mail-key-env`, `--mail-from`, `--mail-notify`; `MAIL_API_KEY`, `MAIL_FROM`, `MAIL_NOTIFY` in the container). Best effort: a provider failure is logged and never fails a registration.
- **State, Python:** unchanged; released in step.

## 0.6.7 — 2026-09-27

- **Receipts:** registration asks who is registering: name and company or organisation are required, role, phone, and Telegram username optional; the tenant id is filled in from the company name, explained as the path of the log, and previewed as the full URL before the form is sent. `PortalStore.createUser` takes the profile; `portal_users` gains the columns on start. The admin page's Registrations section and `/admin/registrations[.csv]` show who and how to reach them.
- **State, Python:** unchanged; released in step.

## 0.6.6 — 2026-09-27

- **Site, #52:** the home page leaves the docs theme: its own top bar with five entries (Product, Docs, Pricing, Verify, Sign in), one story, the real receipt with the one amber action, one sentence on what a receipt does not prove, three doors (Try it, Make it evidence, For security review), a flow diagram, an in-page demo of the gateway and the verifier, and a comparison with application logs and traces. The docs nav is the same five entries; Receipts, State, Python, and the spec are in the sidebar. Getting started opens with the stacks (Claude Code, Claude Agent SDK, OpenAI Agents SDK, LangChain, Vercel AI, Python) and says which path is the agent's word and which is evidence; the trust table moved to the pieces page. Pricing says what 10,000 appends is in a worked week.
- **Receipts, #52:** the portal overview states the trust limit of the plan: heads signed by our key, no second witness yet, with a link to the proof table.
- **State, Python:** unchanged; released in step.

## 0.6.5 — 2026-09-27

- **Site, #52:** the home page is one column: the claim, one action, and a real receipt from this repository's custody (the denied `git push --force`) with a control that opens it in the browser verifier, then the six steps as a numbered sequence. The VitePress hero and feature grid are gone; the docs keep the theme. `/verify?receipt=<id>` loads one of the site's own receipts with its keys and verifies it on arrival.
- **Receipts, #52:** the tenant portal wears the site's mark and amber in its header, so registering reads as the next page of the same site.
- **State, Python:** unchanged; released in step.

## 0.6.4 — 2026-09-27

- **Receipts:** the admin page opens with a Registrations section: who registered each tenant through the portal, plan, billing state, appends in the chosen month, leaves in total, live tokens, with totals across tenants and a CSV. `GET /admin/registrations?month=` and `/admin/registrations.csv` behind the admin token; `PortalStore.registrations()` reads the portal's tables; the log server wires the portal store in when it runs on Postgres.
- **Deploy:** the admin page on its own host, `ADMIN_HOST`, mapped by Caddy onto the log service's `/admin` surface with the token still required on every request. `/admin` on the log host is unchanged.
- **State, Python:** unchanged; released in step.

## 0.6.3 — 2026-09-27

- **Site, #49:** relative links written without `.md`, as the reference pages write them, resolve to the page instead of becoming repository URLs that do not exist; about sixty links across ten reference pages were dead. The docs host's root goes to the guide. The home page's install block says which line is the command line and which the Python package.
- **Receipts, #49:** the portal's top bar links to the guide, the reference, and the browser verifier.
- **State, Python:** unchanged; released in step.

## 0.6.2 — 2026-09-27

Six vulnerabilities reported as issues #41 to #46, all fixed here.

- **Receipts, #42:** arguments reach Cedar as data only. A value shaped as a Cedar entity or extension (`__entity`, `__extn`) is a deny before evaluation, with the argument's path in the receipt's errors, so an agent cannot satisfy a policy comparison by the shape of what it sends.
- **Receipts, #46:** a stdio upstream is started with a minimal environment (the path, home, and temp directories, the locale, and what its config's `env` names), never the gateway's own, so the tokens other upstreams and the log are given do not reach a tool process.
- **Receipts, #41:** a fact tool named in `precommit` is refused at startup: a lookup runs before the policy decides and must be a read. `"*"` covers the tools the agent calls, not the gateway's lookups.
- **Receipts, #45:** `log --hash-only` (`AGENT_CUSTODY_HASH_ONLY=1`, set by the compose file for the tenanted log) refuses `{ leaf }` at append and accepts only `{ leafHash }`, so a log run for other people never receives a receipt regardless of the client's configuration.
- **Receipts, #44:** behind a trusted proxy, per-address limits key on the rightmost `X-Forwarded-For` entry, the one the proxy appended, never on one the client supplied.
- **Receipts and the browser verifier, #43:** delegation windows are compared as instants in both verifiers; the package's grant schema accepts ISO offsets so both reach the same comparison. New vector `gateway-chain-offset-window-resigned`, which both must refuse.
- **State, Python:** unchanged; released in step.

## 0.6.1 — 2026-09-26

- **Receipts:** plans and monthly quotas. Every tenant is on a plan, free (ten thousand appends a calendar month), team (a million), or enterprise (no allowance); an append past the allowance is refused with 429, the numbers, and a `retry-after` reaching the start of next month, so the gateway behind it withholds pre-committed calls rather than acting without evidence. The plan is set on the admin page or with `log-admin tenant plan`, audited, and reported with the quota on the tenant's usage route, the admin usage table, and the CSV. Existing tenants read as free.
- **Receipts:** the tenant portal. `agent-custody portal` (`ROLE=portal`, compose service `portal`, Caddy at `PORTAL_HOST`): a team registers with an email, a password, and a tenant id and gets the tenant and its first key shown once with the welcome sheet; the dashboard shows appends against the plan, the tree size and root, the latest checkpoint, the log's URLs, keys, and the audit rows; keys are minted and revoked there; the export command is on the page; and with `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and `STRIPE_PRICE_TEAM` the team plan is bought through Stripe Checkout, the signed webhook moving the plan. One inline page, no framework, strict content-security policy, signed-cookie sessions.
- **Deploy:** the compose env file is optional, so the file validates without one.
- **State, Python:** unchanged; released in step.

## 0.6.0 — 2026-09-21

- **Receipts:** one gateway for many agents. `gateway --http` serves the gateway as an MCP server over Streamable HTTP; every connection presents its own grant (base64url in `Authorization: Bearer` or `X-Agent-Custody-Grant`) and gets a session under exactly that grant, sharing the upstreams, the policy, the key, and the log with the others and nothing else. `createGatewayHost` and `host.open(grant)` are the library form; `grantFile` in the config is now optional. A stranger's, an expired, or a missing grant gets 403 with the reason. Tutorial 20.
- **Receipts:** delegation chains for sub-agents. A grant that names the agent's own key (`grant --agent-key`) lets the agent delegate a narrower grant to a sub-agent (`delegate`), parent embedded, up to three deep. The verifier, the browser verifier, and the gateway walk the chain back to a trusted principal key and refuse any link that escalates scope, widens the window, changes the principal, or is signed by the wrong key; the receipt names the sub-agent and the principal and carries the chain. New check `delegation chain to the principal`; vectors `gateway-chain-executed` and `gateway-chain-escalated-resigned`. Existing grants are unchanged.
- **State:** write-through adapters for Letta (archival passages, custody as tags), any LangGraph store, where LangMem keeps its memories (one item per fact under a namespace), and Cognee (its REST API, the data id found by listing the dataset, tested against a stand-in of its routes only). Closes #4.
- **Repository:** built under custody. `.claude/settings.json` records every tool call an agent makes here as a receipt, hash-logged to our tenant on the hosted log; the site's [custody page](https://agent-custody.dev/custody) shows the live tenant and two verifiable receipts. The container image base moves to Node 24; Dependabot skips mermaid and Node majors.
- **Python:** unchanged; released in step.

## 0.5.9 — 2026-09-10

- **Receipts:** the checkpoint publisher re-signs a quiet log's head every `--checkpoint-heartbeat` seconds (default six hours; `AGENT_CUSTODY_CHECKPOINT_HEARTBEAT` in the container) even when the tree has not grown. Before this a log with no appends for a day tripped the monitor's "checkpoint keeps up with the head" check, which requires a checkpoint at the head to be signed within twenty-four hours: a quiet log looked like a stalled publisher, and the hosted log's status went red on 2026-09-10 for that reason alone. The Postgres checkpoint store now updates the signature at an existing size when the root is unchanged and never when it differs.
- **Receipts:** the witness names each alarm file uniquely; two refusals in the same millisecond no longer overwrite one another.
- **State, Python:** unchanged; released in step.

## 0.5.8 — 2026-09-09

- **Receipts:** an audit trail of administrative actions. Every tenant created or disabled and every token minted or revoked is recorded with who did it (the name entered at the admin page's prompt and the address, `bearer` for an API client, the user and host for `log-admin`), what, which tenant, and the detail, never the token itself. The admin page shows it under Activity, `GET /admin/audit` and `log-admin audit` list it, a tenant reads their own rows at `GET /t/<name>/audit` with their token, and `log-export` writes them to `audit.json`.
- **Receipts:** `docs/threat-model.md`, the attacker's view: every party who could make a receipt false, the move, what stops it, whether that is a property of the evidence or of the deployment, and what is not defended.
- **State, Python:** unchanged; released in step.

## 0.5.7 — 2026-09-09

- **Receipts:** a tenant's export. `agent-custody log-export --log-url <url> --tenant <name> --token-env NAME --out <dir>` fetches, with the tenant's own token, every leaf hash (`GET /t/<name>/leaves`, paged), the signed head, the published keys, the signed checkpoints, and their usage (`GET /t/<name>/usage`), checks that the head and every checkpoint verify against the keys and that the leaves hash to their roots, and writes `log.jsonl` in the format `verify --log` and `audit --log` read. Both routes answer only to that tenant's token. The welcome sheet includes the command.
- **Receipts:** every outbound request carries a timeout. The log client's is `log.timeoutMs` in either config, default ten seconds, so a log that accepts connections and never answers cannot hold a pre-committed call; the key, witness, and consistency fetches time out at ten seconds.
- **Receipts:** the signer publishes retired keys from `/data/keys/retired/*.pub` in the container, so rotating the signing key is a copy and a restart with every old head still verifying.
- **Deploy:** `RUNBOOK.md` (upgrade and rollback, backups and the restore drill, token rotation, tenant export and offboarding, key rotation, leaked secrets, a compromised host, what each monitor failure means) and `backup-offsite.sh`, which mirrors the nightly backups to an rclone remote named in `.env`. `SECURITY.md` at the repository root is the disclosure policy. Dependabot watches npm, pip, GitHub Actions, and the image base.
- **State, Python:** unchanged; released in step.

## 0.5.6 — 2026-09-09

- **Receipts:** `docs/compliance.md`, the mapping from each artefact (receipt, authorization, denial, remote log, checkpoint, witness, ledger event, forget record, custody pack, explain output) to the SOC 2 criteria, ISO 27001 Annex A controls, EU AI Act articles, and UK GDPR articles it is evidence for, and what no artefact claims.
- **Receipts:** Splunk export. `splunk: { url, tokenEnv, index?, source?, sourcetype?, host? }` in either config sends every receipt as one event to a Splunk HTTP Event Collector, the token from the environment, with the receipt id, tool, agent, principal, status, decision, policy digest, and log position as plain fields; beside or instead of `otel`, each exporter told independently, after the receipt and never on its path. Tutorial 19.
- **Receipts:** the deployment guide states what a remote log costs per call, measured against the live log: about five milliseconds of server work plus the network round trip, twice for a pre-committed call.
- **State:** `agent-custody-memory review`, the explain output as pages for the reviewer who will not open a terminal: an index of every receipt in a directory with when, tool, outcome, agent, principal, producer, and its verdict against the keys given, and one page per receipt with the ten answers, the verification report, and the bundle to download. Served on loopback with no login of its own, or written as static files with `--out` for a case file.
- **State:** `pgvectorStore(client, { embed, dimensions, table })`, write-through to a pgvector table with the fact id as the row key and custody metadata beside the embedding; removal is verified by the same nearest-neighbour query recall would run. Tested against the pgvector image in Docker. The server now assigns the fact id before the stores are written, so every store sees the real id.
- **Python:** `agent_custody.crewai.wrap_tools(client, tools)`, one `CustodyTool` per CrewAI tool, same name, description, and schema, every run decided, executed, and recorded through the sidecar; a denied call never runs and the crew sees the denial as the tool's result. Extra `crewai`. The memory client now works with mcp 1.x and 2.x and reports a refused token as one plain `MemoryError`.

## 0.5.5 — 2026-09-08

- **Receipts:** monitoring. `agent-custody log-check` is the outside probe: it verifies a log's head against its published keys, that the latest checkpoint verifies and keeps up with the head, that the head extends the checkpoint, and, with a witness, that the witness has countersigned, keeps up, and has raised no alarm; it exits 1 on any failure. The `monitor` workflow runs it against log.agent-custody.dev every ten minutes from GitHub's machines and its badge is the status page. `GET /health` is the liveness check.
- **Receipts:** metering. Appends per tenant per month, leaves in total, and live tokens, on the admin page and as `/admin/usage.csv?month=YYYY-MM`.
- **Python:** unchanged; released in step.

## 0.5.4 — 2026-09-08

- **Receipts:** the witness. `agent-custody witness` runs on a machine the log's operator does not control, fetches each watched log's latest published checkpoint, verifies it against the log's published keys, proves with the log's own consistency proof that it extends the last head the witness signed, and countersigns it, DSSE allowing several signatures on one envelope; a rewritten history, a second history at the same size, or a checkpoint signed by an unpublished key gets an alarm file instead. It publishes its key at `/.well-known/agent-custody-witness.json`. `audit --witness-url` or `--witness-key` requires the witness's signature on the newer head, and `--older`/`--newer` accept checkpoint files from either host. Mirrored in the browser verifier. Phase 6 of issue #6: the code; running it needs a second operator.
- **Deploy:** `deploy/witness/`, a separate compose stack with `ROLE=witness` and its own host.
- **Python:** unchanged; released in step.

## 0.5.3 — 2026-09-08

- **Receipts:** `log --trust-proxy`. Behind a reverse proxy every request arrives from the proxy's address, so the per-address limits, the admin failure throttle above all, were shared by everyone and one client's wrong attempts could lock the page for all. With the flag, and `TRUST_PROXY=1` in the container, limits key on the first `X-Forwarded-For` address; off by default, since the header is otherwise the client's to forge. The compose file sets it because Caddy is the only way in.
- **Python:** unchanged; released in step.

## 0.5.2 — 2026-09-08

- **Receipts:** the admin page itself is gated. Everything under `/admin`, the page included, needs the admin token, presented by the browser's own prompt as HTTP Basic or by an API client as a bearer; wrong attempts from one address are throttled. The page stores nothing. In 0.5.1 the page shell was served without the token while every request it made required it.
- **Python:** unchanged; released in step.

## 0.5.1 — 2026-09-08

- **Receipts:** the operator's admin page. `/admin` on a Postgres-backed log server, behind `--admin-token-env`: tenants listed and created, a token minted and shown once beside the tenant's welcome sheet, tokens revoked, tenants disabled. One inline page, no outside requests. `ADMIN_TOKEN` turns it on in the container.
- **Receipts:** the combined checkpoint store reports the store furthest behind as latest, so a store that missed a write is caught up on the next publication; the image creates `/checkpoints` owned by the log's user.
- **Deploy:** `onboard-tenant.sh` for the shell path; the early-access page says the log is running and taking tenants.
- **Tests:** a thirty-second budget per test in every package; PGlite's engine load is paid in setup.
- **Python:** unchanged; released in step.

## 0.5.0 — 2026-09-08

- **Receipts:** the log over Postgres. `log --db-env` keeps leaves as hashes in one table keyed by tenant, one writer per tenant by advisory lock so a second instance is safe, tenants and sha256-hashed tokens in tables managed by `log-admin`, rate limits per token with a body cap and `retry-after`, retries in the HTTP sink, and `import` for an existing file log. Phase 2 of issue #6.
- **Receipts:** the signer, the key document, and checkpoints. `signer` holds the log's key in its own process and the log signs through `--signer-url`; the log serves `/.well-known/agent-custody-log.json` and `verify --log-url` and `audit --log-url` fetch and pin its keys by keyid; signed checkpoints per log are published to a directory and a table and listed at `/checkpoints`. Phase 3 of issue #6.
- **Deploy:** Postgres and the signer are in the default compose profile, with a checkpoints volume served from a second Caddy host; `--profile file` keeps the single-file server. The image installs `pg`.
- **Python:** unchanged; released in step.

## 0.4.0 — 2026-09-08

- **Receipts:** a log for someone else. `"hashOnly": true` in the `log` config sends only the leaf hash, so a remote log commits to a receipt without ever holding it; the receipts stay with the issuer and the verifier is unchanged. The reference server accepts `{leaf}` or `{leafHash}`, serves several tenant logs at `/t/<tenant>/` from a `--tenants` file with their own tokens and ids, and writes `--log-id` into every tree head. `verify --log-id` and `audit --log-id` check that the tree heads name the expected log. Phase 1 of the hosted log, issue #6.
- **Deploy:** the log server as a container, `ghcr.io/ch4r10t33r/agent-custody-log`, built for amd64 and arm64 by a workflow on every `v*` tag; a docker compose file for one VM with a Caddy TLS profile; Kubernetes manifests on the same contract; `AGENT_CUSTODY_LOG_ID` and `AGENT_CUSTODY_LOG_TENANTS` in it.
- **Site:** the landing page is a quarter of its former length and says what the default install proves and what it does not; a trust-by-setup table; the hosted log stated as not yet built; certified forget defined by what it reaches; the gateway's bypasses listed.
- **Python:** unchanged; released in step.

## 0.3.0 — 2026-09-08

- **Receipts:** pre-commit authorization for consequential tools. Name them in `precommit` (or `*`) and the gateway signs an authorization statement and appends it to the log before forwarding the call; if the log will not take it the call is withheld, nothing goes upstream, and the receipt records `allow` beside `withheld`. The receipt embeds the committed authorization with its inclusion proof, and the verifier adds five checks that it is the issuer's, names this call, is in the log, and precedes the receipt. Mirrored in the browser verifier; three new conformance vectors; tutorial 16. Evidence now precedes the side effect for the calls where that matters.
- **State:** `agent-custody-memory explain`. From a receipt id: who acted, who authorized it, what was allowed, what the agent saw, what it did, why, the evidence, whether it verifies, what depended on it, and what needs reversal. The first eight come from the receipt alone; the last two from the ledger, and without one they read "unknown". `--out --sign` writes the same as one signed action pack with every downstream receipt inside; `--verify` checks it as a whole.
- **Receipts:** the REST connector. An upstream may be a plain HTTP API described as tools, `{ "rest": { "baseUrl", "headerEnv", "tools": [...] } }`, credentials read from the environment at startup. Scope, policy on the gateway's own lookups, pre-commit, and receipts apply unchanged, and a REST upstream sits beside MCP upstreams behind one grant. Tutorial 17.
- **Receipts:** OpenTelemetry export. `otel` in a gateway or SDK config sends one OTLP/HTTP span per receipt to the collector you already run, trace id equal to the receipt id, after the receipt and never on the evidence path. No OpenTelemetry SDK dependency. Tutorial 18.
- **Site:** the landing page leads with proof of what an agent did, the six steps a call goes through, and the questions every receipt answers.
- **Python:** unchanged; released in step.

## 0.2.0 — 2026-09-07

- **State, breaking:** the ledger is asynchronous. Every method returns a promise, `size` is `count()`, `close()` and `export()` return promises, and `blastRadius` and `buildPack` are awaited. Code written against 0.1.x must add `await`; nothing else changes.
- **State:** the ledger holds no events. Every question is a query to the store: everything about the facts matching a filter, everything that touched one fact, the spaces that exist. SQLite answers each from an index on fact, time, space, subject, predicate, and supersession, and fills those columns on a ledger written by an earlier version the first time it opens it. Closes #8.
- **State:** Postgres as a store, for a ledger shared by several servers in the database you already run. `--ledger postgres://…` with the `pg` package installed, or `new PostgresStore(pool)` in code. Forget is an update followed by `VACUUM FULL`, so the old row image does not stay in the table; `vacuum: false` leaves that to your schedule. Tested against the real engine in-process through PGlite, including that a forgotten value is absent from the database files.
- **State:** `Ledger.get`, `learnedBefore`, `spaces`, and `compact`; sweeps compact once at the end rather than per fact.
- **Site:** the landing page says where the ledger lives.

## 0.1.9 — 2026-09-07

- **State:** the custody pack, `agent-custody-memory pack`: one fact's history with the receipt behind each event, its holds, its blast radius with every downstream receipt, and its forget certificate with what the stores answered, as one signed artefact; `pack --verify` checks the signature, the digest, every receipt inside against the gateway's keys, and that the forget receipt names the fact.
- **State:** removal verification. After a retraction, forget, or sweep the server asks each store's own search whether the value still surfaces, with bounded retries, and records `verified`, `stillIndexed`, `unverified`, or `failed` per store in the result and so in the receipt. Mem0 and Zep verify through their search APIs.
- **State:** the memory server warns at startup when no forget key is set, since a plain digest of a short value is guessable.
- **Site:** a deployment page with the architecture and measured sizing, and this changelog.

## 0.1.8 — 2026-09-07

- **State:** the eval harness as a CLI, `agent-custody-memory eval`, with validated scenario files for a team's own incidents, the naive baseline scored beside the ledger, a non-zero exit on regression for cron, and a signed report a reviewer verifies with `eval --verify`.
- **State:** a storage interface for the ledger. JSONL stays the default and the auditable file; a path ending in `.sqlite` or `.db` selects SQLite, with write-ahead logging, secure delete and a truncating checkpoint on forget so no erased value lingers, and a file several processes can open. `export` writes the JSONL of any ledger.
- **Receipts:** provider-native deliveries. An upstream wrapping Stripe or GitHub attaches the signed webhook or delivery for a call; a verifier with the shared secret checks the HMAC, Stripe's timestamp against the receipt's, and the binding of the delivery to the result, and reports the execution as attested by shared secret. `verify --stripe-secret-env`, `--github-secret-env`; three new conformance vectors; the browser verifier mirrors the check.

## 0.1.7 — 2026-09-07

- **State:** forget digests can be keyed under a secret held outside the ledger (`--forget-key-env`) or omitted (`keepDigest: false`), so an erased value cannot be guessed back from the file. The event records which.
- **State:** retention windows per space in the server (`--retention 'org=P365D,team:*=P90D'`); a sweep with no cutoff uses them; `sweep --via gateway.json` runs retention as a receipted call by the principal in that gateway's grant, for any timer.
- **Receipts:** `prune` replaces log leaves older than a cutoff with their hashes and removes their bundles; every proof still verifies.
- **Receipts:** the Merkle log caches complete subtrees, so appends and proofs are logarithmic; receipt cost is flat at 0.15 ms regardless of log size.
- A test loads every receipts module under plain Node, after a construct plain Node rejects broke process-spawning tests for one commit.

## 0.1.6 — 2026-09-07

- **Receipts:** several upstreams behind one gateway and one grant, each tool owned by exactly one; the receipt names which served the call.
- **State:** value-level quarantine. A write may cite a fact the gateway fetched itself; the value must match and the fact is written as `verified`, the provenance level above `attested`, or the write is refused. `requireVerified` on reads.
- **State:** retention sweeps and legal holds, as events with actor, reason, and receipt; a held fact cannot be forgotten or swept until released.
- **Python:** the memory tools over MCP against the shared memory server. Python 3.10 or later.

## 0.1.5 — 2026-09-07

- **Receipts:** consumed facts. An upstream declares the facts it served; every later gateway receipt in the session carries them, observed.
- **State:** blast radius: from a fact to every later call and derived belief, transitively, with retraction status. `agent-custody-memory blast`.
- **State:** policy over provenance: the gateway looks up the fact a write supersedes or a retraction targets through `memory.get`; optional fact lookups in the gateway.
- **State:** certified forget: the value erased from the ledger and every store, the gateway's receipt as the certificate.
- **State:** the memory server over HTTP with bearer auth; the gateway reaches any running MCP server by URL.
- **Receipts:** attested execution: an upstream signs its result for the receipt; the memory server and the demo upstream sign with `--key`.

## 0.1.4 — 2026-09-07

- **State:** quarantine. Facts carry `claimed` or `attested` provenance; claimed facts are hidden from reads until a gateway-only `memory.confirm` lifts them.
- **State:** the memory-mutation eval harness, with the ledger and a naive overwrite store as reference points.
- **State:** write-through adapters for Mem0 and Zep, tested against the real client packages offline; custody metadata travels with the write, retractions reach the store.

## 0.1.3 — 2026-09-07

- **Receipts:** the log sink: append to a remote log whose key signs the tree heads; the reference log server with bearer auth; consistency proofs and the `audit` command; the sidecar (`serve`) for agents in other languages.
- **State:** the memory server: the ledger as MCP tools behind the gateway, with the source receipt id and the attested actor supplied by the gateway.
- **Receipts:** conformance vectors published with the spec.

## 0.1.2 — 2026-09-06

- **Receipts:** the sidecar, required by the Python client.
- **Python:** `agent-custody` on PyPI: a standard-library client of the sidecar with adapters for LangChain, the OpenAI Agents SDK, and the Claude Agent SDK. Go, Java, and Rust clients as examples.

## 0.1.1 — 2026-09-06

- The root walkthrough, the cross-package example, and the first end-to-end use of both packages from a fresh install.

## 0.1.0 — 2026-09-06

- First publish: `@agent-custody/receipts` (gateway, SDK, log, verifier) and `@agent-custody/state` (the bitemporal fact ledger).
