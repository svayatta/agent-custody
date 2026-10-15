# Contributing

This file holds the rules for one area of the code at a time. The rules for every change are in `CLAUDE.md`, the commands are in the root README, the site rules are in `site/README.md`, and the deploy checks are in `deploy/README.md`.

## Files that change together

- `packages/receipts/docs/policies.md` and `packages/receipts/test/docs-policies.test.ts`: the test executes every Cedar example in the guide.
- The `_meta` keys `agent-custody/receipt`, `agent-custody/agent`, and `agent-custody/observed` are in both packages. The state package duplicates them on purpose, to avoid a runtime import. Keep the strings identical.
- The tenant path regex in `packages/receipts/src/log-sink.ts` lists the permitted tenant operations. Add each new tenant route there.
- A new public module goes into the package's `src/index.ts`. A new adapter gets its own `./sdk/<name>` subpath in the `exports` map.
- The portal and admin pages are TypeScript template literals. Inside the page's own JavaScript strings, write a quote as `\\"` in the source. Their tests compile every inline `<script>` with `node:vm`, because one unescaped `\"` makes the page blank.

## Code rules

- Load `node:sqlite` and `pg` with `createRequire`, never with a static import, so that a JSONL user never loads them. `pg` is an optional peer dependency.
- `issue`, `record`, and `handleHookEvent` are asynchronous, because the log may be remote. A log that refuses a leaf is an error, and no bundle is written. Never swallow that error, except where a framework cannot await. There, print it.
- Exporters (`otel.ts`, `splunk.ts`) swallow their failures, so that a collector is never on the evidence path.
- Do not make a data warehouse an event store of the ledger. A warehouse is an export target.
- `--trust-proxy` stays off by default. Only the container sets `TRUST_PROXY=1`, because Caddy fronts it.
- The deploy scripts print ids, never a secret.

## Adapters

- Test each framework adapter against the real package with a scripted model and no network. A hand-written stand-in alone is not sufficient. The Python tests follow the same rule: they run with `uv run --extra test pytest` against a sidecar started from `packages/receipts/src/cli.ts`, and the TypeScript verifier checks every receipt that they produce.
- Drive each host's documented hook contract as the host drives it. The Claude Agent SDK adapter is the precedent.
- An enforcing adapter blocks the call on a deny after it issues the denial receipt. It also blocks the call when it cannot issue the receipt. The OpenClaw `before_tool_call` hook in `src/sdk/openclaw.ts` is the reference.
- A record-only adapter evaluates no policy. On one tool, an adapter enforces or observes, never both.
- Every adapter calls `denies(policy)` (TypeScript in `sdk/index.ts`, Python in `agent_custody`) before it blocks, so that it never acts on a recorded deny. Observe mode stamps `enforced: false` on a Cedar `PolicyDecision` only. A grant denial (out of scope, expired, revoked) is enforced in every mode (issue #97).
- DeepSeek Harness: `tools/pre-execute` returns `{ kind: "deny", reason }` or `next()`, never `allow`. `Config` is a zod schema, because Cordis requires Standard Schema. A post-execute for a tool that the policy denies records deny and executed, and verification fails. This is correct, because the pre gate runs first in the harness.
- CrewAI: `agent_custody/crewai.py` builds a `CustodyTool` subclass instance that delegates to the original tool's `_run`. Replacing `_run` on a pydantic tool instance has no effect.
- Muse (muse.ai) has no hook surface. Do not build an adapter for it: a connector provider fronts its own API with the gateway.
- Python needs 3.10, because the `mcp` client needs it. Both mcp 1.x and 2.x work. The mcp result flag in Python is `is_error`. `bun run test:python` runs `bun run build` first, because the memory tests need it. The `crewai` extra is large.

## Security invariants

Do not weaken an invariant to make a test pass.

Gateway and receipts:

- The gateway checks the grant on every call and again just before the forward (then `withheld`). A revocation file that it cannot read makes it deny every call, never throw.
- A grant digest is a sha256 over the signed payload, so a repacked envelope keeps its digest. Revoking any link of a delegation chain revokes the grants below it.
- Over HTTP, a grant failure answers 403 with the reason before any session exists. Do not use 401: the MCP client transport treats 401 as an OAuth challenge. A session whose grant expires or is revoked closes on its next request.
- `precommit`: when the authorization append fails, the call is `withheld` and nothing goes upstream. `httpLog` believes no append answer that it has not checked (issue #99). The gateway config refuses `precommit` with a remote log and no `log.keys`.
- The verifier accepts a deny beside an executed call only when the receipt carries `enforced: false` (observe mode).
- An upstream signature covers `{ content, isError }` only, never `_meta`.
- `serveA2a` drops the `signatures` of the card that it serves, because the rewritten card no longer matches them.
- The gateway never reads published policies.

Verifier (`src/verify.ts` and its mirror `site/verifier/verify-web.ts`):

- `canonicalize` builds null-prototype objects, so that an own property named `__proto__` (which `JSON.parse` produces) stays in the digest (issue #102; vector `gateway-executed-proto-key`).
- `verifyBundle` recomputes `execution.resultDigest` on executed and failed receipts: the check `execution result digest` (issue #104; vector `resigned-result-digest`).
- `delegation valid at receipt time` passes a denied or withheld receipt that was issued after the grant window. Only an executed call must be inside the window.
- `delegation chain to the principal` runs when the grant embeds a parent, and walks the chain to the principal's key.

Memory:

- The memory server believes `_meta` only from a caller known to be the gateway. It drops a direct caller's `_meta` whole (issue #95). Gateway tokens and direct-writer tokens are different, and `serve --http` refuses to start without `--token-env`.
- Memory write order is validate, stores, ledger. Retract order is ledger, then stores.
- `memory.repair` removes only the store entries whose fact id the ledger does not know and that were stored before its cutoff, the earlier of `before` and ten minutes ago. A write whose stores take more than five minutes is refused before its ledger append, so a write in progress is never that old.
- One store scope (a pgvector table, a Mem0 user, a Zep user or graph, a Letta agent with its tags, a LangGraph namespace, a Cognee dataset) belongs to one ledger. A repair on one ledger removes the entries of another ledger that shares the scope. The clocks of the memory servers agree to within a few minutes, because `storedAt` comes from the writer and the repair cutoff from the repairer. An entry without a parseable `storedAt` is never repaired.
- A store without `verifyDeleted` is `unverified`, never `verified`. Without a ledger, the explain belief questions read "unknown without a ledger", never "nothing". Receipts inside a custody pack keep the values they recorded, by design.
- `selectAbout` and `selectFor` in `packages/state/src/storage.ts` are the reference semantics. The SQL stores must match them. The ledger suite runs on JSONL, SQLite, and Postgres; a store change is wrong if any backend diverges. `PostgresStore` never closes a client that it was given.

Web pages and the hosted log:

- The review pages, the portal, and the admin page load no outside content. Each sends a content security policy that starts with `default-src 'none'`.
- The review server has no authentication of its own and binds to `127.0.0.1` by default. Keep that default.
- The portal session cookie is `HttpOnly; SameSite=Strict`, and every portal API write requires a JSON body. Together they stop a cross-site page from acting as the user.
- The portal reads Google's id token without a signature check, because the token arrives from Google's token endpoint over TLS in the same code exchange. Do not read an id token from any other source this way.
- The portal links a provider sign-in to a password account only when the account's email is verified (issue #103). The Stripe webhook checks `Stripe-Signature` and never touches an enterprise tenant. It ignores an event id that it applied already, and an event older than the last one applied (issue #105).
- Every path under `/admin`, the page included, needs the admin token. The admin routes throttle failed attempts per address.
- `Verifier.vue` fetches only receipt ids that match `^[0-9a-f-]{36}$`, and only files under `/custody/` on its own origin.
- The log rate-limits each token and caps the request body (64 KiB by default). A tenant route answers only to that tenant's token.
- The log stores tenant tokens as sha256 hashes, never as plain text. An audit row never holds a token.
- The witness must not run on the log operator's machine.

## Tests

- Each package's `vitest.config.ts` sets a 30-second test budget and a 60-second hook budget, because tests spawn gateways and load PGlite. A test that needs longer says so in its own `it(..., ms)`.
- `.githooks/pre-push` runs `bun run ci` before a push to main. Enable it once per clone with `git config core.hooksPath .githooks`. A fresh clone has no hook until you do this.
- When a gate run and the pre-push hook run back to back, the second one runs under load. Do not pack or build while either runs.
- Tests use `node:http` stand-ins, or real client packages against fake endpoints. Set `MEM0_TELEMETRY=false` so that the Mem0 client stays offline.
- `packages/state/test/pgvector.test.ts` runs against the `pgvector/pgvector:pg16` image in Docker, and skips visibly when no daemon runs. PGlite 0.5.8 has no pgvector.
- A test that runs a language client synchronously must not host the sidecar in-process, or the client hangs. A missing toolchain skips its language visibly.

## Release and publish

- Pack with `bun pm pack`, not `npm pack`, so that `workspace:*` dependencies become versions.
- To bump: change the three package versions, the two `"version"` fields in `packages/receipts/server.json`, and the two workspace `"version"` lines in `bun.lock`. Edit the `bun.lock` lines by hand. A blanket search-and-replace of the old version string also changes every dependency pinned at the same string (for example `@electric-sql/pglite` 0.5.8), and `bun install --frozen-lockfile` then hangs silently. Never delete and regenerate the lockfile: that re-resolves every dependency and can break vitest.
- To publish: `bun run build`, then `bun pm pack` in the package directory, then `npm publish <tarball> --access public` from a terminal with `NPM_TOKEN` set (a granular token with the 2FA bypass; the gitignored project `.npmrc` reads it). Publish receipts before state. Then run the `mcp-registry` workflow (Actions tab).
- `.github/workflows/release.yml` runs its check job on every tag. Its npm and PyPI jobs run only when the repository variable `PUBLISH_FROM_CI` is `true`. Set it when trusted publishing is configured on both registries.
