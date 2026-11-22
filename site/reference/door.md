# The door

> Every field, route, and flag. How it works and when to use it is in [the guide](/receipts/door).

A reverse proxy in front of your own website, API, or forms. Where the [gateway](./gateway) sits between an agent and its tools, the door sits between the world and your HTTP surface. Every arrival is classified by what it presented, decided by a Cedar policy for the route it hit, relayed to your origin or refused, and receipted either way with the same signed, logged receipt, `issuer.kind: "door"`. The guide is [the door](/receipts/door); this page is the exact contract.

## Config

`door.json`, paths relative to the file. `loadDoorConfig(path)`; schema `DoorConfigSchema`.

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000", "headers": { "x-via": "door" }, "headerEnv": { "x-door-secret": "DOOR_SECRET" }, "timeoutMs": 30000 },
  "routes": [
    { "name": "catalogue", "methods": ["GET"], "path": "/catalogue/*" },
    { "name": "refund", "methods": ["POST"], "path": "/refunds" },
    { "name": "api", "path": "/api/*" }
  ],
  "unmatchedRoute": "other",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "mode": "enforce",
  "trustProxy": false,
  "challenge": { "provider": "turnstile", "siteKey": "0x4AAA...", "secretEnv": "TURNSTILE_SECRET", "hostnames": ["shop.example"] },
  "webBotAuth": { "agents": ["https://crawler.example"], "authorities": ["shop.example"] },
  "partner": { "engine": "datadome", "url": "https://bot-adapter.internal/verdict", "keyFile": "keys/engine.pub", "routes": ["refund", "api"], "timeoutMs": 1500, "onFailure": "deny" },
  "maxBodyBytes": 1048576,
  "maxResponseBytes": 33554432,
  "maxInFlight": 256,
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

| field | type | meaning |
| --- | --- | --- |
| `identity.keyFile` | path | the door's Ed25519 private key; signs every receipt |
| `origin.url` | URL | where allowed arrivals are relayed; a path in it is kept as the prefix of every relayed path. Required by the proxy unless `authz`; absent for the [in-process door](#in-process) |
| `authz` | boolean, optional | answer nginx `auth_request` and Envoy `ext_authz` checks instead of relaying ([authz mode](#authz-mode)); `origin` is then not needed and not used. Requires `trustProxy: true` |
| `origin.headers`, `origin.headerEnv` | maps, optional | headers added to every relayed request; `headerEnv` maps a header name to an environment variable, read at startup, missing is a startup error |
| `origin.timeoutMs` | integer, default 30000 | one relayed request's budget |
| `routes[]` | `{ name, methods?, path }` | the action per arrival. `path`: exact (`/refunds`), prefix (`/api/*`, which also matches `/api`), or `*`. `methods`: a subset of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS; default all. First match wins, on the path percent-decoded once with empty segments merged (`normalizePath`: `//admin/x` and `/admin//x` are `/admin/x`); a trailing slash matches as none (`/refunds/` matches `/refunds`). The origin is sent that form encoded once, trailing slash kept. Names are unique |
| `unmatchedRoute` | string, default `other` | the action for an arrival no route matches |
| `trustedPrincipalKeys` | paths, default `[]` | principals whose grants are passports |
| `revokedGrants` | path, optional | a JSON array of revoked grant digests, the gateway's format; `agent-custody revoke --config door.json` appends to it. Re-read when it changes. A grant it lists, or one delegated from a grant it lists, is `revoked`. Unreadable at start: the door does not start; unreadable later: every grant is `revoked` until it can be read. Missing: no grant is revoked |
| `policyFile` | path | Cedar; re-read on change; a file that does not parse is refused and the policy in force stays |
| `mode` | `enforce` (default) or `observe` | observe relays everything and records `enforced: false` |
| `trustProxy` | boolean, optional | one trusted proxy in front: the arrival's address is the last in `X-Forwarded-For`; the proxy's `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, and `Fastly-Client-IP` are kept on the relay. Without it the door drops all of these and sets its own |
| `maxBodyBytes` | integer, default 1 MiB | a larger request body the policy allowed is refused with 413 and receipted as `withheld`; one the policy refuses is `denied` as any other |
| `maxResponseBytes` | integer, default 32 MiB | a larger origin response is not relayed: 502, and the receipt records the origin's act by size |
| `maxInFlight` | integer, default 256 | arrivals handled at once; past it, 503 with `Retry-After: 1` before the body is read, no receipt |
| `challenge` | `{ provider, siteKey, secretEnv, hostnames, action?, header?, timeoutMs?, maxInFlight? }`, optional | `provider`: `turnstile` or `hcaptcha`. A token in `header` (default `x-agent-custody-challenge`) is posted with the secret from `secretEnv` to the provider's `siteverify`, with the arrival's address as `remoteip` only under `trustProxy`, within `timeoutMs` (default 5000), never following a redirect, and the answer is the arrival's `challenge` signal. To hCaptcha `siteKey` is sent as `sitekey`. It passes only when the provider confirms it and reports one of `hostnames` (required) and, when set, `action` (Turnstile only). A token longer than 4096 characters (`MAX_CHALLENGE_TOKEN`) is `failed` without a call. Provider and operator faults (`internal-error`, `bad-request`, `missing-input-secret`, `invalid-input-secret`, `sitekey-secret-mismatch`, `invalid-sitekey`, `missing-sitekey`, `invalid-remoteip`), a non-200, a non-JSON answer, a redirect, and a timeout are `unavailable`; every other refusal is `failed`, with the codes in `error`. At most `maxInFlight` (default 64) checks wait at once; past that the outcome is `unavailable`. A token serves one request: the provider refuses one it has seen and the door remembers no pass, so a page takes a new token (`turnstile.reset()`, `hcaptcha.reset()`) before every request and every retry. The secret is read at startup; missing is a startup error. The token is stripped before relay and never recorded |
| `webBotAuth` | `{ agents, authorities, requireNonce?, maxAgeSeconds?, clockSkewSeconds?, timeoutMs?, maxDirectoryBytes?, cacheSeconds?, maxNonces? }`, optional | Web Bot Auth: an RFC 9421 signature tagged `web-bot-auth`, Ed25519, is checked against the key its `Signature-Agent` origin publishes, and the outcome is the arrival's `signature` signal. `agents` (required): https origins, no path, whose directories the door fetches; any other signature agent is `invalid` without a fetch. `authorities` (required): the hosts (`host` or `host:port`, lowercase, `:443` and `:80` dropped) this door serves; the covered `@authority` is the request's `Host` and must be one of them. `requireNonce` (default `true`): a signature without a nonce is `invalid`, and a nonce already used with this agent and key is a replay. `maxAgeSeconds` (300): the longest after `created` a signature is accepted, whatever `expires` says. `clockSkewSeconds` (60). The directory is `GET <origin>/.well-known/http-message-signatures-directory`, within `timeoutMs` (3000), never following a redirect, as `application/http-message-signatures-directory+json`, at most `maxDirectoryBytes` (65536), kept `cacheSeconds` (300), a failure retried after 30 s. `maxNonces` (100000): past it a signature is `unavailable`; it bounds the default store, one process's memory, and not a Worker's Durable Object store. The signature must cover `@authority` and the `Signature-Agent` member; the base supports `@method`, `@authority`, `@path`, `@query`, and header fields whole or by `;key` member, and refuses any other component or parameter |
| `partner` | `{ engine, url, keyFile, routes, timeoutMs?, onFailure?, maxInFlight?, maxResponseBytes? }`, optional | A partner detection engine's signed verdict (`src/door-partner.ts`). For an arrival on `routes` (route names, `unmatchedRoute`, or `"*"`; an unknown name is a config error) the door POSTs `url` `{ receiptId, route, method, path, remote, class, headers }` (`headers`: `user-agent`, `content-type`, `accept`, `host`; never the query, body, grant, or cookies), within `timeoutMs` (default 1500), never following a redirect, reading at most `maxResponseBytes` (16384); at most `maxInFlight` (64) wait at once. The answer is `{ verdict: { engine, verdict, score? }, signature }`: `engine` equal to the config's, `verdict` matching `^[A-Za-z0-9_.:-]{1,64}$`, `score` an integer, no other field; `signature` the upstream attestation envelope `{ receiptId, tool: <route>, contentDigest: digestOf(verdict) }` (`signVerdict`), verifying under `keyFile` (Ed25519 public key), naming this arrival's receipt and route, with nothing else in it. Then `arrival.partner` is `{ engine, outcome: "verified" }` and the verdict is `context.facts.partner` and the receipt's `facts.partner`, attested. Otherwise `arrival.partner.outcome` is `rejected` (an answer that is not that) or `unavailable` (no answer in time, a non-2xx, a redirect, `maxInFlight` reached), with `error`, and there is no `partner` fact. `onFailure`: `deny` (default) refuses such an arrival with 503 and `withheld` after the policy, which may still deny it with 403; `absent` lets the policy decide without the fact. Observe mode prints and relays |
| `precommit` | strings, default `[]` | route names whose arrivals are committed to the log before they are relayed whatever their method, or `["*"]`. Every arrival whose method is not GET, HEAD, or OPTIONS is committed regardless |
| `receiptsDir`, `logFile` or `log`, `otel`, `splunk`, `capture`, `captureKeyEnv` | | as for the [gateway](./gateway#the-config-file). Capture rules are keyed by route name. Without a rule for the route and without a `"*"` rule, the door applies `DOOR_DEFAULT_CAPTURE`: `args` in digest mode with `method`, `path`, `headers`, `bodyBytes`, `bodyOversized` in clear; the query, the body, and `bodyDigest` are withheld as `request.args.$rest`; `facts` and `result` clear. A remote `log` needs `log.keys` |

## Running it

```bash
agent-custody check --config door.json
agent-custody door --config door.json [--port 8780] [--host 127.0.0.1]
```

Plain HTTP; bind to loopback or put TLS in front. `check` on a door config reports unknown keys, the key, the principal keys, the policy (and warns on a permit that names an agent without requiring `context.facts.arrival.class == "verified"`), the routes, what is precommitted, the challenge provider or its absence, the Web Bot Auth agents and authorities or their absence (and warns when `requireNonce` is off), the partner engine and whether its key loads, the origin's scheme (or, with `authz`, that the receipts record decisions only), every credential variable the door reads at startup (origin headers, log, Splunk, OTel, capture key, challenge secret), and the paths; exit 1 on an error.

In code: `createDoorHost(cfg, { log?, exporter?, fetch?, autoFlush? })`, which needs `cfg.origin` or `cfg.authz`, returns a `DoorHost` with `keyid`, `policyDigest()`, `handle(req, res)`, `flushOutbox()`, `pendingReceipts()`, `close()`. `serveDoor(host, { port, host?, log? })` returns `{ url, close() }`. `normalizePath(pathname)`, `matchRoute(routes, unmatched, method, path)`, `classifyArrival(req, trustedKeys, route, trustProxy, atIso, signature?)` (which leaves `rate` unset; `req` is an `IncomingMessage` or any `DoorRequest`, `{ method?, url?, headers, headersDistinct?, socket: { remoteAddress? } }`; `signature` is a `SignatureCheck`, and without it a `Signature-Input` is `unchecked`), `authzTarget(req)` (the original request of an authz check as a `DoorRequest`: method from `X-Original-Method`, `url` from `X-Original-URI`, the check's headers and socket; or `{ problem }`), `ORIGINAL_METHOD_HEADER`, `ORIGINAL_URI_HEADER`, `AUTHZ_ALLOWED_REASON`, `signedRequestOf(req)` (a `DoorRequest` without `headersDistinct`, such as a fetch request, gives each field as one value), `cedarArgs(args)`, `DOOR_DEFAULT_CAPTURE`, `createRateTracker(now?, { maxSources?, maxKeyLength? })`, whose clock defaults to the monotonic `performance.now` and which returns `{ hit(source), size(), close() }`, costs the same per hit however full the window, keeps at most `maxSources` (10000) sources, keeps a key longer than `maxKeyLength` (256) as its sha256, and drops stale sources every minute, and `verifyChallengeToken({ provider, secret, token, remoteIp?, hostnames, action?, siteKey?, timeoutMs }, fetch)` are exported for embedding the door in a server of your own. From `web-bot-auth.ts`: `createWebBotAuthVerifier(options, fetch, now?, nonceStore?)` returns `{ verify(signedRequest), nonces() }`, where `verify` resolves a `SignatureCheck`: `{ outcome: "verified", agent, keyid, label }`, `{ outcome: "invalid" | "unavailable", error, agent?, keyid? }`, or `{ outcome: "unchecked" | "absent" }`, and `nonces()` counts the nonces held, or is undefined when the store does not count them. `nonceStore` is a `NonceStore`, `{ check?(key), claim(key, until), size?() }`: `claim` records `<agent> <keyid> <nonce>` until `until` (ms since the epoch) unless it is held, in one step, and answers `claimed`, `replayed`, or `full`; `check`, asked before the directory is fetched, answers `free`, `replayed`, or `full`; a store that throws makes the signature `unavailable`. `createMemoryNonceStore(maxNonces, now?)` is the default, one process's memory; `signatureBase(signedRequest, innerList)` (RFC 9421 section 2.5), `parseDictionary(text)` (RFC 8941), `jwkThumbprint(x)` (RFC 7638 for an Ed25519 key), `normalizeAuthority(host)`, `agentOrigin(uri)`, `DIRECTORY_PATH`, `DIRECTORY_MEDIA_TYPE`, and `WEB_BOT_AUTH_TAG`.

## As a Cloudflare Worker

`deploy/door/cloudflare-worker` is the template; [the guide](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/docs/door-worker.md) says what differs from the Node door and its limits. The Worker runs the same decision core (`src/door-core.ts`) with its I/O from bindings:

| binding | kind | meaning |
| --- | --- | --- |
| `DOOR_CONFIG` | variable, JSON | the door config without the fields that name files or a Node door's modes: `identity`, `policyFile`, `receiptsDir`, `logFile`, `log`, `trustedPrincipalKeys`, `revokedGrants`, `authz`, `trustProxy`, `partner`, `otel`, `splunk`, `origin.url`. A config with one answers 500 with the reason and relays nothing |
| `DOOR_POLICY` | variable | the Cedar policy |
| `ORIGIN_URL` | variable | where allowed requests go |
| `LOG_URL`, `LOG_KEYS` | variables | the log, and its public keys (SPKI PEM), pinned: every append's answer is checked against them |
| `LOG_ID`, `LOG_HASH_ONLY` | variables, optional | the log id every tree head must name; `"true"` to send leaf hashes only |
| `TRUSTED_PRINCIPAL_KEYS` | variable, optional | principal keys (SPKI PEM) whose grants are passports |
| `REVOKED_GRANTS` | variable, optional | a JSON array of revoked grant digests |
| `DOOR_KEY` | secret | the door's signing key, PKCS8 PEM |
| `LOG_TOKEN` | secret, optional | the log token |
| any name the config gives | secret | `challenge.secretEnv`, `captureKeyEnv`, `origin.headerEnv` values |
| `RECEIPTS` | R2 bucket | `<id>.json`, `<id>.authorization.json`, `salts/<id>.json`, `outbox/<id>.json` |
| `NONCES` | Durable Object namespace, class `DoorNonce` | Web Bot Auth nonces, one object per agent, key id, and nonce, reached by every isolate. Needed with `webBotAuth`: without it the Worker answers 500 and relays nothing. An object that fails or does not answer in 3 s makes the signature `unavailable` |

The receipt's `issuer.framework` is `cloudflare-worker`. The arrival's address is `CF-Connecting-IP`; Cloudflare's own `cf-*` and `cdn-loop` headers are not relayed. Where the zone has Bot Management, `request.cf.botManagement` with an integer `score` and a boolean `verifiedBot` becomes the fact `cloudflare` (`{ score, verifiedBot }`, tool `cloudflare.botManagement`, labelled `observed`), read by the policy as `context.facts.cloudflare`. The `scheduled` handler (a cron trigger) appends the outbox. `GET /.well-known/agent-custody-door` and the form protector are served as by the Node door.

In code, from `src/door-worker.ts`: `createDoorWorker({ fetch? })` returns the Worker's `{ fetch, scheduled }`; `workerDoorConfig(env)`, `workerDoorIO(env, fetch)`, `doorRequestOf(request)`, `cloudflareFacts(cf)`, `pemKeys(text)`, `r2Store(bucket)`, `durableNonceStore(namespace, timeoutMs?)` (a `NonceStore` over a `DoorNonce` namespace; default timeout 3000 ms), and the `DoorNonce` class, which the Worker's entry exports. From `src/object-issuer.ts`: `createObjectIssuer(key, store, sink, { capture?, prefix? })`, an `Issuer` over any `{ put, get, list, delete }` store. From `src/door-core.ts`: `createDoorCoreWith(cfg, io, framework, { autoFlush? })` and the `DoorIO` it takes (`key`, `trustedPrincipalKeys`, `readPolicy()`, `policySource`, `revoked(chainDigests)`, `secret(name)`, `issuer(capture)`, `fetch`, `timers`, and `nonceStore?`, the Web Bot Auth nonce store, one process's memory when absent), `relayToOrigin` and `relayedAnswer`; `decide` takes `observed` facts by name. Build with `node packages/receipts/scripts/build-door-worker.ts <outDir>`: one ES module and `cedar_wasm_bg.wasm`, which the Worker imports as a compiled module.

## In-process

`@agent-custody/receipts/door` runs the same decision loop inside a Node site; the guide is [the door in your Node app](/receipts/door-middleware). The config is the one above without `origin`: `door()` refuses a config with one, or with `authz`, and `createDoorHost` and `agent-custody door` refuse a config with neither. `maxResponseBytes` is not used; `agent-custody check` reports a config without `origin` as in-process.

```ts
import { door } from "@agent-custody/receipts/door";
const guard = door("door.json");                 // or a config from loadDoorConfig
app.use(guard);                                   // Express or Connect: (req, res, next)
export const POST = guard.route(async (req) => Response.json({ ok: true }));   // a fetch-style handler: Next.js App Router
```

| export | contract |
| --- | --- |
| `door(config, { log?, exporter?, fetch?, autoFlush? })` | `config` is a path or a loaded `DoorConfig`; throws at once when the door cannot serve it (a missing key, a policy that does not parse, an `origin` or `authz`, a missing secret). `autoFlush` defaults to true. Returns an `InProcessDoor`: a `(req, res, next)` middleware with `route(handler)`, `keyid`, `policyDigest()`, `flushOutbox()`, `pendingReceipts()`, `close()`. One per process: every route it wraps shares its key, log, policy, and rate count |
| the middleware | decides before `next()`. Refused: answers as the proxy does (403, 400, 413, 503, 500, and 503 with `Retry-After: 1` past `maxInFlight`) and never calls `next`. Allowed: sets the door's headers on the response and the request, removes the grant from `req.headers` and `req.rawHeaders`, makes the body it read readable again for what follows (`express.json()`, `for await`, `pipe`), and calls `next()`. A throw before the decision goes to `next(err)` |
| `route(handler)` | `(req, ...rest) => Promise<Response>`, keeping the handler's parameter types. Refused: a `Response` as the proxy answers, and the handler is not called. Allowed: the request's headers are changed in place (a request whose headers are sealed is replaced by a `Request` with the same body), the handler's `Response` is returned with the door's headers, its body streamed to the client and hashed on a tee. A throw is receipted as `error` and rethrown |
| `MIDDLEWARE_FRAMEWORK`, `ROUTE_FRAMEWORK` | the receipt's `issuer.framework`: `node-middleware` and `fetch-route` |
| `formScript()` | the form protector script for the config's `challenge`, or `null`. The middleware answers `GET /.well-known/agent-custody-door/form.js` with it, before deciding anything; a Next.js site serves it from a route |

The request your code gets carries `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class` (a client's own values replaced) and no `X-Agent-Custody-Grant`, `X-Agent-Custody-Agent`, challenge header, or `Authorization` that carried the grant. Client-address headers are left alone. A Web Bot Auth signature is checked as by the proxy; over a fetch request it reads each field as the request holds it (repeated fields joined with `, `), and a request without `Host` takes its authority from its URL. A fetch request has no socket: its `remote` is `unknown`, or with `trustProxy` the last `X-Forwarded-For` address.

The receipt of an allowed request is written after the app's answer: `execution` is `executed` (or `failed` on a 5xx) with `result: { status, contentType?, bodyBytes, bodyDigest }`, the digest over the bytes the app wrote (middleware: through `res.write` and `res.end`; route: the `Response` body); `error` with "the app may have acted on the request" when the connection closed before the response finished, the handler threw, or its body stream failed. The answer carries no `X-Agent-Custody-Log-Pending`, and a receipt that cannot be written is printed on stderr, since the answer has gone. A request that can change something is committed to the log before `next()` or the handler, as before relaying.

## What an arrival presents

| header | effect |
| --- | --- |
| `Authorization: Bearer <base64url DSSE envelope>` or `X-Agent-Custody-Grant: <same>` | a grant, as to the HTTP gateway. Signed by a trusted principal, inside its window, with the route among its scopes: the arrival is `verified`. Otherwise `claimed`, with the reason in the arrival fact. Stripped before relaying. Alone, bearer-grade: the door does not check that the sender holds the agent's key, and a verified receipt carries the grant in `delegation`, so whoever reads the receipt can present the grant until it expires or is revoked (`revokedGrants`). Keep door grants short-lived. Under a verified Web Bot Auth signature from the signature agent the grant names, it is bound to its sender; under another agent's signature it is `wrong-sender` and the arrival `claimed` |
| `X-Agent-Custody-Agent: <name>` | a declared name; `claimed`, never checked. Stripped before relaying |
| `Signature-Input`, `Signature`, `Signature-Agent` (RFC 9421, Web Bot Auth) | with `webBotAuth`: checked as above. Verified and no grant: `verified` as the signature agent's origin. Not verified: `claimed`, `signature` `invalid` or `unavailable` with `signatureError`. Without `webBotAuth`: `signature: "unchecked"`, `claimed`. Relayed to the origin |
| nothing of the above | `unknown` |

## The arrival fact

Recorded as `facts.arrival` (observed) and given to the policy as `context.facts.arrival`:

```json
{ "class": "verified", "subject": "shopping-agent", "grant": "verified", "signature": "absent", "remote": "203.0.113.9", "method": "POST", "path": "/refunds", "route": "refund", "rate": { "by": "agent", "burst": 1, "minute": 4 }, "challenge": { "provider": "turnstile", "outcome": "absent" } }
```

`class`: `verified` | `claimed` | `unknown`. `grant`: `verified` | `out-of-scope` | `invalid` | `revoked` | `wrong-sender` | `absent`, with `grantError` when not verified. `signature`: `verified` | `invalid` | `unavailable` | `unchecked` | `absent`, with `signatureError` when not verified, and `signatureAgent` and `signatureKeyid` when the signature named them (checked only when `verified`). `declared` when the agent header was sent. `rate`: arrivals from the same source in the last 10 s (`burst`) and 60 s (`minute`), this one included, counted in this process; `by` is `agent` (a verified agent's name) or `remote` (the address). `challenge`, only when configured: `{ provider, outcome, error? }`, `outcome` one of `passed`, `failed`, `unavailable`, `absent`; it never changes `class`. `partner`, only for a route in `partner.routes`: `{ engine, outcome, error? }`, `outcome` one of `verified`, `rejected`, `unavailable`. There is no `human` class. `subject` reaches the Cedar principal only when `class` is `verified`. What each field does and does not mean: [door signals](/receipts/door-signals).

## The Cedar request

`principal` `Agent::"<agent>"` for a verified arrival's agent (a grant's agent, or a verified signature's agent origin), `Agent::"unknown"` otherwise; `action` and `resource` the route name. `context.args`: `{ method, path, query, headers, body?, bodyBytes, bodyDigest }`, where `path` is normalised as above, `query` maps names to a string or an array of strings (own properties: `?constructor=x` and `?__proto__=x` are parameters), `headers` carries `user-agent`, `content-type`, `accept`, `host` only, and `body` is present for a JSON body of at most 64 KiB. A body above `maxBodyBytes` gives `bodyBytes` (read so far) and `bodyOversized: true`, no `body`, no `bodyDigest`. The policy reads `cedarArgs(args)`: `null` members dropped, numbers that are not safe integers as strings, since Cedar refuses both; the receipt keeps the body as sent. `context.facts.arrival` as above. `context.facts.partner` `{ engine, verdict, score? }` only when a partner verdict verified. `context.grant` `{ principal, scopes }` only when verified.

## Before relaying

An arrival whose method is not GET, HEAD, or OPTIONS, or whose route is in `precommit`, is committed to the log as an authorization statement before it is relayed, as the [gateway's precommit](./gateway#the-config-file) does; `receipts/<receiptId>.authorization.json`, embedded in the receipt as `authorization`. A refusal by the log: 503, `withheld`, nothing relayed; in observe mode relayed, and printed.

## Responses

| outcome | status | body | headers | receipt `execution` |
| --- | --- | --- | --- | --- |
| relayed | the origin's | the origin's | the origin's, minus hop-by-hop, plus the door's; a `Location` on the origin's host, on any scheme or port, becomes a path on the door: under the origin's path it loses that prefix, and any other path is kept as it is | `executed`; `failed` on an origin 5xx. `result` is `{ status, contentType?, bodyBytes, bodyDigest }` |
| denied, whatever the body's size | 403 | `{ "error": "refused by the door's policy", "reason", "receipt" }`, plus `"challenge": { provider, siteKey, header }` when a challenge is configured and this arrival has not passed it | the door's | `denied` |
| origin unreachable (connection refused, host not resolved) | 502 | `{ "error": "the origin could not be reached", "detail", "receipt" }` | the door's | `error` |
| outcome unknown (timeout, reset, body stopped after the headers) | 504 | `{ "error": "the origin may have acted on the request; its answer did not arrive. Do not retry", "detail", "receipt" }` | the door's | `error`; `error` says the origin may have acted |
| allowed, body too large | 413 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld` |
| allowed, log refused the authorization | 503 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld` |
| allowed, no verified partner verdict, `partner.onFailure` `deny` | 503 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld` |
| allowed, a path segment does not decode or decodes to a slash | 400 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld`, under `unmatchedRoute` |
| allowed, origin's response above `maxResponseBytes` | 502 | `{ "error", "receipt" }` | the door's | `executed` or `failed`; `result` is `{ status, contentType?, bodyBytes, bodyOversized: true }` |
| receipt could not be written | 500 | `{ "error", "outcome", "receipt" }` | `X-Agent-Custody-Receipt`, `-Class` | none; `outcome` says whether the origin acted |
| more than `maxInFlight` at once | 503 | `{ "error" }` | `Retry-After: 1` | none |

The door's headers on every answer: `X-Agent-Custody-Receipt` (receipt id), `X-Agent-Custody-Class`, and `X-Agent-Custody-Log-Pending: true` when the receipt waits in the outbox. On the relayed request: the same two, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` (the socket's address, the `Host`, and `http`; with `trustProxy` the proxy's values, the address appended), `X-Real-IP` (the socket's address, without `trustProxy`), and `Accept-Encoding: identity`; `Expect` is not relayed. Every `Set-Cookie` from the origin is relayed.

`GET /.well-known/agent-custody-door` → `{ "keyid", "policyDigest", "version", "pendingReceipts" }`.

`GET /.well-known/agent-custody-door/form.js` (any query string) → the form protector script (`text/javascript`, `cache-control: public, max-age=300`, `nosniff`) when `challenge` is configured, else 404 `{ "error" }`. It is not decided or receipted. It carries `provider`, `siteKey`, `header`, and `action`, never the secret. In the browser it renders the provider's widget in each same-origin POST form (or those matching `data-forms` on the script tag), sends the form with `fetch` (to the submit button's `formaction`, by its `formmethod` and `formenctype` when it has them; a GET or a cross-site action goes natively) and the token in `header` (removing `cf-turnstile-response`, `h-captcha-response`, and `g-recaptcha-response` from the fields), follows a redirect, writes an HTML answer over the page, shows a refusal under the widget, and resets the widget after each send. `formScript(challenge)` and `FORM_SCRIPT_PATH` are exported from the package and from `@agent-custody/receipts/door`; `DoorHost.formScript()` returns the script or `null`. Guide: [protecting a form with one line](/receipts/door#protecting-a-form-with-one-line).

## Authz mode

With `"authz": true` the door relays nothing: every request except `GET /.well-known/agent-custody-door` is a check from nginx `auth_request` or Envoy `ext_authz` (HTTP mode). Stock configs: `deploy/door/nginx.conf`, `deploy/door/envoy.yaml`; `deploy/door/demo.sh` runs both. The guide is [behind nginx or Envoy](/receipts/door#behind-nginx-or-envoy-authz-mode). Middleware for Go `net/http`, Rack (Rails), Django and WSGI, and the JDK `HttpServer` (with a Spring filter snippet) sends the same check from inside the app: [the door in Go, Rails, Django, and Spring](/receipts/door-languages).

| in the check | read as |
| --- | --- |
| `X-Original-Method` (required, letters only) | the original request's method |
| `X-Original-URI` (required, starting with `/`) | the original request's path and query, normalised as above |
| `X-Forwarded-For` | the arrival's address: the last entry (`trustProxy` is required) |
| the grant, `X-Agent-Custody-Agent`, `Signature`, `Signature-Input`, `Signature-Agent`, the challenge header, `User-Agent`, `Accept`, `Content-Type`, `Host` | as for a relayed arrival; a Web Bot Auth signature is checked against the original method and target and the `Host`, never the check request's own |
| the check's own method, path, and body | ignored; the body is drained unread |

| outcome | status | body | receipt `execution` |
| --- | --- | --- | --- |
| allowed | 200 | `{ "allowed": true, "receipt" }` | `withheld`, reason `AUTHZ_ALLOWED_REASON` (with "Observe mode: ..." appended for an unenforced deny) |
| denied | 403 | as above | `denied` |
| no `X-Original-Method` or `X-Original-URI`, or a URI that is not a path | 400 | `{ "error" }` | none |
| allowed, a path segment does not decode or decodes to a slash | 400 | `{ "error": "not relayed", "reason", "receipt" }` | `withheld` |
| allowed, log refused the authorization | 503 | `{ "error": "not relayed", "reason", "receipt" }` | `withheld` |
| receipt could not be written | 500 | `{ "error", "outcome": "nothing was relayed", "receipt" }` | none |
| more than `maxInFlight` at once | 503 | `{ "error" }` | none |

Every answer carries `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class` as above; the stock configs pass both to the origin on an allow and to the client always. Any method but GET, HEAD, and OPTIONS, and any route in `precommit`, is committed to the log before the 200. `request.args` is `{ method, path, query, headers }`: no `body`, `bodyBytes`, or `bodyDigest`.

## The receipt

Receipt v0.2 with `issuer: { kind: "door", keyid, version, framework: "http" }`, or `framework: "authz"` in authz mode, where the receipt records the decision and never a result. `tool.name` is the route, observed. `request.args` as the Cedar request's `args`, claimed. For an arrival verified by a grant `principal` and `agent` are attested and `delegation` carries the grant; for one verified by a signature alone `principal` is `{ id: null, provenance: "claimed" }` and `agent` is the signature agent, `observed`; otherwise `principal` is `{ id: null, provenance: "claimed" }` and `agent.id` is the subject, claimed. `authorization` is present when the request was committed before relaying. `facts.partner`, when a partner verdict verified, is `{ tool: "door.partner", args: {}, value: <verdict>, resultDigest, provenance: "attested", attestation: <envelope> }`; the envelope stays in clear beside a verdict in clear and is withheld with it under a private facts rule. Verification runs `fact partner signature (upstream key)` on it: with the engine's key as an upstream key (`--upstream-key`) the signature, receipt id, route, and verdict digest are checked; without one it fails (vectors `door-partner-*`, `resigned-door-partner-moved`). Every door receipt's verification runs `door receipt carries a policy decision`, on an authz receipt also `door authz decided, relayed nothing` (an allow `withheld`, a deny `denied`, nothing else), and otherwise the gateway's checks, the authorization checks included; vectors `door-*`. See the [specification](/receipt/v0.2).

## Not yet

Agent detection in web or API traffic of the door's own beyond Web Bot Auth (a partner engine's signed verdict is the slot for it), a credential on the question to a partner engine, Web Bot Auth with algorithms other than Ed25519, `Content-Digest`, directory response signatures, or nonces shared between doors, AP2 mandates, passkeys as a challenge, streamed request bodies, and streamed responses or responses above `maxResponseBytes` (a larger response is cut at the limit: 502 to the client, `executed` with `bodyOversized` in the receipt).
