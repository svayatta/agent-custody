# The door: a receipted reverse proxy in front of your own site or API

The gateway stands between an agent and the tools it uses. The door stands between the world and your own HTTP surface: a website, an API, a form. Every arrival, a browser, an API client, a crawler, or an agent acting for someone, is classified by what it presented, decided by a Cedar policy for the route it hit, relayed to your origin or refused, and receipted either way. The receipt is the same signed, logged, independently verifiable receipt the gateway issues, with `issuer.kind: "door"`.

This is the first piece of the agent front door. It answers "what may this arrival do here" and "what did it do, provably". It does not yet answer "is this an agent" for web traffic: that is detection, and the door records only what it can check. Read [what the door knows](#what-the-door-knows-about-an-arrival) before writing a policy.

```bash
agent-custody keygen --dir keys --name door
agent-custody check --config door.json
agent-custody door --config door.json --port 8780
```

## The config file

`door.json`, paths relative to the file. Loaded with `loadDoorConfig(path)`.

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000", "timeoutMs": 30000 },
  "routes": [
    { "name": "catalogue", "methods": ["GET"], "path": "/catalogue/*" },
    { "name": "refund", "methods": ["POST"], "path": "/refunds" },
    { "name": "api", "path": "/api/*" }
  ],
  "unmatchedRoute": "other",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

| field | meaning |
| --- | --- |
| `identity.keyFile` | the door's Ed25519 key; signs every receipt. From `agent-custody keygen` |
| `origin.url` | where allowed arrivals are relayed: the site or API behind the door. `headers` and `headerEnv` add headers to every relayed request, the latter from the environment, so the origin can require a secret only the door holds. `timeoutMs` bounds one relayed request, default 30 s. A path in the URL (`https://host/api/v1`) is kept: the arrival's path goes under it, and a redirect from the origin to a place under it comes back as a door path |
| `routes` | what the policy sees as the action. `path` is exact (`/refunds`), a prefix (`/api/*`), or `*`; `methods` narrows it, default every method. The first route that matches wins; an arrival no route matches is the action `unmatchedRoute`, default `other`. The match reads the path as the origin will: percent-decoded once, so `/%61dmin` falls under `/admin/*`; the origin is sent that form. A path with a segment that does not decode, or decodes to a slash or a backslash, falls under `unmatchedRoute` and is never relayed |
| `trustedPrincipalKeys` | public keys of principals whose signed grants the door accepts as a passport. Without any, no arrival can be `verified` |
| `policyFile` | the Cedar policy, re-read when the file changes; one that does not parse is refused and the policy in force stays |
| `mode` | `enforce` (default) refuses what the policy denies. `observe` relays everything and records the decision with `enforced: false` |
| `trustProxy` | behind one reverse proxy you run: the arrival's address is the last in `X-Forwarded-For`, the one your proxy appended; everything before it is what the client sent. The proxy's `X-Forwarded-For`, `-Proto`, and `-Host` are kept on the relay, with the door's own socket address appended; without `trustProxy` whatever the client wrote in them is replaced |
| `maxBodyBytes` | the largest request body the door relays; a larger one gets 413 and a `withheld` receipt once the policy has allowed it. Default 10 MiB |
| `precommit` | route names whose arrivals are committed to the log before they are relayed whatever their method, or `["*"]`. Every arrival whose method is not GET, HEAD, or OPTIONS is committed regardless; see [before the origin hears of it](#before-the-origin-hears-of-it). Default `[]` |
| `challenge` | the human branch: `{ provider: "turnstile" or "hcaptcha", siteKey, secretEnv, header?, timeoutMs? }`. A token an arrival sends in `header` (default `x-agent-custody-challenge`) is verified with the provider, and the outcome is the arrival's `challenge` signal; see [challenging a human](#challenging-a-human). The secret comes from the environment variable, read at startup; missing is a startup error |
| `receiptsDir`, `logFile` or `log`, `otel`, `splunk`, `capture`, `captureKeyEnv` | as for the [gateway](configuration.md): where receipts and the log go, exporters, and private evidence per route. A remote `log` needs `log.keys`, because its answer is checked before a request is relayed |

`agent-custody check --config door.json` reads a door config the way the door would: unknown keys, the key, the principal keys, the policy (including a permit that names an agent without requiring a verified arrival, see below), the routes, what is precommitted, the challenge provider or its absence, the origin's scheme, every credential variable the door reads at startup (origin headers, the log, Splunk, OTel, the capture key, the challenge secret), and the paths. It exits 1 on an error.

## What the door knows about an arrival

The door records one fact for every arrival, `arrival`, observed by the door itself, and the policy reads it as `context.facts.arrival`:

| field | values | meaning |
| --- | --- | --- |
| `class` | `verified`, `claimed`, `unknown` | `verified`: a grant signed by a trusted principal, inside its window, naming this route among its scopes. `claimed`: something was asserted that the door could not accept: a grant from a stranger, an expired one, one for other routes, a declared agent name, or an HTTP signature header. `unknown`: nothing was presented |
| `subject` | string | the agent named in a verified grant; else the declared name or the agent a rejected grant named; else `unknown`. Only a verified subject reaches the Cedar `principal` |
| `grant` | `verified`, `out-of-scope`, `invalid`, `absent` | what became of the grant header, with `grantError` when it was not accepted |
| `signature` | boolean | an RFC 9421 `Signature-Input` header was present. **Not checked yet.** It is a claim |
| `declared` | string | the `x-agent-custody-agent` header, when sent. A claim |
| `remote` | string | the arrival's address |
| `challenge` | `{ provider, outcome, error? }` | only when `challenge` is configured. `passed`: the provider confirmed the token the arrival sent. `failed`: the provider refused it, `error` carries its codes. `unavailable`: the provider did not answer in time. `absent`: no token. A passed challenge leaves `class` as it was: it says a provider's test was passed in front of this arrival, not who the arrival is |
| `rate` | `{ by, burst, minute }` | arrivals from the same source in the last 10 and 60 seconds, this one included, whatever was decided about them, counted by this door process alone. `by` is `agent` for a verified arrival (counted by the agent's name across addresses) or `remote` (by address). A pace, not a verdict |
| `method`, `path`, `route` | strings | what arrived, and the route it fell under |

[Door signals](door-signals.md) says, for each field, what it establishes and what it does not, and how a policy should read it.

There is no `human` class. The door cannot tell a person from a program that presents nothing, and it does not pretend to. With `challenge` configured, a policy can require a passed challenge on a route instead; without it, a policy that lets `unknown` through on a route is letting everything through on that route, and should say so.

**Presenting a passport.** An agent presents its grant exactly as it does to the HTTP gateway: the DSSE envelope as base64url in `Authorization: Bearer <value>` or in `X-Agent-Custody-Grant`. The scopes of the grant are route names. A grant that travelled in `Authorization` is stripped before the request is relayed, so the origin never sees it; one in the custom header is stripped too. The door's own headers are added to the relayed request: `X-Agent-Custody-Receipt` (the receipt id), `X-Agent-Custody-Class`, and `X-Forwarded-For`, `-Host`, `-Proto`.

**Challenging a human.** The door builds no CAPTCHA. With `challenge` configured, a page in front of a protected route renders the provider's widget (Cloudflare Turnstile or hCaptcha) with `siteKey`, and sends the token the widget produced in the `challenge.header` header of its request. The door posts the token, the secret from `secretEnv`, and the arrival's address to the provider's `siteverify` endpoint, with a timeout, and records the answer as `challenge.outcome`. The token is stripped before the request is relayed, and neither the token nor the secret is recorded. A policy admits a person on a form route with

```cedar
permit(principal, action == Action::"refund", resource)
when { context.facts.arrival.challenge.outcome == "passed" };
```

and a refused arrival that has not passed is told how in the 403 body: `challenge: { provider, siteKey, header }`, so a page can render the widget and try again. The outcome is a signal, not a class: a `verified` agent that also passes a challenge is still the agent its grant names, and an `unknown` arrival that passes is still `unknown`, with `challenge.outcome: "passed"` beside it. What the provider's pass means, and what it does not, is in [door signals](door-signals.md). Passkeys are not a provider here: a passkey proves possession of a credential the site registered, which is a login, not a challenge, and belongs to the origin.

## How an arrival becomes a Cedar request

| Cedar slot | value |
| --- | --- |
| `principal` | `Agent::"<agent>"` for the agent a verified grant names; `Agent::"unknown"` for every other arrival. A declared name and the agent a rejected grant names stay in the arrival fact: a permit on `principal == Agent::"shopping-agent"` cannot be satisfied by sending a header |
| `action` | `Action::"<route>"` |
| `resource` | `Tool::"<route>"` |
| `context.args` | `{ method, path, query, headers, body?, bodyBytes, bodyDigest }`. `headers` carries `user-agent`, `content-type`, `accept`, and `host` only. `body` is present for a JSON body of at most 64 KiB; every body the door read is recorded by `bodyDigest` (sha256 of the raw bytes) and `bodyBytes`. A body above `maxBodyBytes` is dropped as it passes the limit and recorded as `bodyBytes` read so far and `bodyOversized: true`, with no digest and no `body`. **Provenance: claimed** |
| `context.facts.arrival` | the fact above. **Provenance: observed** |
| `context.grant` | `{ principal, scopes }`, present only when the arrival is `verified`. **Provenance: attested** |

Every rule the gateway's policies obey applies: default deny, `forbid` wins, an evaluation error is a deny, the policy digest is in the receipt. A policy for the shop in the tutorial:

```cedar
// The catalogue is public: humans, agents, anyone.
permit(principal, action == Action::"catalogue", resource);

// Refunds: a verified agent, in its grant's scope, for a positive amount of at most £50.
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};

// Everything else on the API is for verified agents.
permit(principal, action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };
```

A refund without a JSON body, or with no `amount`, is an evaluation error and a deny. That is the behaviour you want in front of a payments route. The bound has two ends on purpose: `amount <= 5000` alone admits `{"amount": -1}`, and the door relays the body as it came.

A permit that names an agent, `permit(principal == Agent::"shopping-agent", action == Action::"refund", resource)`, admits only an arrival whose verified grant names that agent, since nothing else reaches the principal slot. `agent-custody check` still warns on such a permit when it does not also require `context.facts.arrival.class == "verified"`: the same text in a gateway policy reads differently, and the condition says what the permit relies on.

## Before the origin hears of it

A request that can change something at the origin, any method but GET, HEAD, and OPTIONS, and any arrival at a route named in `precommit`, is committed to the log before it is relayed, exactly as the gateway's precommit does for a consequential tool call: the door signs an authorization statement (the receipt without its outcome), appends it, writes it as `receipts/<receiptId>.authorization.json`, and only then relays. The receipt embeds it as `authorization`, and the verifier checks that it names this receipt and sits in the log before it. A door that dies between the relay and the receipt leaves the authorization behind, so the side effect has a record and a retry can be told from a first attempt. If the log will not take the authorization, the request is not relayed: 503 and a `withheld` receipt. In observe mode it is relayed and the missing authorization is printed.

## What the arrival gets back

| the door's decision | HTTP | body | receipt `execution.status` |
| --- | --- | --- | --- |
| policy allows, origin answered | the origin's status and body, plus the door's headers | the origin's | `executed`, or `failed` when the origin answered 5xx |
| policy denies, whatever the body's size | 403 | `{ error, reason, receipt }`, plus `challenge: { provider, siteKey, header }` when a challenge is configured and this arrival has not passed it | `denied` |
| origin unreachable or timed out | 502 | `{ error, detail, receipt }` | `error` |
| policy allows, body above `maxBodyBytes` | 413 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the log refused the authorization | 503 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the path does not decode cleanly | 400 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the origin's response above 32 MiB | 502 | `{ error, receipt }`, and "do not retry" | `executed` or `failed`: the origin acted; `result` carries the status and `bodyOversized: true`, no digest |
| the receipt could not be written | 500 | `{ error, outcome, receipt }` | none on disk; `outcome` says whether the origin acted, so that a refund is not retried on the strength of a 500 |

A redirect from the origin to its own address is rewritten to a path, so the client's next request comes back through the door and is classified again; a redirect elsewhere is relayed as sent. Every `Set-Cookie` the origin sent reaches the client. An `Expect: 100-continue` is the client's conversation with the door, which answers it; the origin does not see the header.

Every answer carries `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class`. When the log did not take the receipt, it waits in `receipts/outbox/` and the answer also carries `X-Agent-Custody-Log-Pending: true`; a serving door appends the outbox every 30 seconds, as the gateway does.

`GET /.well-known/agent-custody-door` answers the door's key id, the policy digest in force, the version, and the count of pending receipts.

## The receipt

A door receipt is a v0.2 receipt with `issuer.kind: "door"` and `issuer.framework: "http"`. The route is the tool, observed. `request.args` is the arrival as the table above describes it, claimed. `facts.arrival` is the door's observation. When the arrival was verified, `principal` and `agent` are attested and `delegation` carries the grant; otherwise `principal` is `{ id: null, provenance: "claimed" }` and `agent` is the subject, claimed. `execution.result` for a relayed call is `{ status, contentType?, bodyBytes, bodyDigest }`: the origin's body is never copied into the receipt, only committed to.

The verifier runs `door receipt carries a policy decision` in place of the gateway's two checks, and otherwise the same checks: a verified arrival's receipt passes `delegation binds principal and agent` and `executed tool within delegated scope`; an unknown arrival's passes `principal is claimed, not attested`; a receipt that carries an `authorization` passes the authorization checks, including `authorization logged before execution`. Both verifiers, the Python verifier, and `policy simulate` accept door receipts; the conformance vectors `door-unknown-executed`, `door-unknown-denied`, and `door-verified-executed` pin them.

## What it does not do yet

- Detect agents in web or API traffic. The only signals are the ones in the arrival fact: `signature` and `declared` are claims, and `rate` is a pace ([door signals](door-signals.md)).
- Check RFC 9421 HTTP message signatures, Web Bot Auth directories, or AP2 mandates. The grant is the only passport today.
- Challenge an arrival with a passkey. Turnstile and hCaptcha are the providers; see [challenging a human](#challenging-a-human).
- Revoke a grant by a revocation list; a grant stands until it expires.
- Stream a request body: the body is read whole, up to `maxBodyBytes`, so that the policy can read it and the receipt can commit to it.
- Relay a response larger than 32 MiB, or stream one: the body is relayed whole so that its digest can be recorded. A larger one is not held: reading stops at the limit, the client gets 502, and the receipt records that the origin answered.

Tutorial: [40-door.ts](../examples/40-door.ts).
