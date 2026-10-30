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
| `origin.url` | where allowed arrivals are relayed: the site or API behind the door. `headers` and `headerEnv` add headers to every relayed request, the latter from the environment, so the origin can require a secret only the door holds. `timeoutMs` bounds one relayed request, default 30 s |
| `routes` | what the policy sees as the action. `path` is exact (`/refunds`), a prefix (`/api/*`), or `*`; `methods` narrows it, default every method. The first route that matches wins; an arrival no route matches is the action `unmatchedRoute`, default `other` |
| `trustedPrincipalKeys` | public keys of principals whose signed grants the door accepts as a passport. Without any, no arrival can be `verified` |
| `policyFile` | the Cedar policy, re-read when the file changes; one that does not parse is refused and the policy in force stays |
| `mode` | `enforce` (default) refuses what the policy denies. `observe` relays everything and records the decision with `enforced: false` |
| `trustProxy` | behind a reverse proxy you run: the arrival's address is the first in `X-Forwarded-For` |
| `maxBodyBytes` | the largest request body the door relays; a larger one gets 413 and a `withheld` receipt. Default 10 MiB |
| `receiptsDir`, `logFile` or `log`, `otel`, `splunk`, `capture`, `captureKeyEnv` | as for the [gateway](configuration.md): where receipts and the log go, exporters, and private evidence per route |

`agent-custody check --config door.json` reads a door config the way the door would: unknown keys, the key, the principal keys, the policy, the routes, the origin's scheme and credential variables, and the paths. It exits 1 on an error.

## What the door knows about an arrival

The door records one fact for every arrival, `arrival`, observed by the door itself, and the policy reads it as `context.facts.arrival`:

| field | values | meaning |
| --- | --- | --- |
| `class` | `verified`, `claimed`, `unknown` | `verified`: a grant signed by a trusted principal, inside its window, naming this route among its scopes. `claimed`: something was asserted that the door could not accept: a grant from a stranger, an expired one, one for other routes, a declared agent name, or an HTTP signature header. `unknown`: nothing was presented |
| `subject` | string | the agent named in a verified grant; else the declared name or the agent a rejected grant named; else `unknown` |
| `grant` | `verified`, `out-of-scope`, `invalid`, `absent` | what became of the grant header, with `grantError` when it was not accepted |
| `signature` | boolean | an RFC 9421 `Signature-Input` header was present. **Not checked yet.** It is a claim |
| `declared` | string | the `x-agent-custody-agent` header, when sent. A claim |
| `remote` | string | the arrival's address |
| `method`, `path`, `route` | strings | what arrived, and the route it fell under |

There is no `human` class. The door cannot tell a person from a program that presents nothing, and it does not pretend to. A challenge step (a CAPTCHA or passkey integration) will add that branch; until then a policy that lets `unknown` through on a route is letting everything through on that route, and should say so.

**Presenting a passport.** An agent presents its grant exactly as it does to the HTTP gateway: the DSSE envelope as base64url in `Authorization: Bearer <value>` or in `X-Agent-Custody-Grant`. The scopes of the grant are route names. A grant that travelled in `Authorization` is stripped before the request is relayed, so the origin never sees it; one in the custom header is stripped too. The door's own headers are added to the relayed request: `X-Agent-Custody-Receipt` (the receipt id), `X-Agent-Custody-Class`, and `X-Forwarded-For`, `-Host`, `-Proto`.

## How an arrival becomes a Cedar request

| Cedar slot | value |
| --- | --- |
| `principal` | `Agent::"<subject>"`: the verified agent, the declared name, or `unknown` |
| `action` | `Action::"<route>"` |
| `resource` | `Tool::"<route>"` |
| `context.args` | `{ method, path, query, headers, body?, bodyBytes, bodyDigest }`. `headers` carries `user-agent`, `content-type`, `accept`, and `host` only. `body` is present for a JSON body of at most 64 KiB; every body is recorded by `bodyDigest` (sha256 of the raw bytes) and `bodyBytes`. **Provenance: claimed** |
| `context.facts.arrival` | the fact above. **Provenance: observed** |
| `context.grant` | `{ principal, scopes }`, present only when the arrival is `verified`. **Provenance: attested** |

Every rule the gateway's policies obey applies: default deny, `forbid` wins, an evaluation error is a deny, the policy digest is in the receipt. A policy for the shop in the tutorial:

```cedar
// The catalogue is public: humans, agents, anyone.
permit(principal, action == Action::"catalogue", resource);

// Refunds: a verified agent, in its grant's scope, for at most £50.
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args.body.amount <= 5000
};

// Everything else on the API is for verified agents.
permit(principal, action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };
```

A refund without a JSON body, or with no `amount`, is an evaluation error and a deny. That is the behaviour you want in front of a payments route.

## What the arrival gets back

| the door's decision | HTTP | body | receipt `execution.status` |
| --- | --- | --- | --- |
| policy allows, origin answered | the origin's status and body, plus the door's headers | the origin's | `executed`, or `failed` when the origin answered 5xx |
| policy denies | 403 | `{ error, reason, receipt }` | `denied` |
| origin unreachable or timed out | 502 | `{ error, detail, receipt }` | `error` |
| body above `maxBodyBytes` | 413 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |

Every answer carries `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class`. When the log did not take the receipt, it waits in `receipts/outbox/` and the answer also carries `X-Agent-Custody-Log-Pending: true`; a serving door appends the outbox every 30 seconds, as the gateway does.

`GET /.well-known/agent-custody-door` answers the door's key id, the policy digest in force, the version, and the count of pending receipts.

## The receipt

A door receipt is a v0.2 receipt with `issuer.kind: "door"` and `issuer.framework: "http"`. The route is the tool, observed. `request.args` is the arrival as the table above describes it, claimed. `facts.arrival` is the door's observation. When the arrival was verified, `principal` and `agent` are attested and `delegation` carries the grant; otherwise `principal` is `{ id: null, provenance: "claimed" }` and `agent` is the subject, claimed. `execution.result` for a relayed call is `{ status, contentType?, bodyBytes, bodyDigest }`: the origin's body is never copied into the receipt, only committed to.

The verifier runs `door receipt carries a policy decision` in place of the gateway's two checks, and otherwise the same checks: a verified arrival's receipt passes `delegation binds principal and agent` and `executed tool within delegated scope`; an unknown arrival's passes `principal is claimed, not attested`. Both verifiers, the Python verifier, and `policy simulate` accept door receipts; the conformance vectors `door-unknown-executed`, `door-unknown-denied`, and `door-verified-executed` pin them.

## What it does not do yet

- Detect agents in web or API traffic. The only signals are the ones in the arrival fact, and `signature` and `declared` are claims.
- Check RFC 9421 HTTP message signatures, Web Bot Auth directories, or AP2 mandates. The grant is the only passport today.
- Challenge an arrival. There is no human branch.
- Revoke a grant by a revocation list; a grant stands until it expires.
- Relay a response larger than 32 MiB, or stream one: the body is relayed whole so that its digest can be recorded.

Tutorial: [36-door.ts](../examples/36-door.ts).
