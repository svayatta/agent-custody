# The door

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
  "maxBodyBytes": 10485760,
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

| field | type | meaning |
| --- | --- | --- |
| `identity.keyFile` | path | the door's Ed25519 private key; signs every receipt |
| `origin.url` | URL | where allowed arrivals are relayed |
| `origin.headers`, `origin.headerEnv` | maps, optional | headers added to every relayed request; `headerEnv` maps a header name to an environment variable, read at startup, missing is a startup error |
| `origin.timeoutMs` | integer, default 30000 | one relayed request's budget |
| `routes[]` | `{ name, methods?, path }` | the action per arrival. `path`: exact (`/refunds`), prefix (`/api/*`, which also matches `/api`), or `*`. `methods`: a subset of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS; default all. First match wins. Names are unique |
| `unmatchedRoute` | string, default `other` | the action for an arrival no route matches |
| `trustedPrincipalKeys` | paths, default `[]` | principals whose grants are passports |
| `policyFile` | path | Cedar; re-read on change; a file that does not parse is refused and the policy in force stays |
| `mode` | `enforce` (default) or `observe` | observe relays everything and records `enforced: false` |
| `trustProxy` | boolean, optional | the arrival's address is the first in `X-Forwarded-For` |
| `maxBodyBytes` | integer, default 10 MiB | a larger request body is refused with 413 and receipted as `withheld` |
| `receiptsDir`, `logFile` or `log`, `otel`, `splunk`, `capture`, `captureKeyEnv` | | as for the [gateway](./gateway#the-config-file). Capture rules are keyed by route name |

## Running it

```bash
agent-custody check --config door.json
agent-custody door --config door.json [--port 8780] [--host 127.0.0.1]
```

Plain HTTP; bind to loopback or put TLS in front. `check` on a door config reports unknown keys, the key, the principal keys, the policy, the routes, the origin's scheme and credential variables, and the paths; exit 1 on an error.

In code: `createDoorHost(cfg, { log?, exporter?, fetch?, autoFlush? })` returns a `DoorHost` with `keyid`, `policyDigest()`, `handle(req, res)`, `flushOutbox()`, `pendingReceipts()`, `close()`. `serveDoor(host, { port, host?, log? })` returns `{ url, close() }`. `matchRoute(routes, unmatched, method, pathname)` and `classifyArrival(req, trustedKeys, route, trustProxy, atIso)` are exported for embedding the door in a server of your own.

## What an arrival presents

| header | effect |
| --- | --- |
| `Authorization: Bearer <base64url DSSE envelope>` or `X-Agent-Custody-Grant: <same>` | a grant, as to the HTTP gateway. Signed by a trusted principal, inside its window, with the route among its scopes: the arrival is `verified`. Otherwise `claimed`, with the reason in the arrival fact. Stripped before relaying |
| `X-Agent-Custody-Agent: <name>` | a declared name; `claimed`, never checked. Stripped before relaying |
| `Signature-Input` (RFC 9421) | noted as `signature: true`; not checked yet; `claimed` |
| nothing of the above | `unknown` |

## The arrival fact

Recorded as `facts.arrival` (observed) and given to the policy as `context.facts.arrival`:

```json
{ "class": "verified", "subject": "shopping-agent", "grant": "verified", "signature": false, "remote": "203.0.113.9", "method": "POST", "path": "/refunds", "route": "refund" }
```

`class`: `verified` | `claimed` | `unknown`. `grant`: `verified` | `out-of-scope` | `invalid` | `absent`, with `grantError` when not verified. `declared` when the agent header was sent. There is no `human` class.

## The Cedar request

`principal` `Agent::"<subject>"`, `action` and `resource` the route name. `context.args`: `{ method, path, query, headers, body?, bodyBytes, bodyDigest }`, where `query` maps names to a string or an array of strings, `headers` carries `user-agent`, `content-type`, `accept`, `host` only, and `body` is present for a JSON body of at most 64 KiB. `context.facts.arrival` as above. `context.grant` `{ principal, scopes }` only when verified.

## Responses

| outcome | status | body | headers | receipt `execution` |
| --- | --- | --- | --- | --- |
| relayed | the origin's | the origin's | the origin's, minus hop-by-hop, plus the door's | `executed`; `failed` on an origin 5xx. `result` is `{ status, contentType?, bodyBytes, bodyDigest }` |
| denied | 403 | `{ "error": "refused by the door's policy", "reason", "receipt" }` | the door's | `denied` |
| origin unreachable | 502 | `{ "error", "detail", "receipt" }` | the door's | `error` |
| body too large | 413 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld` |

The door's headers on every answer: `X-Agent-Custody-Receipt` (receipt id), `X-Agent-Custody-Class`, and `X-Agent-Custody-Log-Pending: true` when the receipt waits in the outbox. On the relayed request: the same two, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `Accept-Encoding: identity`.

`GET /.well-known/agent-custody-door` → `{ "keyid", "policyDigest", "version", "pendingReceipts" }`.

## The receipt

Receipt v0.2 with `issuer: { kind: "door", keyid, version, framework: "http" }`. `tool.name` is the route, observed. `request.args` as the Cedar request's `args`, claimed. For a verified arrival `principal` and `agent` are attested and `delegation` carries the grant; otherwise `principal` is `{ id: null, provenance: "claimed" }` and `agent.id` is the subject, claimed. Verification runs `door receipt carries a policy decision` and otherwise the gateway's checks; vectors `door-*`. See the [specification](/receipt/v0.2).

## Not yet

Agent detection in web or API traffic, RFC 9421 and Web Bot Auth verification, AP2 mandates, a challenge branch, grant revocation lists, and streamed or >32 MiB responses.
