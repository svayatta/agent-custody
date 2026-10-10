# The gateway

A separate process between the agent and its tools. The agent connects to it as an MCP server and sees only the tools its grant names; the gateway checks the grant, fetches the facts the policy needs, evaluates the policy, forwards or refuses the call, and issues a signed receipt whose hash goes to the log. For tools named in `precommit`, the authorization is logged before the call is forwarded.

## The config file

`gateway.json`, paths relative to the file. Loaded with `loadConfig(path)`.

```json
{
  "identity": { "keyFile": "keys/gateway.key" },
  "upstream": { "command": "node", "args": ["memory-server.js"], "env": { "TOKEN": "..." } },
  "grantFile": "grant.json",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "facts": [
    { "name": "customer", "tool": "customer.lookup", "args": { "customer_id": "$args.customer_id" }, "forTools": ["stripe.refund"], "optional": false }
  ],
  "precommit": ["stripe.refund"],
  "receiptsDir": "receipts",
  "logFile": "log.jsonl",
  "otel": { "url": "http://localhost:4318", "headersEnv": { "x-api-key": "OTEL_KEY" }, "serviceName": "support-agents" },
  "splunk": { "url": "https://splunk.example.com:8088", "tokenEnv": "HEC_TOKEN", "index": "agents" }
}
```

| field | type | meaning |
| --- | --- | --- |
| `identity.keyFile` | path | the gateway's Ed25519 private key; signs every receipt. From `agent-custody keygen` |
| `upstream` | one of four shapes | `{ command, args?, env? }` spawns an MCP server over stdio; `{ url, tokenEnv? }` connects to an MCP server over Streamable HTTP with a bearer token from the environment; `{ rest: {...} }` describes a plain HTTP API as tools; `{ a2a: {...} }` is another agent reached over the A2A protocol, both below |
| `upstreams` | array of the above, each with `name` | several upstreams behind one gateway; each tool name must belong to exactly one, checked at startup. Exactly one of `upstream` or `upstreams` |
| `grantFile` | path, *optional* | the signed delegation the stdio gateway serves. Not needed over HTTP, where each connection presents its own |
| `trustedPrincipalKeys` | paths | public keys of principals whose grants are accepted; matched by keyid |
| `policyFile` | path | the Cedar policy; its SHA-256 is in every receipt |
| `facts` | array | lookups the gateway makes itself before deciding: `name` under `context.facts`, the upstream `tool` to call, `args` templates where `"$args.<key>"` copies the agent's argument, `forTools` the intercepted tools that trigger it, `optional` skips the lookup when the template's argument is absent |
| `precommit` | array of tool names or `["*"]` | consequential tools: the authorization is logged before the call is forwarded, and the call is withheld if the log will not take it |
| `mode` | `"enforce"` (default) or `"observe"` | observe forwards every call the grant allows and records the decision the policy would have made, with `enforced: false` on the receipt; nothing is withheld, and a log that refuses an authorization is printed instead. The way to run a new policy against real traffic before turning it on |
| `receiptsDir` | path | one `<receiptId>.json` per receipt, and `<receiptId>.authorization.json` for pre-committed calls |
| `logFile` | path | a local Merkle log, one leaf per line. Exactly one of `logFile` or `log` |
| `log` | `{ url, tokenEnv?, hashOnly?, timeoutMs? }` | a remote log: the tenant's append URL, the bearer token's environment variable, `hashOnly: true` to send only the leaf hash (use it for any log run by someone else), and how long one append may take, default 10000 ms |
| `otel` | *optional* | OpenTelemetry export, one span per receipt, after the receipt, never on its path |
| `splunk` | *optional* | Splunk HTTP Event Collector export, one event per receipt, the token from the environment |

### A REST API as an upstream

```json
{ "rest": {
  "baseUrl": "https://api.example.com",
  "headerEnv": { "authorization": "PAYMENTS_BEARER" },
  "headers": { "accept": "application/json" },
  "timeoutMs": 30000,
  "tools": [
    { "name": "customer.lookup", "method": "GET", "path": "/customers/{customer_id}", "inputSchema": { "type": "object", "properties": { "customer_id": { "type": "string" } }, "required": ["customer_id"] } },
    { "name": "stripe.refund", "method": "POST", "path": "/refunds", "body": "json", "description": "Refund a customer" }
  ]
} }
```

`{name}` segments in `path` are filled from the call's arguments; the remaining arguments go to the query string on GET and DELETE and to a JSON body otherwise, or `query` names the ones for the query and `body: "none"` sends no body. The response body is the tool result, JSON kept as JSON; a non-2xx status is a failed execution with the API's answer in the receipt.

### An A2A agent as an upstream

```json
{ "a2a": {
  "url": "https://docs-agent.internal",
  "headerEnv": { "authorization": "DOCS_AGENT_BEARER" },
  "headers": { "accept": "application/json" },
  "timeoutMs": 120000,
  "prefix": "docs"
} }
```

`url` is the agent's base URL, whose card the gateway fetches at startup from `/.well-known/agent-card.json` or `/.well-known/agent.json`, or the card's own URL when it ends in `.json`. `headers` and `headerEnv` are as for a REST upstream; `timeoutMs` is how long one delegated task may take, streamed or not, default 120000; `prefix` names the tools, default `a2a`, one per A2A upstream. The card decides the wire format: A2A 1.0 (`supportedInterfaces`, `SendMessage`, `ROLE_USER`) or 0.3 (`url`, `message/send`, `kind`). The upstream offers two tools:

| tool | arguments | result |
| --- | --- | --- |
| `<prefix>.send` | `text` (the task; the gateway builds the message) or `message` (a full A2A message, forwarded as is); optional `taskId`, `contextId`, `configuration`, `metadata` | the agent's task or message, as JSON text. A streamed delegation is relayed after the agent finishes, the events in `_meta["agent-custody/a2a-stream"]` and the final task as the result; a JSON-RPC error from the agent is `isError: true` with the error, recorded as `failed` |
| `<prefix>.card` | none | the agent card, fetched afresh; name it in `facts` (`{ "name": "card", "tool": "docs.card", "args": {}, "forTools": ["docs.send"] }`) so a policy reads `context.facts.card.name` |

Programmatically: `a2aUpstream(name, cfg, { fetch?, env? })` returns the upstream client with `resolved(): Promise<ResolvedCard>`; `fetchAgentCard(url, headers, fetch, timeoutMs): Promise<{ card, cardUrl, endpoint, legacy }>` is the lookup it uses; `textOf(message)` joins a message's text parts, which is what a policy reads as `context.args.text`.

## Grants

A grant is a DSSE envelope over this payload, signed by a principal's key:

```json
{ "version": "0.1", "principal": "user_456", "agent": "support-agent", "scopes": ["customer.lookup", "stripe.refund"], "issuedAt": "2026-09-21T09:27:30.384Z", "expiresAt": "2026-09-21T10:27:31.384Z", "agentKey": "-----BEGIN PUBLIC KEY-----…", "parent": { "payloadType": "…", "payload": "…", "signatures": [] } }
```

`agentKey` (*optional*, SPKI PEM) names the agent's own key so it may delegate; `parent` (*optional*) is the grant this one was delegated from. See [delegation chains](#delegation-chains).

```bash
agent-custody grant --key keys/principal.key --principal user_456 --agent support-agent --scopes customer.lookup,stripe.refund --ttl-hours 24 --agent-key keys/agent.pub --out grant.json
```

Programmatically: `createDelegation(principalKey, payload): Envelope`, `verifyDelegation(envelope, trustedPrincipalKeys): { ok: true, delegation, keyid, chain } | { ok: false, error }`, `delegationValidAt(delegation, isoInstant): boolean`.

### Delegation chains

An agent whose grant names its key delegates a narrower grant to a sub-agent:

```bash
agent-custody delegate --key keys/agent.key --parent grant.json --agent refunder --scopes stripe.refund --ttl-hours 2 --out refunder.json
```

`delegateFrom(parentEnvelope, agentKeyPair, { agent, scopes, issuedAt?, expiresAt?, agentKey? }): Envelope` refuses, before signing, a scope the parent lacks or a window outside the parent's. The verifier walks the chain to a trusted principal key, three delegations deep at most: every link signed by the key its parent names, no scope the parent lacks, a window inside the parent's, the same principal throughout. A receipt issued under a chained grant names the sub-agent as `agent`, the principal as `principal`, and carries the whole chain in `delegation.envelope`.

## Running it

**One agent, over stdio.** The agent's MCP host spawns the gateway; the config's `grantFile` is the grant.

```bash
agent-custody gateway --config gateway.json
```

**Many agents, over HTTP.** One process; each connection presents its own grant on `initialize`, base64url of the envelope's JSON, as `Authorization: Bearer <value>` or `X-Agent-Custody-Grant: <value>`.

```bash
agent-custody gateway --config gateway.json --http --port 8790 --host 127.0.0.1 --idle-minutes 30
```

| route | meaning |
| --- | --- |
| `POST /mcp` | MCP Streamable HTTP. The first request of a session must be `initialize` with the grant; the response carries `mcp-session-id`, sent back on every later request |
| `GET /mcp`, `DELETE /mcp` | the session's event stream and its termination, per the MCP transport |
| `GET /health` | `{ "ok": true, "sessions": 2, "keyid": "9d44…" }` |

A grant signed by a stranger, an expired one, or none gets `403` with the reason in a JSON-RPC error body, for example `{ "jsonrpc": "2.0", "error": { "code": -32000, "message": "delegation grant rejected: no trusted key matches keyids [19b2…]" }, "id": null }`. Sessions share the upstreams, the policy, the key, and the log; each has its own tools, its own receipts, and its own consumed facts. Idle sessions close after `--idle-minutes`.

From JavaScript:

```ts
import { createGatewayHost, serveHttp, grantHeader, loadConfig } from "@agent-custody/receipts";
const host = await createGatewayHost(loadConfig("gateway.json"));   // shared: key, policy, issuer, upstreams
const running = await serveHttp(host, { port: 8790 });               // { url, sessions(), close() }
// a client:
new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: `Bearer ${grantHeader(grantEnvelope)}` } } });
```

`host.open(grantEnvelope): Gateway` opens a session by hand; `createGateway(cfg): Promise<Gateway>` is the single-grant form. A `Gateway` has `agentId`, `delegation`, `listTools(): Promise<Tool[]>`, `handleCall({ name, arguments, _meta? }): Promise<CallToolResult>`, and `close()`.

**As an A2A agent.** The gateway speaks A2A itself in front of the config's one `a2a` upstream (exactly one is required, or the command refuses to start). An A2A client, Google ADK's `RemoteA2aAgent` for one, is given the gateway's card URL instead of the remote agent's.

```bash
agent-custody gateway --config gateway.json --a2a --port 8790 --host 127.0.0.1
```

| route | meaning |
| --- | --- |
| `GET /.well-known/agent-card.json`, `GET /.well-known/agent.json` | the remote agent's card with the gateway's own address as its endpoint (`supportedInterfaces[0].url` on a 1.0 card, `url` on a 0.3 card) and its `signatures` removed, since they signed a card that named another address |
| `POST /` | JSON-RPC. `SendMessage` and `SendStreamingMessage` (0.3: `message/send`, `message/stream`) become a `<prefix>.send` call; every other method (`GetTask`, `CancelTask`, the push notification configs) is forwarded to the remote agent as it is, with the `a2a-version` header the client sent |
| `POST /message:send`, `POST /message:stream` | the 1.0 HTTP+JSON binding of the same two methods, the request in the body and the task or message answered without the JSON-RPC wrapper |
| `GET /health` | `{ "ok": true, "agent": "document_agent", "keyid": "9d44…" }` |

A delegation runs under the grant in `grantFile` or, when the request carries one, the grant in `Authorization: Bearer <base64url envelope>` or `X-Agent-Custody-Grant`, as for `--http`; one session per distinct grant. Without a `grantFile` a grant header is required, and a request without one, or with an envelope that does not verify, gets `403` with the reason. `<prefix>.send` receives `text` (the message's text parts joined), `message`, `method`, and the `taskId`, `contextId`, `configuration`, and `metadata` the request carried, so a policy reads `context.args.text`.

What the client gets back, in the remote agent's wire format:

| outcome | answer |
| --- | --- |
| allowed | the remote agent's task or message, with `metadata["agent-custody/receipt"]` set to the receipt id; a stream is relayed after the remote agent finishes, each event carrying the key |
| denied by scope or policy, or withheld because the log refused the pre-commit | a task in state `TASK_STATE_REJECTED` (0.3: `rejected`) with the request's `taskId` and `contextId` or fresh ones, the status message `agent-custody: <reason> (receipt <id>)`, and the receipt id in `metadata`; nothing reached the remote agent |
| the remote agent could not be reached | a task in state `TASK_STATE_FAILED` (0.3: `failed`), the same shape |
| the remote agent answered a JSON-RPC error | that error, with `data.receipt` set to the receipt id; the receipt records the call as `failed` |

```json
{ "jsonrpc": "2.0", "id": "1", "result": { "id": "0f3c…", "contextId": "7a1e…", "status": { "state": "TASK_STATE_REJECTED", "message": { "role": "ROLE_AGENT", "messageId": "…", "parts": [{ "text": "agent-custody: Denied by policy: no permit policy matched (receipt 36c85dc9-…)" }] }, "timestamp": "2026-10-10T09:27:31.401Z" }, "metadata": { "agent-custody/receipt": "36c85dc9-43c1-46a9-9be7-9210210a7aa1" } } }
```

From JavaScript, `serveA2a(host, cfg.a2a, { port, host?, grant?, log? }): Promise<{ url, close() }>` is the same server; `A2A_CARD_PATH`, `A2A_RECEIPT_METADATA_KEY` (`"agent-custody/receipt"`), and `A2A_STREAM_META_KEY` (`"agent-custody/a2a-stream"`) are the constants. Example 25 in the repository runs it in front of a stand-in agent.

## What the agent sees

`tools/list` returns the upstreams' tools filtered to the grant's scopes, unchanged. `tools/call` returns the upstream's result with one addition, `_meta["agent-custody/receipt"]`, the receipt id:

```json
{ "content": [{ "type": "text", "text": "{\"refund_id\":\"re_cf4d8b16\",\"status\":\"succeeded\"}" }], "_meta": { "agent-custody/receipt": "36c85dc9-43c1-46a9-9be7-9210210a7aa1" } }
```

A refused call is a tool error, never an exception, so the agent can carry on:

| execution status | tool result text | what happened |
| --- | --- | --- |
| `denied` | `Denied by policy: <reasons> (receipt <id>)` | the grant or the policy refused it; nothing went upstream |
| `withheld` | `Not executed: the log did not commit the authorization… (receipt <id>)` | a pre-committed tool whose authorization the log refused; nothing went upstream |
| `error` | `Upstream error: <message> (receipt <id>)` | the upstream threw or could not be reached |
| `failed` | the upstream's own error result | the upstream answered `isError: true` |
| `executed` | the upstream's result | forwarded and answered |

The agent may set `_meta["agent-custody/model"]` on a call to have a model id recorded, as `claimed`.

## The policy's view

Each call becomes a Cedar request: principal `Agent::"<agent>"`, action and resource the tool name, and a context:

```json
{ "args": { "customer_id": "cust_123", "amount": 50000 }, "facts": { "customer": { "id": "cust_123", "verified": true } }, "grant": { "principal": "user_456", "scopes": ["customer.lookup", "stripe.refund"] } }
```

`args` is what the agent sent (`claimed`); `facts` is what the gateway fetched itself (`observed`); `grant` is the signed delegation (`attested`). No match is a deny; a `forbid` beats every `permit`; an evaluation error is a deny recorded in the receipt. The decision object in the receipt:

```json
{ "decision": "allow", "reasons": ["policy1"], "errors": [], "policyDigest": "ba4e4461…", "provenance": "observed" }
```

## The receipt bundle

`receipts/<receiptId>.json`, self-contained apart from public keys:

```json
{
  "envelope": { "payloadType": "application/vnd.in-toto+json", "payload": "<base64 statement>", "signatures": [{ "keyid": "9d44…", "sig": "…" }] },
  "treeHead": { "payloadType": "application/vnd.agent-custody.treehead+json", "payload": "<base64 { treeSize, rootHash, timestamp, log? }>", "signatures": [{ "keyid": "6ddd…", "sig": "…" }] },
  "inclusion": { "leafIndex": 0, "treeSize": 1, "hashes": [] }
}
```

The statement inside `envelope.payload` is an in-toto Statement whose predicate is the receipt:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "tool-call:stripe.refund:36c85dc9-…", "digest": { "sha256": "<args digest>" } }],
  "predicateType": "https://agent-custody.dev/receipt/v0.2",
  "predicate": {
    "receiptId": "36c85dc9-43c1-46a9-9be7-9210210a7aa1",
    "timestamp": "2026-09-21T09:27:31.401Z",
    "issuer": { "kind": "gateway", "keyid": "9d44…", "version": "0.1.0" },
    "principal": { "id": "user_456", "keyid": "19b2…", "provenance": "attested" },
    "agent": { "id": "support-agent", "provenance": "attested" },
    "delegation": { "envelope": { "…": "the grant" }, "provenance": "attested" },
    "session": { "id": null, "toolUseId": null, "provenance": "claimed" },
    "model": { "id": "vector-model", "provenance": "claimed" },
    "tool": { "name": "stripe.refund", "provenance": "observed", "upstream": "payments" },
    "request": { "args": { "customer_id": "cust_123", "amount": 50000 }, "argsDigest": "33fc…", "provenance": "claimed" },
    "facts": { "customer": { "tool": "customer.lookup", "args": { "customer_id": "cust_123" }, "value": { "id": "cust_123", "verified": true }, "resultDigest": "8a47…", "provenance": "observed" } },
    "consumed": { "factIds": [], "provenance": "observed" },
    "policy": { "decision": "allow", "reasons": ["policy1"], "errors": [], "policyDigest": "ba4e…", "provenance": "observed" },
    "authorization": { "envelope": { "…": "the authorization statement, pre-committed tools only" }, "treeHead": { "…": "" }, "inclusion": { "leafIndex": 0, "treeSize": 1, "hashes": [] } },
    "execution": { "status": "executed", "result": { "content": [{ "type": "text", "text": "…" }] }, "resultDigest": "d650…", "provenance": "observed", "upstream": { "envelope": { "…": "the upstream's signature, when it signs" } } }
  }
}
```

`execution` is one of `{ status: "executed" | "failed", result, resultDigest, upstream? }`, `{ status: "denied", reason }`, `{ status: "withheld", reason }`, or `{ status: "error", error }`. `tool.upstream` appears when several upstreams are configured. Every check a verifier runs on this is listed under [verify](./verify).

## Exporters

Both run after the receipt is written and never block or fail it; a collector that is down costs a line on stderr.

| config | what is sent |
| --- | --- |
| `otel: { url, headersEnv?, serviceName? }` | `POST <url>/v1/traces`, OTLP/HTTP JSON, one span per receipt: trace id = receipt id without hyphens, span name = tool, attributes `agent_custody.receipt_id`, `.issuer.kind`, `.tool`, `.agent`, `.principal`, `.execution.status`, `.policy.decision`, `.policy.digest`, `.log.leaf_index`, `.log.tree_size`, `.consumed.count`, `.model`, `.session`; status error only for `failed` and `error` |
| `splunk: { url, tokenEnv, index?, source?, sourcetype?, host? }` | `POST <url>/services/collector/event` with `Authorization: Splunk <token>`, one event `{ time, source: "agent-custody", sourcetype: "agent-custody:receipt", index?, host?, event: { receipt_id, issuer_kind, issuer_keyid, tool, upstream, agent, agent_provenance, principal, status, reason, policy_decision, policy_digest, policy_reasons, args_digest, log_leaf_index, log_tree_size, authorization_leaf_index, consumed_count, model, session } }` |

Programmatically: `otlpExporter(cfg)`, `splunkExporter(cfg)`, `openExporter(config)` (every configured exporter as one), each a `ReceiptExporter` with `exported(predicate, bundle): Promise<void>`; `createGateway(cfg, { exporter })` and `createGatewayHost(cfg, { exporter, log })` accept one for tests.
