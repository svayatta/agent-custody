# Configuring the gateway

Who may use which tools, and where those tools live, is set in three files and a few environment variables. This page is the map: what each one decides, how they fit together, a worked example with two agents on one shared gateway, how it all works in the Docker image, and how to check a config before you start. The full list of config keys is in [the gateway reference](/reference/gateway); the Cedar language is in [policies.md](policies.md).

## What you configure, and where

| what | file | written by | decides |
| --- | --- | --- | --- |
| **The grant** | `<agent>.grant.json`, signed | the principal (the person or organisation delegating), with `agent-custody grant` | which agent may use which tool names, until when |
| **The policy** | `policy.cedar` | the operator or security owner | whether this particular call, with these arguments and these facts, is allowed |
| **The gateway config** | `gateway.json` | the operator | where the tools live (the upstreams), what the gateway looks up for itself (facts), which tools are consequential (`precommit`), where receipts and the log go |
| **Credentials** | environment variables | the operator | the tokens the gateway uses to reach the tools; never in a file, never in an agent |

The agent configures none of them. It connects to the gateway as an MCP server, presents its grant, and sees only the tools the grant names.

## How a call is decided

For each call, in this order, and a refusal at any step is a signed receipt:

1. **The grant** is valid, signed by a trusted principal, inside its window, and not revoked.
2. **The tool** is one of the grant's scopes.
3. **Facts** the policy needs are fetched by the gateway from an upstream (`facts` in the config).
4. **The Cedar policy** permits the call. No matching `permit` means deny.
5. **For `precommit` tools**, the authorization is committed to the log before anything is forwarded.
6. **The call** is forwarded to the upstream that owns the tool.

The one thing that ties all of it together is the **tool name**. The grant's scopes, the policy's `action == Action::"..."`, `facts`, and `precommit` all name the tools the upstreams offer, so a name that is spelled differently in one place is a rule that never applies.

## Tool names

- A **REST** upstream's tool names are the ones you give them in `tools[].name`.
- An **A2A** agent offers `<prefix>.send` and `<prefix>.card`, with the prefix you choose.
- An **MCP** server (stdio or HTTP) offers whatever names the server defines. Run `agent-custody check --config gateway.json --connect` to print them.
- **One owner per tool.** If two upstreams offer the same name the gateway refuses to start. Give REST and A2A tools a prefix (`billing.refund`, `docs.send`) and the collision cannot happen.

## A worked example: two agents, one shared gateway

A support agent may look customers up and refund them up to 1,000.00, and only for customers the gateway itself found to be verified. A reporting agent may only read. Both reach the same tools through one gateway.

**1. The principal issues one grant per agent.** On the principal's machine, with a key that never goes near the gateway:

```bash
agent-custody grant --key principal.key --principal acme-support --agent support-agent \
  --scopes customer.lookup,billing.refund,kb.search,docs.send --ttl-hours 8 --out support-agent.grant.json
agent-custody grant --key principal.key --principal acme-support --agent report-agent \
  --scopes customer.lookup,kb.search --ttl-hours 8 --out report-agent.grant.json
```

The grants limit *which tools*. The report agent's grant has no `billing.refund`, so it never sees that tool and the policy is not even asked.

**2. The operator writes one policy for both.** It limits *how* a tool may be used:

```cedar
// anything in a grant's scopes may read
permit(principal, action == Action::"customer.lookup", resource);
permit(principal, action == Action::"kb.search", resource);

// refunds: only the support agent, at most 1,000.00 (integer minor units), and only for a customer the gateway
// itself found to be verified. context.facts comes from the gateway's own lookup, never from the agent.
permit(principal == Agent::"support-agent", action == Action::"billing.refund", resource)
when {
  context.args.amount <= 100000 &&
  context.facts has customer &&
  context.facts.customer.verified == true
};

// delegating a task to the docs agent: the support agent only
permit(principal == Agent::"support-agent", action == Action::"docs.send", resource);
```

**3. The operator writes the gateway config.** One file, four kinds of upstream, one remote log:

```json
{
  "identity": { "keyFile": "/data/keys/gateway.key" },
  "upstreams": [
    {
      "name": "billing",
      "rest": {
        "baseUrl": "https://billing.internal.example.com",
        "headerEnv": { "authorization": "BILLING_API_AUTHORIZATION" },
        "tools": [
          { "name": "customer.lookup", "method": "GET", "path": "/v1/customers/{customer_id}",
            "inputSchema": { "type": "object", "properties": { "customer_id": { "type": "string" } }, "required": ["customer_id"] } },
          { "name": "billing.refund", "method": "POST", "path": "/v1/refunds", "idempotencyHeader": "Idempotency-Key",
            "description": "Refund a customer. amount is in minor units.",
            "inputSchema": { "type": "object", "properties": { "customer_id": { "type": "string" }, "amount": { "type": "integer" } }, "required": ["customer_id", "amount"] } }
        ]
      }
    },
    { "name": "github", "url": "https://mcp.internal.example.com/github", "tokenEnv": "GITHUB_MCP_TOKEN" },
    { "name": "kb", "command": "kb-mcp-server", "args": ["--root", "/srv/kb"], "env": { "KB_MODE": "read-only" } },
    { "name": "docs", "a2a": { "url": "https://docs-agent.internal.example.com", "headerEnv": { "authorization": "DOCS_AGENT_BEARER" }, "prefix": "docs" } }
  ],
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "facts": [
    { "name": "customer", "tool": "customer.lookup", "args": { "customer_id": "$args.customer_id" }, "forTools": ["billing.refund"] }
  ],
  "precommit": ["billing.refund", "docs.send"],
  "revokedGrants": "/data/revoked.json",
  "receiptsDir": "/data/receipts",
  "log": { "url": "https://log.agent-custody.dev/t/acme/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true, "keys": ["keys/log.pub"] }
}
```

What each part does:

| key | what it says here |
| --- | --- |
| `identity.keyFile` | the gateway's signing key, in `/data` because the gateway writes and keeps it. Verifiers check receipts against its public half. |
| `upstreams` | four tool sources behind one gateway: a REST API described as tools, an MCP server over HTTP, an MCP server the gateway starts, and another agent over A2A. |
| `…headerEnv`, `tokenEnv` | the **name** of an environment variable holding the credential. The gateway reads it at startup and refuses to start without it. The secret is never in the file. |
| `kb.env` | what the started MCP server gets. A stdio upstream gets a minimal environment and nothing of the gateway's own, so it cannot read the other upstreams' tokens. |
| `trustedPrincipalKeys` | the public keys whose grants this gateway accepts. Only public keys go here. |
| `facts` | before a refund, the gateway calls `customer.lookup` itself with the customer id from the call, and the policy reads the answer as `context.facts.customer`. |
| `precommit` | the consequential tools: the gateway commits the authorization to the log before it forwards, and withholds the call if the log will not take it. |
| `revokedGrants` | the file `agent-custody revoke` appends to; the gateway re-reads it on every call. |
| `receiptsDir`, `log` | full receipts stay on the gateway's disk. The hosted log receives only their hashes (`hashOnly`), and its public key is pinned (`keys`), which `precommit` with a remote log requires. |

Paths in `gateway.json` are resolved relative to the file, so `keys/principal.pub` sits beside it, and absolute paths are left as they are.

**4. Each agent presents its own grant** when it connects: the grant file, base64url-encoded, as `Authorization: Bearer <value>` or `X-Agent-Custody-Grant`. [The gateway guide](usage.md#one-gateway-for-many-agents-over-http) and [wiring it into an agent host](usage.md#wiring-it-into-an-agent-host) show how for each host. Adding a third agent is issuing it a grant. The gateway config does not change.

## In the Docker image

The same `gateway.json` works in the [gateway image](https://github.com/svayatta/agent-custody/blob/main/deploy/gateway/README.md), with these rules:

- **Mount the config read-only at `/config`** (`gateway.json`, `policy.cedar`, and the principals' and log's **public** keys) and a **volume at `/data`**. Relative paths in the file resolve against `/config`.
- **Anything the gateway writes needs an absolute path under `/data`**: the key, `receiptsDir`, `logFile`, `revokedGrants`. `/config` is read-only, so `"receiptsDir": "receipts"` fails.
- **Credentials come from the container's environment** (`--env-file`, a compose `.env`, a Kubernetes Secret), under the variable names the config gives.
- **The gateway key is created on the first start** at the path `identity.keyFile` names, if the file is absent. Keep the volume.
- **REST, A2A, and MCP-over-HTTP upstreams work as they are.** A **stdio** MCP server (`command`) has to be inside the image. Build on it:

  ```dockerfile
  FROM ghcr.io/svayatta/agent-custody-gateway:<version>
  USER root
  RUN npm install -g kb-mcp-server
  USER custody
  ```

- `docker run ... <image> init` writes a starter config into an empty `/config`. [The gateway README](https://github.com/svayatta/agent-custody/blob/main/deploy/gateway/README.md) has the whole run, and the limits of a shared gateway.

## Check it before you start it

`agent-custody check --config gateway.json` reads the config the way the gateway would and reports what would go wrong at startup:

```bash
agent-custody check --config gateway.json --connect
docker run --rm -v "$PWD/config:/config:ro" -v gateway-data:/data --env-file .env <image> check --config /config/gateway.json --connect
```

| it checks | an error or a warning |
| --- | --- |
| the config parses, with each problem and its path | **error** |
| a key that is not in the schema (a typo such as `precomit` is otherwise silently ignored) | warning, with the key it nearly is |
| the gateway key loads, and is not readable by other users | error, and a warning |
| every trusted principal key loads | error |
| the Cedar policy parses, and has at least one `permit` | error, and a warning |
| every credential variable the config names is set | **error**: the gateway does not start without it |
| a stdio `command` exists, and a script argument exists | error, and a warning |
| the receipts, log, and revocation paths can be written, and the revocation file is a JSON array | error |
| the grant the config names verifies, and is inside its window | error, and a warning near expiry |
| a remote log with an empty `precommit` | warning: a log outage after a call leaves its side effect without evidence |

With **`--connect`** it also starts the upstreams, which is where an unreachable server or **two upstreams offering the same tool** shows up, prints the tools they offer, and compares every tool name in `precommit`, `facts`, `approvals`, `operations`, and the grant's scopes with that list. A name that no upstream offers is reported. `--connect` starts your stdio upstreams and may create the receipts directory. It exits 1 on any error, so it can gate a deploy.

## When the gateway does not start

| the message | the cause | the fix |
| --- | --- | --- |
| `environment variable X is not set` | a `tokenEnv`, `headerEnv`, `log.tokenEnv`, or `captureKeyEnv` names a variable the process does not have | set it where the gateway runs |
| `tool "t" is offered by both upstream "a" and upstream "b"` | two upstreams offer one name | rename one (give REST and A2A tools a prefix) |
| `exactly one of upstream or upstreams is required` | both, or neither | use `upstream` for one source and `upstreams` for several |
| `exactly one of logFile or log is required` | both, or neither | a local file, or a remote log |
| `precommit with a remote log needs log.keys` | a remote log gating consequential calls without a pinned key | add the log's public key file to `log.keys` |
| `fact "f" uses tool t, which precommit names as consequential` | a fact lookup must be a read | use a read tool for the fact |
| `ENOENT … gateway.key` | the key file does not exist | `agent-custody keygen`, or let the container create it |
| `EROFS` or a permission error on `receipts` | a writable path points into the read-only `/config` | use an absolute path under `/data` |
| `403 delegation grant rejected: …` (an agent's connection) | the grant is expired, revoked, not signed by a trusted principal, or missing | issue a new grant, and check `trustedPrincipalKeys` |

Run `agent-custody check --connect` first: it reports most of these together, instead of one at a time.
