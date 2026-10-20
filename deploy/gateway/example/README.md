# An example gateway config you can use

A complete, working layout for one shared gateway in front of one REST API: a read tool, a refund tool the policy limits, a fact lookup the gateway makes for itself, a refund that is committed to the log before it is forwarded, and a local log. Copy it, change the API address and the tool list to yours, and run it.

```
config/
  gateway.json      where the API lives, the tools, the fact lookup, precommit, and where receipts go
  policy.cedar      what an agent may do with those tools
  keys/             the principal's PUBLIC key goes here (principal.pub); nothing private ever does
```

## Use it

**1. Make the principal's key pair, on the machine of whoever issues grants, not the gateway host.** The private half signs grants; keep it there. [The principal's key](../../../packages/receipts/docs/configuration.md#the-principals-key) says how.

```bash
agent-custody keygen --dir ./principal --name principal      # principal.key (private, mode 0600) and principal.pub
cp principal/principal.pub config/keys/principal.pub          # only the public half goes to the gateway
```

**2. Point the config at your API.** In `config/gateway.json` change `baseUrl` and the `tools` to your API's. Names such as `orders.get` are yours to choose; the grant, the policy, `facts`, and `precommit` must all use the same names. The API's credential is read from the environment variable `APP_API_AUTHORIZATION` (the whole header value, such as `Bearer sk_live_...`).

**3. Check it, then run it.** Paths under `/data` are where the gateway writes; the container mounts a volume there.

```bash
echo 'AGENT_CUSTODY_GATEWAY_VERSION=<version>' > .env
echo 'APP_API_AUTHORIZATION=Bearer <your token>' >> .env
docker run --rm -v "$PWD/config:/config:ro" -v gateway-data:/data --env-file .env \
  ghcr.io/svayatta/agent-custody-gateway:<version> check --config /config/gateway.json --connect
docker run -d --name gateway -p 127.0.0.1:8790:8790 -v "$PWD/config:/config:ro" -v gateway-data:/data --env-file .env \
  ghcr.io/svayatta/agent-custody-gateway:<version>
```

On a plain host without Docker, change `/data/` in `gateway.json` to a directory you own and run `agent-custody gateway --config config/gateway.json --http`.

**4. Issue a grant for each agent** (on the principal's machine) and give it to the agent, which presents it when it connects:

```bash
agent-custody grant --key principal/principal.key --principal acme-support --agent support-agent \
  --scopes orders.get,orders.refund --ttl-hours 8 --out support-agent.grant.json
agent-custody grant --key principal/principal.key --principal acme-support --agent report-agent \
  --scopes orders.get --ttl-hours 8 --out report-agent.grant.json
base64 < support-agent.grant.json | tr -d '\n=' | tr '+/' '-_'     # the value after "Authorization: Bearer "
```

The support agent's grant can read and refund, within the policy. The report agent's grant names only `orders.get`, so it never sees the refund tool. The agent name in the grant (`support-agent`) is what the policy's `principal == Agent::"support-agent"` matches.

## Log to a log you do not run

Replace `"logFile"` with a remote log, which is what lets an auditor accept a receipt without trusting you. `precommit` with a remote log requires the log's public key to be pinned:

```json
  "log": { "url": "https://log.agent-custody.dev/t/<tenant>/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true, "keys": ["keys/log.pub"] }
```

Put the log's public key at `config/keys/log.pub` and its token in the environment.
