# Running the gateway as a service

One shared agent-custody gateway for every agent on a host or cluster. All their tool calls go through it, each agent connection presents its own signed grant, and the tool credentials live in the gateway and never in an agent. This is the long-running way to run the gateway (`agent-custody gateway --http`); for a single agent session the host can spawn the gateway on stdio and there is nothing to operate (see [the gateway guide](../../packages/receipts/docs/usage.md)).

```
agent A ─┐                                          ┌─ Stripe (REST)
agent B ─┼─ MCP over HTTP, own grant ─▶ gateway ────┼─ GitHub (MCP)
agent C ─┘      (this image)             │          └─ another agent (A2A)
                                         └─ signed receipts ─▶ /data, and the log
```

## The image

`ghcr.io/svayatta/agent-custody-gateway`, for linux/amd64 and linux/arm64, built by the `gateway-image` workflow:

| tag | built when | from |
| --- | --- | --- |
| `edge`, `sha-<short>` | every merge to main that touches the receipts package or `deploy/gateway` | the source of that commit |
| `<version>`, `<major>.<minor>`, `latest` | every release | the published npm package of that version |

Pin a version in production. `latest` moves on every release, and `edge` on every merge. Every build starts the image and runs [smoke.sh](smoke.sh) before it is pushed: healthy, a connection with no grant refused, a demo grant accepted, and `docker stop` closing the gateway cleanly. The first push creates the package as private; make it public once in the package's settings so `docker pull` needs no login.

## Start one

```bash
mkdir config
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/config:/config" ghcr.io/svayatta/agent-custody-gateway init
docker compose up -d        # or: docker run -d -v "$PWD/config:/config:ro" -v gateway-data:/data -p 127.0.0.1:8790:8790 <image>
curl http://127.0.0.1:8790/health
```

`init` writes a starter `gateway.json`, an example `policy.cedar`, the public half of a demo principal key, and a demo 24-hour grant under `config/demo/`. Edit the upstream and the policy, then restart. **Delete `config/demo/` before production:** the principal's private key must never sit on the gateway host. Issue real grants on the principal's own machine with `agent-custody grant --key principal.key ...`, and put only `principal.pub` in the config.

An agent connects to `http://<gateway>:8790/mcp` and presents its grant as the base64url of the grant file, in `Authorization: Bearer <value>` or `X-Agent-Custody-Grant`. `base64 < grant.json | tr -d '\n=' | tr '+/' '-_'` makes the value. From JavaScript, `grantHeader(envelope)` does. One gateway serves every grant that is signed by a key in `trustedPrincipalKeys`.

## What goes where

| path in the container | holds | mounted |
| --- | --- | --- |
| `/config` | `gateway.json`, `policy.cedar`, the principals' public keys | read-only, from your repository or a ConfigMap |
| `/data` | the gateway's key (created on first start), receipts, the local log, `revoked.json`, the operations store | a named volume or a persistent volume claim |
| environment | the credentials the upstreams read (`headerEnv`, `tokenEnv` in `gateway.json`), the log's token | `.env`, a Secret |

Paths in `gateway.json` are relative to `/config`; give absolute `/data/...` paths for anything the gateway writes. The gateway key is created once and printed (public half) in the container log; verifiers check receipts against it, so back the `/data/keys` directory up and keep it. Do not put tool credentials in an agent's environment: an agent that holds a Stripe key can call Stripe directly and nothing here sees it.

For evidence a customer or auditor will accept, point `log` in `gateway.json` at a log run by someone else (`"log": { "url": ..., "tokenEnv": ..., "hashOnly": true, "keys": [...] }`; [usage.md](../../packages/receipts/docs/usage.md), "Logging to a remote log"). `init` configures a local file log and `"precommit": ["*"]`, so every agent call is authorized in the log before it is forwarded; name only the consequential tools once you know them.

## Running it

| task | how |
| --- | --- |
| revoke a grant | `docker compose exec gateway agent-custody revoke --config /config/gateway.json --grant /path/in/container/grant.json`. The next call of every session under that grant, and every grant delegated from it, is refused; no restart. |
| change the policy | edit `config/policy.cedar` and `docker compose restart gateway`. The policy is read at start; every open session ends. |
| upgrade | set `AGENT_CUSTODY_GATEWAY_VERSION` and `docker compose pull && docker compose up -d`. |
| stop | `docker compose stop`. The gateway closes on SIGTERM; `stop_grace_period` is 30 s. |
| other commands | anything after the image name runs through the `agent-custody` CLI: `docker compose run --rm gateway verify ...`. |
| plain VM | [agent-custody-gateway.service](agent-custody-gateway.service) runs the same command under systemd. |
| Kubernetes | `kubectl apply -k deploy/gateway/k8s`; the header of [k8s/kustomization.yaml](k8s/kustomization.yaml) lists the steps. |
| TLS | `docker compose --profile tls up -d` puts Caddy in front on `GATEWAY_HOST`. |

## What a shared gateway means, and its limits

- **A grant is a bearer credential.** The gateway does not check that the connecting party holds the agent's key, so whoever has a grant can connect as that agent until it expires or is revoked. Use short grant lifetimes, keep the port on a private network or behind mutual TLS, and revoke at once on a leak.
- **The transport is plain HTTP.** The compose file publishes on 127.0.0.1 by default. Put TLS in front before it crosses a network.
- **One process holds every agent's tool credentials.** That is the point, and also the blast radius. One policy and one gateway key apply to all agents on it; run one gateway per team where that is not acceptable.
- **One replica.** Sessions live in memory and the local log has one writer, so run a single instance (the Kubernetes manifest uses `Recreate`). A second replica needs sticky routing and shared state that is not built.
- **Availability.** A stopped gateway is every agent stopped, and a log that is down withholds the `precommit` calls of every agent.
- **Policy edits need a restart.** Grants and revocations are picked up on the next call.
- **Stdio upstreams need their tool inside the image.** REST and A2A upstreams work out of the box. For an MCP server that is a command, build on this image (`FROM ghcr.io/svayatta/agent-custody-gateway`, then install the tool) or reach it over HTTP.

## Building it yourself

```bash
cd packages/receipts && bun run build && bun pm pack --destination ../../deploy/gateway/pkg   # from the workspace
cd ../../deploy/gateway && docker build -t agent-custody-gateway:local .
# or, from a published version: docker build --build-arg AGENT_CUSTODY_VERSION=0.8.0 -t agent-custody-gateway:local .
./smoke.sh agent-custody-gateway:local
```
