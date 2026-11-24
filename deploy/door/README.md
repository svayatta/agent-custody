# Running the door

Four ways to put the agent-custody door in front of a site: as the reverse proxy itself, from the gateway image in `door` mode; behind a site's own nginx or Envoy, answering their authz checks; at Cloudflare's edge, as a Worker ([cloudflare-worker](cloudflare-worker/README.md)); or inside a WordPress site, as a plugin ([wordpress](wordpress/README.md)).

## As a reverse proxy, from the gateway image

The gateway image (`ghcr.io/svayatta/agent-custody-gateway`, [deploy/gateway](../gateway/README.md#the-image)) runs the door with the command `door`. The door relays each arrival it allows to the origin, refuses the rest with 403, and writes a signed receipt for each one into `/data`.

| file | what it is |
| --- | --- |
| [proxy/docker-compose.yaml](proxy/docker-compose.yaml) | the image in door mode in front of the stand-in origin ([origin.mjs](origin.mjs)); only the door is published, on `127.0.0.1:8780` |
| [proxy/config/](proxy/config) | its `door.json` and `policy.cedar`: the catalogue is public, a refund is for a verified agent, of more than 0 and at most 5000 minor units (this door relays, so the policy reads the body) |
| [k8s/](k8s/kustomization.yaml) | Deployment, Service, and volume claim, one replica, the image in door mode; the header of `kustomization.yaml` lists the steps |
| [agent-custody-door.service](agent-custody-door.service) | systemd, on a plain VM: the published package on `127.0.0.1:8780` |
| [smoke.sh](smoke.sh) | runs the compose file with a given image: a catalogue read relayed, an unknown arrival's refund refused, a granted refund relayed, refunds above the bound and below 1 refused, the grant revoked and its next refund refused, every receipt verified, and a clean stop |

```bash
cd deploy/door/proxy
mkdir -p config/keys && cp /path/to/principal.pub config/keys/       # the principal whose grants the door trusts
echo 'AGENT_CUSTODY_GATEWAY_VERSION=<version>' > .env                 # a release that has door mode
docker compose up -d
curl -i http://127.0.0.1:8780/catalogue/shoes                         # 200 from the origin, with X-Agent-Custody-Receipt
```

The principal's key pair and a grant are made on the principal's own machine (`agent-custody keygen --name principal`, then `agent-custody grant --key principal.key --principal <you> --agent <agent> --scopes refund --ttl-hours 1 --out grant.json`); only `principal.pub` goes in `config/keys`. An agent presents the grant as `Authorization: Bearer <base64url of grant.json>`. To withdraw a grant before it expires, revoke it through the running container: `docker compose exec -T door agent-custody revoke --config /config/door.json --grant /dev/stdin < grant.json` writes its digest to `/data/revoked.json` (`revokedGrants` in `door.json`), and the door classifies the next arrival carrying it as `claimed` with `grant: "revoked"`. The grant file never has to be copied into the config directory. To try a build of your own, set `AGENT_CUSTODY_GATEWAY_REPOSITORY` to its name and `AGENT_CUSTODY_GATEWAY_VERSION` to its tag, and run `deploy/door/smoke.sh <name>:<tag>`; the `gateway-image` workflow runs it on every build of the image.

In door mode the container reads `DOOR_CONFIG` (default `/config/door.json`), creates the door's key at `DOOR_KEY` (default `/data/keys/door.key`) on first start and prints its public half in the log, checks the config like the gateway (`GATEWAY_CHECK`), and listens on `DOOR_PORT` (default 8780), which the image's healthcheck probes at `/.well-known/agent-custody-door`. Keep `identity.keyFile` in `door.json` equal to `DOOR_KEY`, and give absolute `/data/...` paths for the receipts and the log. Verifiers check the door's receipts with its public key (`/data/keys/door.pub`), never the gateway's. Point `origin.url` at your own site and replace the `origin` service with it; every field is in [the reference](../../site/reference/door.md#config). Run one replica: the local log has one writer, and the rate counts and Web Bot Auth nonces live in memory.

## Behind nginx or Envoy

A site that already runs nginx or Envoy keeps its proxy and its routing: the proxy asks the agent-custody door about each request, and relays it only when the door says yes. The door classifies the arrival, runs the Cedar policy for its route, writes a signed receipt, and answers 200 or 403. It never relays anything itself.

| file | what it is |
| --- | --- |
| [nginx.conf](nginx.conf) | stock nginx: `auth_request` to the door, the receipt id and class passed to the origin and to the client |
| [envoy.yaml](envoy.yaml) | stock Envoy: the `ext_authz` HTTP filter, the same headers |
| [door.json](door.json), [policy.cedar](policy.cedar) | the door they ask: `"authz": true`, `"trustProxy": true`, two routes; the catalogue is public, a refund is for a verified agent |
| [docker-compose.yaml](docker-compose.yaml), [origin.mjs](origin.mjs) | the door, a stand-in origin, and nginx (`--profile nginx`) or Envoy (`--profile envoy`); only the proxy is published, on loopback |
| [demo.sh](demo.sh) | runs each proxy: an allowed read, a refused refund, a verified agent's refund with its body, the proxy refusing with the door down, and every receipt verified |

```bash
bun install            # at the repository root: the compose file runs the door from this checkout
deploy/door/demo.sh    # or: deploy/door/demo.sh nginx
```

**The receipts record the decision, not the result.** The door sees the request line and the headers the proxy passes, never the body or the origin's answer. Its receipts say `issuer.framework: "authz"`, an allow is `withheld` (the door relayed nothing), and the verifiers check that no such receipt claims a result. A request that can change something (any method but GET, HEAD, and OPTIONS) is committed to the log before the door answers 200. What to get right in your own proxy config, and the exact contract, are in [the door guide](../../packages/receipts/docs/door.md#behind-nginx-or-envoy-authz-mode) and [the reference](../../site/reference/door.md#authz-mode).

In a deployment, run the door from a published release that has authz mode (`npx @agent-custody/receipts door --config door.json --host 0.0.0.0`) on a network only the proxy can reach, with your own keys, routes, and policy.
