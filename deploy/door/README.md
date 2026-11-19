# The door behind nginx or Envoy

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
