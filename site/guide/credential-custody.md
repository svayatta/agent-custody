# Credential custody and egress lockdown

The gateway can only receipt calls that pass through it. If an agent holds a tool credential, or can reach the internet on its own, it can call the tool directly, and the gateway never sees that call. This page covers the two deployment steps that close that route:

1. **Credential custody.** Tool credentials live only in the gateway.
2. **Egress lockdown.** The agent's network reaches only the gateway and the [egress witness](/receipts/egress). The witness receipts and decides by policy every connection that is not a tool call.

Do both. Lockdown without custody leaves a credential the agent can use through any permitted destination. Custody without lockdown leaves the agent free to call public APIs, and to send data out, with nothing recorded.

## Credential custody: tool credentials live only in the gateway

- **Give the credential to the gateway, never the agent.** Each upstream's key is in the gateway's environment (`headerEnv` for the REST connector, `env` for a stdio server). See [configuring the gateway](/receipts/configuration). The agent holds its grant, which works only through the gateway and only for the tools in its scope.
- **Describe the API as gateway tools.** If agent code calls an HTTP API directly, describe its endpoints as REST tools in the gateway config, so the agent calls them through the gateway. [Deployment](/guide/deployment#where-interception-stops) has the details.
- **Keep the agent's environment clean.** Check the agent's container image, its environment, its mounted files, and its host config. Look for API keys, cloud credentials (an instance role or a mounted service account token counts), and a second MCP server entry that points at the tool directly. Set `automountServiceAccountToken: false` on the agent's pod unless the agent needs the Kubernetes API.
- **Check the gateway for leaks.** A stdio upstream starts with a minimal environment, never the gateway's, so one tool cannot read another tool's token. The console runs as a service of its own and is not given the gateway's credentials. `deploy/gateway/docker-compose.yaml` shows both.

What custody cannot do: it cannot take back a credential that the agent already copied, or one that a tool's output handed to the agent. Rotate a credential that was ever in an agent's environment.

## Egress lockdown: the agent reaches only the gateway and the witness

`deploy/gateway/lockdown` has the manifests.

**Kubernetes** (`lockdown/k8s`):

- A NetworkPolicy gives every agent pod labelled `agent-custody.dev/egress: locked` default-deny egress. It allows the gateway on 8790, the witness on 8791, and the cluster DNS.
- The witness runs as a Deployment beside the gateway, from the same image. Its own NetworkPolicy accepts connections only from locked agents. It refuses the cloud metadata address and private ranges on their behalf.
- A NetworkPolicy has no effect unless the cluster's network plugin enforces it. Calico, Cilium, and most managed CNIs do; flannel alone does not.

```bash
kubectl label namespace agents agent-custody.dev/agents=true
kubectl -n agent-custody-gateway create configmap egress-config --from-file=deploy/gateway/lockdown/config
kubectl -n agent-custody-gateway create secret generic egress-env --from-literal=EGRESS_SECRET_RESEARCH_AGENT="$(openssl rand -hex 32)"
kubectl apply -k deploy/gateway/lockdown/k8s
```

**Docker compose** (`lockdown/docker-compose.yaml`, an override for the gateway's compose file):

- The agent sits on an internal network (`internal: true`), which has no route out.
- The gateway and the witness sit on that network and on the default one. They are the only way out.

```bash
cd deploy/gateway
docker compose -f docker-compose.yaml -f lockdown/docker-compose.yaml run --rm egress keygen --dir /data/keys --name egress
docker compose -f docker-compose.yaml -f lockdown/docker-compose.yaml --profile demo-agent up -d
```

On Docker, the witness sits on the default network, so it can reach the host, the other services, the private ranges, and the metadata address, which the agent cannot. Compose has no equivalent of the Kubernetes exception list. The witness itself refuses an internal address for a host name before it connects. It dials an IP literal only when the policy names that address, so do not permit internal addresses. On a cloud VM, also block the metadata address for the witness's container in the host firewall.

**A VM or bare metal** (`lockdown/vm`): each agent runs as its own Unix user, and the gateway and the witness run beside it as systemd services.

- `agent-lockdown.nft` is an nftables table that matches the agent's user (`meta skuid`). Whatever that user runs may reach only the gateway on 8790, the witness on 8791, and the DNS resolver. Everything else, loopback included, is logged and refused. Packets from every other user, the gateway and the witness among them, are not touched.
- `agent-custody-lockdown.service` loads that table at boot and replaces only that table. Do not load it through `nftables.service`: on Debian and Ubuntu that service runs `/etc/nftables.conf`, which starts with `flush ruleset` and deletes every other table on the host, docker's and ufw's included.
- `agent-lockdown.conf` is a systemd drop-in for the agent's own unit. It requires `agent-custody-lockdown.service`, so an agent whose table fails to load stays down. It runs the agent as that user with `NoNewPrivileges`, loads the proxy settings from a root-only file, and sets `IPAddressDeny=any` plus `IPAddressAllow=` for the gateway, the witness, and the resolver.
- `agent-custody-egress.service` runs the witness under a user of its own, with the same `egress.json` as the other recipes. The gateway uses the existing `deploy/gateway/agent-custody-gateway.service`.
- `check-lockdown.sh` runs the three tests below as the agent user. With `--unit`, it runs them inside the agent unit's IP filter. Before the direct probe, it makes the same connection as root, so a host with no route out cannot pass for a locked-down one. A fourth check confirms that the table is loaded.

Use the nftables rule and the drop-in together. The nftables rule covers everything the user runs, a cron job or a shell included, and it matches ports. The drop-in holds even if the host firewall is flushed. But `IPAddressAllow=` takes addresses, not ports, so allowing `127.0.0.1` allows every service on loopback. Neither can hold an agent that changes user, so give the agent user no sudo and keep it out of the docker group. CI installs this recipe on a fresh Ubuntu runner. It runs the checks with no lockdown, which must fail, then with the whole recipe, then with the drop-in alone. It also checks that a table that fails to load keeps the agent down.

```bash
sudo useradd --system --home /var/lib/agent --create-home --shell /usr/sbin/nologin agent
sudo install -D -m 0644 deploy/gateway/lockdown/vm/agent-lockdown.nft /etc/agent-custody/agent-lockdown.nft  # edit the addresses
sudo install -m 0644 deploy/gateway/lockdown/vm/agent-custody-lockdown.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now agent-custody-lockdown
sudo install -D -m 0644 deploy/gateway/lockdown/vm/agent-lockdown.conf /etc/systemd/system/my-agent.service.d/lockdown.conf
sudo systemctl daemon-reload && sudo systemctl restart my-agent
sudo EGRESS_SECRET=... deploy/gateway/lockdown/vm/check-lockdown.sh --unit my-agent.service
```

The header of each file lists the remaining steps, such as the witness's user and key.

**Other setups.** The witness itself runs anywhere: `agent-custody egress` is a Node 22 process, from npm or the gateway image. The lockdown is the part that depends on the platform. Anywhere else, build the same default-deny egress with the platform's own controls. The rule is always the same: from the agent, allow only the gateway, the witness, and DNS, and drop everything else.

- **Cloud tasks and instances** (ECS, Cloud Run, EC2, GCE, Azure). Give the agent a security group or firewall rule with no general egress, only the gateway and the witness. On a serverless function in a VPC, the agent must have no NAT route out. On an instance you manage yourself, the VM recipe above applies inside it too.
- **A developer laptop.** An agent that runs as you, with your network, cannot be locked down, and the witness is only advice there. Run the agent in a container with the compose override instead.

These two are mechanisms, not recipes. We have not shipped or tested a file for them. Whatever you build, run the three tests below before you rely on it.

**The agent's settings:**

- `HTTPS_PROXY` and `HTTP_PROXY`: `http://<agent id>:<secret>@<witness>:8791`.
- `NO_PROXY`: the gateway's host.
- Give each agent its own secret. Each agent's receipts then name that agent, and you can revoke one agent without the others.

**Test it.** Do not assume it works. From the agent's container or user:

- a direct connection that ignores the proxy must fail to connect;
- a connection through the witness to a destination the policy does not permit must get `403` and leave a receipt;
- a tool call through the gateway must still work.

## What the witness sees and does not see

| | seen | not seen |
| --- | --- | --- |
| a CONNECT tunnel (HTTPS) | the agent (by its proxy credential), the host and port, the address connected to, the times, the bytes each way | anything inside the tunnel: no TLS interception |
| a plain HTTP request | the same, plus the method and the status | the path, the headers, and the bodies |
| traffic when lockdown is off | nothing, if the agent ignores `HTTPS_PROXY` | everything |
| non-HTTP protocols | under lockdown, they cannot leave | without lockdown, everything |
| DNS | not relayed by the witness | queries to a resolver that forwards to the internet |

Each egress receipt is an observed bypass: it shows that the agent connected somewhere around the gateway. It is not a record of what the agent did there. For calls that need that record, put the tool behind the gateway.

[The egress witness](/receipts/egress) has the config, the policy model, and the receipt. [The threat model](/receipts/threat-model) has the row it changes.
