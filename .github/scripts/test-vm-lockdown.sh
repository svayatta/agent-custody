#!/bin/sh
# End-to-end test of the VM egress lockdown (deploy/gateway/lockdown/vm) on a throwaway Linux host with systemd: installs
# the gateway, the witness, a stand-in upstream, and a stand-in agent as the file headers describe, then runs
# check-lockdown.sh with the nftables rule alone, with the systemd drop-in alone, and with neither (which must fail).
# Usage: sudo test-vm-lockdown.sh <@agent-custody/receipts tarball>     needs node 22, nft, curl, python3, openssl
set -eu
pkg="${1:?usage: test-vm-lockdown.sh <package tarball>}"
here=$(cd "$(dirname "$0")/../.." && pwd)
gw="$here/deploy/gateway"
vm="$gw/lockdown/vm"
fail() { echo "test-vm-lockdown: FAIL: $*" >&2; journalctl -u agent-custody-gateway -u agent-custody-egress --no-pager -n 40 >&2 || true; exit 1; }

# into /usr/local, where the units find it on systemd's PATH
npm install -g --silent --prefix /usr/local "$pkg"
[ -x /usr/local/bin/agent-custody ] || fail "npm install -g put no agent-custody in /usr/local/bin"

# the gateway, with one REST tool whose upstream is a stand-in on loopback
id custody > /dev/null 2>&1 || useradd --system --home /var/lib/agent-custody --create-home custody
install -d -o custody -g custody /var/lib/agent-custody/keys
runuser -u custody -- agent-custody keygen --dir /var/lib/agent-custody/keys --name gateway > /dev/null
install -d /etc/agent-custody/keys
work=$(mktemp -d)
agent-custody keygen --dir "$work" --name principal > /dev/null
cp "$work/principal.pub" /etc/agent-custody/keys/principal.pub
echo 'permit(principal, action == Action::"example.lookup", resource);' > /etc/agent-custody/policy.cedar
cat > /etc/agent-custody/gateway.json << 'CONFIG'
{
  "identity": { "keyFile": "/var/lib/agent-custody/keys/gateway.key" },
  "upstream": { "rest": { "baseUrl": "http://127.0.0.1:9000", "tools": [{ "name": "example.lookup", "method": "GET", "path": "/v1/items/{id}", "inputSchema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] } }] } },
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "/var/lib/agent-custody/receipts",
  "logFile": "/var/lib/agent-custody/log.jsonl"
}
CONFIG
install -m 0600 /dev/null /etc/agent-custody/gateway.env
cp "$gw/agent-custody-gateway.service" /etc/systemd/system/
mkdir -p /srv/upstream/v1/items
echo '{"id":"1"}' > /srv/upstream/v1/items/1
systemd-run --quiet --unit upstream-demo -p User=nobody python3 -m http.server 9000 --bind 127.0.0.1 --directory /srv/upstream

# the witness, with the shipped starter config
id custody-egress > /dev/null 2>&1 || useradd --system --home /var/lib/agent-custody-egress --create-home --shell /usr/sbin/nologin custody-egress
install -d /etc/agent-custody/egress
cp "$gw/lockdown/config/egress.json" "$gw/lockdown/config/egress-policy.cedar" /etc/agent-custody/egress/
secret=$(openssl rand -hex 32)
install -m 0600 /dev/null /etc/agent-custody/egress.env
echo "EGRESS_SECRET_RESEARCH_AGENT=$secret" > /etc/agent-custody/egress.env
install -d -o custody-egress -g custody-egress /var/lib/agent-custody-egress/keys
runuser -u custody-egress -- agent-custody keygen --dir /var/lib/agent-custody-egress/keys --name egress > /dev/null
cp "$vm/agent-custody-egress.service" /etc/systemd/system/
systemctl daemon-reload
systemctl start agent-custody-gateway agent-custody-egress

# the agent: its user, the nftables rule with the resolver this host uses, and a service with the drop-in
id agent > /dev/null 2>&1 || useradd --system --home /var/lib/agent --create-home --shell /usr/sbin/nologin agent
resolver=$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)
sed "s/^define RESOLVERS = { 127.0.0.53 }/define RESOLVERS = { $resolver }/" "$vm/agent-lockdown.nft" > /etc/agent-custody/agent-lockdown.nft
nft -c -f /etc/agent-custody/agent-lockdown.nft
printf '[Service]\nExecStart=/bin/sleep infinity\n' > /etc/systemd/system/demo-agent.service
install -d /etc/systemd/system/demo-agent.service.d
sed "s/^IPAddressAllow=127.0.0.53/IPAddressAllow=$resolver/" "$vm/agent-lockdown.conf" > /etc/systemd/system/demo-agent.service.d/lockdown.conf
install -m 0600 /dev/null /etc/agent-custody/agent.env
systemctl daemon-reload
systemctl start demo-agent

i=0
until curl -fsS http://127.0.0.1:8790/health > /dev/null 2>&1 && curl -fsS http://127.0.0.1:8791/.well-known/agent-custody-egress > /dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "the gateway or the witness did not come up"
  sleep 1
done

export EGRESS_SECRET="$secret"
echo "== no lockdown: the checks must fail"
if "$vm/check-lockdown.sh"; then fail "check-lockdown.sh passed with no lockdown in place"; fi
echo "== the nftables rule"
nft -f /etc/agent-custody/agent-lockdown.nft
"$vm/check-lockdown.sh"
echo "== the systemd drop-in alone"
nft delete table inet agent_custody_lockdown
"$vm/check-lockdown.sh" --unit demo-agent.service
echo "test-vm-lockdown: ok"
