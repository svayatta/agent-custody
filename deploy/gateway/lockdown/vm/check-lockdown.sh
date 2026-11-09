#!/bin/sh
# The three lockdown checks from the guide, for an agent on a VM or bare metal, and a fourth for this recipe. Run it on
# the agent's host, as root, once the gateway, the witness, and agent-lockdown.nft are in place. Each probe runs as the
# agent user. With --unit it runs in a transient unit with the IP filter of the agent's service, so it also tests
# agent-lockdown.conf.
#
#   1. a direct connection that ignores the proxy fails to connect, where the same connection made as root succeeds;
#   2. a connection through the witness to a host the policy does not permit gets 403, and the witness writes a receipt;
#   3. the gateway answers the agent;
#   4. the nftables table is loaded. The drop-in alone would pass 1 to 3, but it allows every port on 127.0.0.1.
#
# Usage: sudo EGRESS_SECRET=<the agent's proxy secret> ./check-lockdown.sh [--unit <agent>.service]
# Settings (environment): AGENT_USER (agent), AGENT_ID (research-agent), GATEWAY (127.0.0.1:8790),
# WITNESS (127.0.0.1:8791), RECEIPTS_DIR (/var/lib/agent-custody-egress/receipts), REFUSED_HOST (example.net, a
# host the policy must not permit), DIRECT_HOST (example.com, a host root can reach), NFT_TABLE (inet
# agent_custody_lockdown; set it empty only to test the drop-in alone). Needs curl, getent, nft, runuser, and
# systemd-run with --unit.
set -eu

: "${AGENT_USER:=agent}"
: "${AGENT_ID:=research-agent}"
: "${GATEWAY:=127.0.0.1:8790}"
: "${WITNESS:=127.0.0.1:8791}"
: "${RECEIPTS_DIR:=/var/lib/agent-custody-egress/receipts}"
: "${REFUSED_HOST:=example.net}"
: "${DIRECT_HOST:=example.com}"
NFT_TABLE="${NFT_TABLE-inet agent_custody_lockdown}"
: "${EGRESS_SECRET:?set EGRESS_SECRET to the agent proxy secret}"

unit=""
if [ "${1:-}" = --unit ]; then unit="${2:?--unit needs the agent service name}"; fi

fail() { echo "check-lockdown: FAIL: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root, so the probes can run as $AGENT_USER"
id "$AGENT_USER" > /dev/null 2>&1 || fail "no user $AGENT_USER"

# as_agent <command...>: runs the command as the agent user, inside the agent unit's IP filter when --unit is given
if [ -n "$unit" ]; then
  deny=$(systemctl show -P IPAddressDeny "$unit")
  allow=$(systemctl show -P IPAddressAllow "$unit")
  [ -n "$deny" ] || fail "$unit has no IPAddressDeny; is the drop-in installed and systemd reloaded?"
  as_agent() { systemd-run --quiet --wait --pipe --collect --uid="$AGENT_USER" -p NoNewPrivileges=true -p "IPAddressDeny=$deny" -p "IPAddressAllow=$allow" "$@"; }
else
  as_agent() { runuser -u "$AGENT_USER" -- "$@"; }
fi

# 1. Direct. The address is looked up here, as root, so a refused DNS query cannot pass for a refused connection.
addr=$(getent ahostsv4 "$DIRECT_HOST" | awk 'NR == 1 { print $1 }')
[ -n "$addr" ] || fail "could not resolve $DIRECT_HOST on this host"
# The control, as root: on a host with no route out, the agent's probe fails whether or not it is locked down.
out=$(env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
  curl -sS -m 10 -o /dev/null --noproxy '*' --resolve "$DIRECT_HOST:443:$addr" "https://$DIRECT_HOST/" 2>&1) || fail "cannot tell: root cannot reach $DIRECT_HOST ($addr:443) directly either ($out). Set DIRECT_HOST to a host this machine reaches"
set +e
out=$(as_agent env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
  curl -sS -m 10 -o /dev/null --noproxy '*' --resolve "$DIRECT_HOST:443:$addr" "https://$DIRECT_HOST/" 2>&1)
code=$?
set -e
# 7 is curl's "could not connect": refused by the firewall. 28, a timeout, means a drop somewhere, still no connection.
case "$code" in
  7 | 28) echo "check-lockdown: ok 1/4: a direct connection to $DIRECT_HOST ($addr:443) failed for $AGENT_USER and succeeded for root: $out" ;;
  0) fail "a direct connection to $DIRECT_HOST ($addr:443) succeeded: the agent is not locked down" ;;
  *) fail "a direct connection to $DIRECT_HOST failed with curl exit $code, not a refused connection: $out" ;;
esac

# 2. Through the witness. The proxy credential goes to curl on stdin, never on a command line that ps shows.
before=$(find "$RECEIPTS_DIR" -type f 2> /dev/null | wc -l)
set +e
connect=$(printf 'proxy-user = "%s:%s"\n' "$AGENT_ID" "$EGRESS_SECRET" \
  | as_agent curl -s -m 15 -o /dev/null -w '%{http_connect}' -K - -x "http://$WITNESS" "https://$REFUSED_HOST/")
set -e
[ "$connect" = 403 ] || fail "the witness answered CONNECT $REFUSED_HOST:443 with '$connect', not 403 (407 is a wrong secret; 000 is no answer)"
# the witness signs the receipt as it refuses; give the write a moment
i=0
until [ "$(find "$RECEIPTS_DIR" -type f 2> /dev/null | wc -l)" -gt "$before" ]; do
  i=$((i + 1)); [ "$i" -le 5 ] || fail "the witness refused $REFUSED_HOST but wrote no new receipt in $RECEIPTS_DIR"
  sleep 1
done
receipt=$(find "$RECEIPTS_DIR" -type f -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2-)
echo "check-lockdown: ok 2/4: CONNECT $REFUSED_HOST:443 through the witness got 403 and a receipt ($receipt)"

# 3. The gateway.
health=$(as_agent curl -sS -m 10 "http://$GATEWAY/health" 2>&1) || fail "the agent cannot reach the gateway at $GATEWAY: $health"
case "$health" in
  *'"ok":true'*) echo "check-lockdown: ok 3/4: the gateway at $GATEWAY answered the agent: $health" ;;
  *) fail "the gateway at $GATEWAY did not answer ok: $health" ;;
esac

# 4. The table. --unit passes 1 to 3 on the drop-in alone, which leaves every service on 127.0.0.1 open to the agent.
if [ -n "$NFT_TABLE" ]; then
  # shellcheck disable=SC2086 # NFT_TABLE is two words, the family and the name
  nft list table $NFT_TABLE > /dev/null 2>&1 || fail "the nftables table $NFT_TABLE is not loaded: is agent-custody-lockdown.service active?"
  echo "check-lockdown: ok 4/4: the nftables table $NFT_TABLE is loaded"
else
  echo "check-lockdown: skipped 4/4: NFT_TABLE is empty, so the nftables table was not checked"
fi
