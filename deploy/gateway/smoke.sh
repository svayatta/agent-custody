#!/bin/sh
# Smoke test for the gateway image: init writes a config, the container becomes healthy, a connection with no grant is
# refused and one with the demo grant gets a session, and `docker stop` closes the gateway (exit 0, not SIGKILL).
# Usage: ./smoke.sh <image>        needs docker, curl, and a free port 18790
set -eu
image="${1:?usage: smoke.sh <image>}"
port=18790
work=$(mktemp -d)
name="gateway-smoke-$$"
cleanup() { docker rm -f "$name" > /dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "smoke: $*" >&2; docker logs "$name" >&2 2>&1 || true; exit 1; }

mkdir "$work/config"
docker run --rm -u "$(id -u):$(id -g)" -v "$work/config:/config" "$image" init > /dev/null 2>&1 || fail "init failed"
[ -f "$work/config/gateway.json" ] && [ -f "$work/config/demo/grant.json" ] || fail "init wrote no config or grant"

docker run -d --name "$name" -v "$work/config:/config:ro" -p "127.0.0.1:$port:8790" "$image" > /dev/null
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ]; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "not healthy after 60 s"
  sleep 2
done

curl -fsS "http://127.0.0.1:$port/health" | grep -q '"ok":true' || fail "/health did not answer ok"
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
post() { curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' "$@" -d "$init"; }
[ "$(post)" = 403 ] || fail "a connection with no grant was not refused"
grant=$(base64 < "$work/config/demo/grant.json" | tr -d '\n=' | tr '+/' '-_')
[ "$(post -H "authorization: Bearer $grant")" = 200 ] || fail "the demo grant did not open a session"

start=$(date +%s)
docker stop "$name" > /dev/null
elapsed=$(( $(date +%s) - start ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$code" = 0 ] || fail "stopped with exit code $code, not 0 (SIGKILL is 137)"
[ "$elapsed" -le 8 ] || fail "docker stop took ${elapsed}s: the gateway ignored SIGTERM"
echo "smoke: ok (healthy, no-grant refused, demo grant accepted, stopped in ${elapsed}s with exit 0)"
