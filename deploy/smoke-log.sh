#!/bin/sh
# Smoke test for the log image: it generates its key, becomes healthy, serves its head and its key document, and
# `docker stop` closes it (exit 0, not SIGKILL). Usage: ./smoke-log.sh <image>     needs docker and curl; port 18787
set -eu
image="${1:?usage: smoke-log.sh <image>}"
port=18787
name="log-smoke-$$"
cleanup() { docker rm -f "$name" > /dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { echo "smoke: $*" >&2; docker logs "$name" >&2 2>&1 || true; exit 1; }

docker run -d --name "$name" -p "127.0.0.1:$port:8787" "$image" > /dev/null
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ]; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "not healthy after 60 s"
  sleep 2
done
curl -fsS "http://127.0.0.1:$port/head" > /dev/null || fail "/head did not answer"
curl -fsS "http://127.0.0.1:$port/.well-known/agent-custody-log.json" | grep -q keyid || fail "the key document has no key"

start=$(date +%s)
docker stop "$name" > /dev/null
elapsed=$(( $(date +%s) - start ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$code" = 0 ] || fail "stopped with exit code $code, not 0 (SIGKILL is 137)"
[ "$elapsed" -le 8 ] || fail "docker stop took ${elapsed}s: the log ignored SIGTERM"
echo "smoke: ok (healthy, head and key document served, stopped in ${elapsed}s with exit 0)"
