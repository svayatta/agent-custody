#!/bin/sh
# Smoke test for the gateway image in door mode, through the compose file in proxy/: the door creates its key, becomes
# healthy in front of the stand-in origin, relays an unknown arrival's catalogue read (200, and the origin gets the receipt
# id), refuses an unknown arrival's refund (403, and the origin never sees it), relays a refund from an agent with a grant
# (200, verified), refuses the same agent's refund above the policy's amount bound and below it (403), answers each with a receipt id,
# and every one of those receipts verifies against the door's public key, the principal's key, and the local log. Then
# `docker compose stop` closes the door (exit 0, not SIGKILL).
# Usage: ./smoke.sh <name>:<tag>   needs docker with compose, curl, and a free port 18780
set -eu
image="${1:?usage: smoke.sh <name>:<tag>}"
repository="${image%:*}"
tag="${image##*:}"
case "$tag" in
  */*) repository="$image"; tag=latest ;;
esac
[ "$repository" != "$image" ] || tag=latest
here=$(cd "$(dirname "$0")" && pwd)
port=18780
work=$(mktemp -d)
project="door-smoke-$$"
# every compose command sees the same settings, or compose refuses to read the file
compose() {
  AGENT_CUSTODY_GATEWAY_REPOSITORY="$repository" AGENT_CUSTODY_GATEWAY_VERSION="$tag" DOOR_CONFIG_DIR="$work/config" DOOR_DATA="$work/data" DOOR_UID="$(id -u)" DOOR_GID="$(id -g)" DOOR_PORT="$port" \
    docker compose -f "$here/proxy/docker-compose.yaml" -p "$project" "$@"
}
cleanup() { compose down -v --remove-orphans > /dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "smoke: $*" >&2; compose logs >&2 2>&1 || true; exit 1; }
cli() { docker run --rm -u "$(id -u):$(id -g)" -v "$work:/work" "$image" "$@"; }

mkdir -p "$work/config/keys" "$work/data" "$work/keys"
cp "$here/proxy/config/door.json" "$here/proxy/config/policy.cedar" "$work/config/"
cli keygen --dir /work/keys --name principal > /dev/null 2>&1 || fail "keygen failed"
cp "$work/keys/principal.pub" "$work/config/keys/"
cli grant --key /work/keys/principal.key --principal shop-owner --agent shopping-agent --scopes refund --ttl-hours 1 --out /work/grant.json > /dev/null 2>&1 || fail "grant failed"
grant=$(base64 < "$work/grant.json" | tr -d '\n=' | tr '+/' '-_')

compose up -d --quiet-pull > /dev/null 2>&1 || fail "docker compose up failed"
door=$(compose ps -q door)
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$door")" = healthy ]; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "the door was not healthy after 60 s"
  sleep 2
done
compose logs door 2>&1 | grep -q "created the door key" || fail "door mode did not create the door key"
[ -f "$work/data/keys/door.pub" ] || fail "no door key in /data/keys"
curl -fsS "http://127.0.0.1:$port/.well-known/agent-custody-door" | grep -q '"keyid"' || fail "the door did not answer its well-known route"

# call <name> <curl args>: sets status and id (the X-Agent-Custody-Receipt of the answer); the body is in $work/<name>.body
ids=""
call() {
  name=$1; shift
  status=$(curl -sS -o "$work/$name.body" -D "$work/$name.headers" -w '%{http_code}' "$@" "http://127.0.0.1:$port$path") || fail "$name: curl failed"
  id=$(tr -d '\r' < "$work/$name.headers" | awk -F': ' 'tolower($1) == "x-agent-custody-receipt" { print $2 }' | tail -n 1)
  [ -n "$id" ] || fail "$name: the answer carried no X-Agent-Custody-Receipt"
  ids="$ids $id"
}
body() { cat "$work/$1.body"; }

path=/catalogue/shoes
call read
[ "$status" = 200 ] || fail "an unknown arrival's catalogue read answered $status: $(body read)"
grep -q "\"origin\":\"reached\"" "$work/read.body" || fail "the catalogue read did not reach the origin: $(body read)"
grep -q "\"receipt\":\"$id\"" "$work/read.body" || fail "the origin did not get receipt $id: $(body read)"

path=/refunds
call unknown-refund -X POST -H 'content-type: application/json' --data '{"order":"o_1","amount":1000}'
[ "$status" = 403 ] || fail "an unknown arrival's refund answered $status, not 403: $(body unknown-refund)"
if compose logs origin 2>&1 | grep -q "receipt=$id"; then fail "the refused refund reached the origin"; fi

call refund -X POST -H 'content-type: application/json' -H "authorization: Bearer $grant" --data '{"order":"o_2","amount":4500}'
[ "$status" = 200 ] || fail "the agent's refund with a grant answered $status, not 200: $(body refund)"
grep -q '"class":"verified"' "$work/refund.body" || fail "the origin did not get class verified: $(body refund)"

call large-refund -X POST -H 'content-type: application/json' -H "authorization: Bearer $grant" --data '{"order":"o_3","amount":9000}'
[ "$status" = 403 ] || fail "a refund above the policy's bound answered $status, not 403: $(body large-refund)"

call negative-refund -X POST -H 'content-type: application/json' -H "authorization: Bearer $grant" --data '{"order":"o_4","amount":-1}'
[ "$status" = 403 ] || fail "a negative refund answered $status, not 403: $(body negative-refund)"

for id in $ids; do
  report=$(cli verify "/work/data/receipts/$id.json" --issuer-key /work/data/keys/door.pub --principal-key /work/keys/principal.pub --log /work/data/log.jsonl 2>&1) \
    || fail "receipt $id did not verify: $report"
done

start=$(date +%s)
compose stop > /dev/null 2>&1 || fail "docker compose stop failed"
elapsed=$(( $(date +%s) - start ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$door")
[ "$code" = 0 ] || fail "the door stopped with exit code $code, not 0 (SIGKILL is 137)"
[ "$elapsed" -le 8 ] || fail "docker compose stop took ${elapsed}s: the door ignored SIGTERM"
echo "smoke: ok (door mode: key created, healthy, catalogue read relayed, unknown refund refused, granted refund relayed, refunds above and below the bound refused, $(echo "$ids" | wc -w | tr -d ' ') receipts verified, stopped in ${elapsed}s with exit 0)"
