#!/usr/bin/env bash
# Runs stock nginx and stock Envoy, each in front of a stand-in origin, with the agent-custody door answering their
# authz checks. For each: an allowed read reaches the origin, an unknown arrival's refund is refused 403 and never
# reaches it, a verified agent's refund reaches it with its body, and every receipt verifies with public keys.
# Usage: deploy/door/demo.sh [nginx] [envoy]   (both when none is named). Needs docker, node 22 or later, and
# `bun install` at the repository root. The proxy listens on 127.0.0.1:${DOOR_PROXY_PORT:-8088}.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
port=${DOOR_PROXY_PORT:-8088}
cli() { node "$root/packages/receipts/src/cli.ts" "$@"; }

if [ "$#" -eq 0 ]; then set -- nginx envoy; fi

work=""
project=""
# every compose command sees the same settings, or compose refuses to read the file
compose() { DOOR_WORK="${work:-$here}" DOOR_USER="$(id -u):$(id -g)" DOOR_PROXY_PORT="$port" docker compose -f "$here/docker-compose.yaml" -p "$project" --profile nginx --profile envoy "$@"; }
cleanup() {
  if [ -n "$project" ]; then compose down --remove-orphans >/dev/null 2>&1 || true; fi
  if [ -n "$work" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# One request through the proxy: prints the status, then the receipt id the proxy returned, then the body.
call() {
  local headers body status receipt
  headers=$(mktemp) body=$(mktemp)
  status=$(curl -sS -o "$body" -D "$headers" -w '%{http_code}' "$@")
  receipt=$(tr -d '\r' < "$headers" | awk -F': ' 'tolower($1) == "x-agent-custody-receipt" { print $2 }' | tail -n 1)
  printf '%s\n%s\n' "$status" "$receipt"
  cat "$body"
  rm -f "$headers" "$body"
}

verify() {
  local id=$1 report
  [ -n "$id" ] || fail "the proxy returned no receipt id"
  report=$(cli verify "$work/receipts/$id.json" --issuer-key "$work/keys/door.pub" --principal-key "$work/keys/principal.pub" --log "$work/log.jsonl") || { echo "$report"; fail "receipt $id did not verify"; }
  echo "$report" | grep -E '^(PASS|FAIL)  door authz|^RESULT' | sed 's/^/      /'
}

for proxy in "$@"; do
  case "$proxy" in nginx|envoy) ;; *) fail "unknown proxy $proxy: name nginx or envoy" ;; esac
  echo "== stock $proxy in front of a site, the door answering its authz checks"
  work=$(mktemp -d)
  mkdir -p "$work/keys" "$work/receipts"
  cli keygen --dir "$work/keys" --name door >/dev/null
  cli keygen --dir "$work/keys" --name principal >/dev/null
  cli grant --key "$work/keys/principal.key" --principal shop-owner --agent shopping-agent --scopes refund --out "$work/grant.json" >/dev/null
  grant=$(node -e 'process.stdout.write(Buffer.from(JSON.stringify(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")))).toString("base64url"))' "$work/grant.json")

  project="agent-custody-door-$proxy"
  started=$(compose up -d --quiet-pull origin door "$proxy" 2>&1) || { echo "$started" >&2; fail "docker compose could not start $proxy"; }
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/catalogue/ready" || true)
    if [ "$code" = 200 ]; then break; fi
    sleep 1
  done
  [ "$code" = 200 ] || { compose logs >&2; fail "$proxy did not answer 200 through the door within 60 s (last status $code)"; }

  echo "   1. anyone reads the catalogue: allowed, and the origin gets the receipt id"
  { read -r status; read -r id; body=$(cat); } < <(call "http://127.0.0.1:$port/catalogue/shoes?colour=red")
  [ "$status" = 200 ] || fail "the catalogue read answered $status: $body"
  echo "$body" | grep -q "\"receipt\":\"$id\"" || fail "the origin did not get receipt $id: $body"
  echo "      HTTP $status, receipt $id; origin: $body"
  verify "$id"

  echo "   2. an unknown arrival asks for a refund: refused 403, and the origin never sees it"
  { read -r status; read -r id; body=$(cat); } < <(call -X POST -H 'content-type: application/json' --data '{"order":"o_1","amount":1000}' "http://127.0.0.1:$port/refunds")
  [ "$status" = 403 ] || fail "the unknown refund answered $status: $body"
  if compose logs origin | grep -q "receipt=$id"; then fail "the refused refund reached the origin"; fi
  echo "      HTTP $status, receipt $id; the origin's log has no request with it"
  verify "$id"

  echo "   3. an agent with a grant from the shop's principal asks for a refund: committed to the log, then relayed with its body"
  { read -r status; read -r id; body=$(cat); } < <(call -X POST -H 'content-type: application/json' -H "x-agent-custody-grant: $grant" --data '{"order":"o_2","amount":4500}' "http://127.0.0.1:$port/refunds")
  [ "$status" = 200 ] || fail "the verified refund answered $status: $body"
  echo "$body" | grep -q '"class":"verified"' || fail "the origin did not get class verified: $body"
  echo "$body" | grep -q '"grantHeader":null' || fail "the grant reached the origin: $body"
  [ -f "$work/receipts/$id.authorization.json" ] || fail "no authorization was committed before the refund was allowed"
  echo "      HTTP $status, receipt $id; origin: $body"
  verify "$id"

  echo "   4. the door is down: $proxy refuses, and nothing reaches the origin"
  compose stop door >/dev/null 2>&1
  { read -r status; read -r id; body=$(cat); } < <(call "http://127.0.0.1:$port/catalogue/shoes?down=1")
  case "$status" in 2*) fail "$proxy relayed a request with the door down: $status $body" ;; esac
  if compose logs origin | grep -q "down=1"; then fail "the request reached the origin with the door down"; fi
  echo "      HTTP $status"

  echo "   the door saw neither body: its receipts record each decision, not the origin's answer"
  compose down --remove-orphans >/dev/null 2>&1
  project=""
  rm -rf "$work"
  work=""
done
echo "OK"
