#!/usr/bin/env bash
# The door Worker run for issue 432: deploy, two requests, both receipts verified.
#
# Inputs:
#   CF_TOKEN_FILE    path of a file that holds the Cloudflare API token
#   LOG_TOKEN_FILE   path of a file that holds the API key of the log tenant
#   TENANT           name of the tenant on the hosted log
#   LOG_ID           optional. Default: the id in the tenant's public tree head. If set, it must be equal to that id.
#   CLOUDFLARE_ACCOUNT_ID  optional. Default: the one account that the token can see.
#   STRICT_PUBLIC    1 (default) adds the compatibility flag global_fetch_strictly_public to the door, because the
#                    test origin is a Worker in the same account. 0 deploys the door with the template's flags only.
#   WARM             number of extra allowed requests for the CPU time figure (default 10)
#   TAIL             1 (default) captures `wrangler tail`; the token then needs Workers Tail Read. 0 skips it.
#   WORK             directory outside the repository for the door key and the output (default ~/.cache/door-worker-run-432)
#
# The script prints no secret. It stops at the first failure. All output goes to $WORK/out/<UTC time>/.
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
WORK="${WORK:-$HOME/.cache/door-worker-run-432}"
DOOR_DIR="$REPO/deploy/door/cloudflare-worker"
CLI="$REPO/packages/receipts/dist/cli.js"
KEYS="$WORK/keys"
DOOR=agent-custody-door
ORIGIN=door-origin-test
RECEIPTS=agent-custody-door-receipts
HITS=door-origin-test-hits
LOG_HOST=https://log.agent-custody.dev
STRICT_PUBLIC="${STRICT_PUBLIC:-1}"
WARM="${WARM:-10}"
TAIL="${TAIL:-1}"

: "${CF_TOKEN_FILE:?set CF_TOKEN_FILE}" "${LOG_TOKEN_FILE:?set LOG_TOKEN_FILE}" "${TENANT:?set TENANT}"
[ -s "$CLI" ] || { echo "no $CLI: run 'bun install' and 'bun run build' at the root" >&2; exit 1; }
case "$WORK/" in "$REPO"/*) echo "WORK must be outside the repository" >&2; exit 1 ;; esac
mkdir -p "$WORK"
[ -s "$KEYS/door.key" ] || node "$CLI" keygen --dir "$KEYS" --name door
for f in "$CF_TOKEN_FILE" "$LOG_TOKEN_FILE" "$KEYS/door.key" "$KEYS/door.pub" "$CLI" "$DOOR_DIR/wrangler.toml"; do
  [ -s "$f" ] || { echo "missing or empty: $f" >&2; exit 1; }
done
[ -z "$(git -C "$REPO" status --porcelain)" ] || { echo "the repository has changes; the run must use the template as committed" >&2; exit 1; }

OUT="$WORK/out/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT/bundles"
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

export CLOUDFLARE_API_TOKEN
CLOUDFLARE_API_TOKEN="$(<"$CF_TOKEN_FILE")"
export WRANGLER_SEND_METRICS=false
wr() { npx -y wrangler@4 "$@"; }
# The token goes to curl on stdin, never on a command line. printf is a shell builtin.
cfapi() { printf 'header = "Authorization: Bearer %s"\n' "$CLOUDFLARE_API_TOKEN" | curl -sS -m 30 -K - "https://api.cloudflare.com/client/v4$1"; }

step "versions"
{ echo "commit $(git -C "$REPO" rev-parse HEAD)"; echo "agent-custody $(jq -r .version "$REPO/packages/receipts/package.json")"; echo "node $(node --version)"; echo "wrangler $(wr --version | tail -1)"; } | tee "$OUT/versions.txt"

step "account"
if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
  ids="$(cfapi /accounts | jq -r '.result[]?.id')"
  [ "$(printf '%s\n' "$ids" | grep -c .)" = 1 ] || fail "the token must see exactly one account; set CLOUDFLARE_ACCOUNT_ID"
  CLOUDFLARE_ACCOUNT_ID="$ids"
fi
export CLOUDFLARE_ACCOUNT_ID
SUB="$(cfapi "/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/subdomain" | jq -r '.result.subdomain // empty')"
[ -n "$SUB" ] || fail "the account has no workers.dev subdomain; register one in the dashboard (Workers & Pages), then run again"
ORIGIN_URL="https://$ORIGIN.$SUB.workers.dev"
DOOR_URL="https://$DOOR.$SUB.workers.dev"
echo "account and workers.dev subdomain: found"

step "plan (not fatal: the subscriptions list needs Billing Read)"
cfapi "/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/account-settings" > "$OUT/plan-account-settings.json" || true
cfapi "/accounts/$CLOUDFLARE_ACCOUNT_ID/subscriptions" > "$OUT/plan-subscriptions.json" || true
jq -r 'if .success then "subscriptions: " + ([.result[]?.rate_plan | (.public_name // .id)] | join(", ") | if . == "" then "none (Workers Free)" else . end) else "subscriptions: not readable with this token; read the plan in the dashboard" end' "$OUT/plan-subscriptions.json" | tee "$OUT/plan.txt" || true

step "log tenant"
LOG_URL="$LOG_HOST/t/$TENANT/"
LOG_KEYS="$(curl -sS -m 30 "$LOG_HOST/.well-known/agent-custody-log.json" | tee "$OUT/log-keys.json" | jq -r '[.keys[].publicKeyPem] | join("")')"
[ -n "$LOG_KEYS" ] || fail "the log publishes no key"
HEAD_ID="$(curl -sS -m 30 "${LOG_URL}head" | tee "$OUT/log-head-before.json" | jq -r '.treeHead.payload | @base64d | fromjson | .log // empty')"
[ -n "$HEAD_ID" ] || fail "no tree head at ${LOG_URL}head: is the tenant name correct?"
LOG_ID="${LOG_ID:-$HEAD_ID}"
[ "$LOG_ID" = "$HEAD_ID" ] || fail "LOG_ID is $LOG_ID, but the tenant's tree head names $HEAD_ID"
code="$(printf 'header = "Authorization: Bearer %s"\n' "$(<"$LOG_TOKEN_FILE")" | curl -sS -m 30 -K - -o /dev/null -w '%{http_code}' "${LOG_URL}usage")"
# The log checks the key before it answers. 404 means the key is good and this log keeps no usage.
[ "$code" = 200 ] || [ "$code" = 404 ] || fail "the log refused the API key for tenant $TENANT (HTTP $code)"
echo "log $LOG_URL id $LOG_ID: tree head and API key OK"

step "origin: bucket and deploy"
(cd "$HERE/origin" && { wr r2 bucket info "$HITS" >/dev/null 2>&1 || wr r2 bucket create "$HITS"; } && wr deploy) 2>&1 | tee "$OUT/origin-deploy.txt"
for i in $(seq 1 60); do [ "$(curl -4 -s -m 10 -o /dev/null -w '%{http_code}' "$ORIGIN_URL/__hits?run=none" || true)" = 200 ] && break; sleep 5; done
[ "$i" -lt 60 ] || fail "the origin does not answer at its workers.dev address"

step "door: bucket, secrets, deploy (the tracked wrangler.toml, with the run's values as --var)"
FLAGS=(nodejs_compat)
[ "$STRICT_PUBLIC" = 1 ] && FLAGS+=(global_fetch_strictly_public)
(
  cd "$DOOR_DIR"
  wr r2 bucket info "$RECEIPTS" >/dev/null 2>&1 || wr r2 bucket create "$RECEIPTS"
  wr secret put DOOR_KEY < "$KEYS/door.key"
  wr secret put LOG_TOKEN < "$LOG_TOKEN_FILE"
  wr deploy --var "ORIGIN_URL:$ORIGIN_URL" --var "LOG_URL:$LOG_URL" --var "LOG_ID:$LOG_ID" --var "LOG_KEYS:$LOG_KEYS" --compatibility-flags "${FLAGS[@]}"
) 2>&1 | tee "$OUT/door-deploy.txt"
grep -F "Total Upload" "$OUT/door-deploy.txt" || fail "the deploy reported no bundle size"
echo "compatibility flags: ${FLAGS[*]}" | tee -a "$OUT/versions.txt"

if [ "$TAIL" = 1 ]; then
  step "tail"
  wr tail "$DOOR" --format json > "$OUT/door-tail.jsonl" 2> "$OUT/door-tail.err" &
  T1=$!
  wr tail "$ORIGIN" --format json > "$OUT/origin-tail.jsonl" 2> "$OUT/origin-tail.err" &
  T2=$!
  trap 'kill "$T1" "$T2" 2>/dev/null || true' EXIT
  sleep 20
  kill -0 "$T1" 2>/dev/null && kill -0 "$T2" 2>/dev/null || fail "wrangler tail stopped; see $OUT/door-tail.err (does the token have Workers Tail Read?)"
fi

step "requests"
RUN="run$(date -u +%H%M%S)$RANDOM"
MYIP="$(curl -4 -sS -m 30 https://www.cloudflare.com/cdn-cgi/trace | sed -n 's/^ip=//p')"
[ -n "$MYIP" ] || fail "cannot read the client address"
for i in $(seq 1 60); do [ "$(curl -4 -s -m 20 -D "$OUT/door-wellknown.headers" -o "$OUT/door-wellknown.json" -w '%{http_code}' "$DOOR_URL/.well-known/agent-custody-door" || true)" = 200 ] && break; sleep 5; done
[ "$i" -lt 60 ] || fail "the door does not answer 200 at /.well-known/agent-custody-door; see $OUT/door-wellknown.json"
jq -c . "$OUT/door-wellknown.json"

code="$(curl -4 -sS -m 30 -D "$OUT/allowed.headers" -o "$OUT/allowed.body" -w '%{http_code}' -H "x-run: $RUN" "$DOOR_URL/products/1")"
cat "$OUT/allowed.headers" "$OUT/allowed.body"; echo
[ "$code" = 200 ] || fail "GET /products/1 answered $code, not 200 (an origin error 1042 means the door needs STRICT_PUBLIC=1)"
code="$(curl -4 -sS -m 30 -D "$OUT/refused.headers" -o "$OUT/refused.body" -w '%{http_code}' -X POST -H "x-run: $RUN" -H 'content-type: application/json' -d '{"sku":"tea","qty":1}' "$DOOR_URL/orders")"
cat "$OUT/refused.headers" "$OUT/refused.body"; echo
[ "$code" = 403 ] || fail "POST /orders answered $code, not 403"

header() { awk -v h="$2:" 'tolower($1) == h { print $2 }' "$1" | tr -d '\r'; }
ALLOWED="$(header "$OUT/allowed.headers" x-agent-custody-receipt)"
REFUSED="$(header "$OUT/refused.headers" x-agent-custody-receipt)"
[ -n "$ALLOWED" ] && [ -n "$REFUSED" ] || fail "an answer has no x-agent-custody-receipt header"
[ "$(header "$OUT/allowed.headers" x-agent-custody-class)" = unknown ] || fail "the allowed answer has no x-agent-custody-class: unknown"
jq -e '.origin == "door-origin-test" and .path == "/products/1"' "$OUT/allowed.body" >/dev/null || fail "the allowed answer is not the origin's"

for i in $(seq 1 "$WARM"); do curl -4 -sS -m 30 -o /dev/null -w '%{http_code} ' -H "x-run: $RUN" "$DOOR_URL/products/1"; done; echo

step "the origin's own log"
curl -4 -sS -m 30 "$ORIGIN_URL/__hits?run=$RUN" | tee "$OUT/origin-hits.json" | jq .
jq -e --argjson n "$((WARM + 1))" '(.truncated | not) and (.hits | length) == $n and all(.hits[]; endswith(" GET /products/1"))' "$OUT/origin-hits.json" >/dev/null \
  || fail "the origin's log must hold $((WARM + 1)) GET /products/1 and no other request for run $RUN"
echo "origin log: $((WARM + 1)) GET /products/1, no POST /orders"

step "bundles from R2, and verify"
for id in "$ALLOWED" "$REFUSED"; do
  (cd "$DOOR_DIR" && wr r2 object get "$RECEIPTS/$id.json" --file "$OUT/bundles/$id.json" --remote) > "$OUT/r2-get-$id.txt" 2>&1 || { cat "$OUT/r2-get-$id.txt"; fail "no bundle $id.json in the bucket"; }
  node "$CLI" verify "$OUT/bundles/$id.json" --issuer-key "$KEYS/door.pub" --log-url "$LOG_URL" --log-id "$LOG_ID" | tee "$OUT/verify-$id.txt"
  node "$CLI" verify "$OUT/bundles/$id.json" --issuer-key "$KEYS/door.pub" --log-url "$LOG_URL" --log-id "$LOG_ID" --json > "$OUT/verify-$id.json"
  jq -e --arg ip "$MYIP" --arg id "$id" '.ok == true
    and .statement.predicate.receiptId == $id
    and .statement.predicate.issuer.kind == "door"
    and .statement.predicate.issuer.framework == "cloudflare-worker"
    and .statement.predicate.facts.arrival.remote == $ip' "$OUT/verify-$id.json" >/dev/null \
    || fail "receipt $id: issuer is not door / cloudflare-worker, or facts.arrival.remote is not the client address"
  echo "receipt $id: verified, issuer door / cloudflare-worker, facts.arrival.remote is the client address"
done
jq -e '.statement.predicate.execution.status == "executed"' "$OUT/verify-$ALLOWED.json" >/dev/null || fail "the allowed receipt is not executed"
jq -e '.statement.predicate.execution.status == "denied"' "$OUT/verify-$REFUSED.json" >/dev/null || fail "the refused receipt is not denied"
cp "$KEYS/door.pub" "$OUT/door.pub"

if [ "$TAIL" = 1 ]; then
  step "CPU time per decision, from wrangler tail (ms, lower is better)"
  sleep 15
  kill "$T1" "$T2" 2>/dev/null || true
  wait "$T1" "$T2" 2>/dev/null || true
  jq -s '[.[] | select(.event.request != null) | {method: .event.request.method, path: (.event.request.url | sub("^https://[^/]+"; "")), status: .event.response.status, outcome, cpuTime, wallTime}]' "$OUT/door-tail.jsonl" > "$OUT/door-cpu.json"
  jq -c '.[]' "$OUT/door-cpu.json"
  jq -e 'length > 0 and all(.[]; .cpuTime != null)' "$OUT/door-cpu.json" >/dev/null || fail "the tail holds no door event with cpuTime; see $OUT/door-tail.jsonl"
  jq -r '[.[] | select(.path == "/products/1") | .cpuTime] | sort | "GET /products/1: \(length) events, cpuTime min \(.[0]) median \(.[(length / 2 | floor)]) max \(.[-1]) ms"' "$OUT/door-cpu.json" | tee "$OUT/door-cpu.txt"
  jq -s -c '[.[] | select(.event.request != null) | .logs[]?.message[]? | (fromjson? // .)]' "$OUT/origin-tail.jsonl" > "$OUT/origin-tail-hits.json"
  echo "origin tail: $(jq length "$OUT/origin-tail-hits.json") log lines (the R2 list above is the complete log)"
fi

step "done"
echo "allowed receipt $ALLOWED"
echo "refused receipt $REFUSED"
grep -F "Total Upload" "$OUT/door-deploy.txt"
cat "$OUT/plan.txt"
echo "output: $OUT"
echo "The bundles and the tail hold the client address $MYIP and the workers.dev host. Read them before you publish them."
