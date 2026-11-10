#!/bin/sh
# The attested gateway on your own machine, with the SIMULATED provider: no TEE is involved, and the receipts say so.
# Builds the gateway image from this checkout, runs it with an attested key (made in memory, never written), makes one
# call, and verifies the receipt from the host: as an attested build with --allow-simulated-attestation, refused
# without it, refused against another release digest, and refused when the receipt or the attestation is edited.
# Usage: deploy/gateway/tee/local-simulated.sh      needs docker, bun, Node 22, and a free port 18796
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
receipts="$repo/packages/receipts"
port=18796
work=$(mktemp -d)
name="gateway-tee-sim-$$"
image="agent-custody-gateway:tee-local"
cleanup() { docker rm -f "$name" > /dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "tee-local: $*" >&2; docker logs "$name" >&2 2>&1 || true; exit 1; }
cli() { node "$receipts/src/cli.ts" "$@"; }

echo "== build the gateway image from this checkout"
mkdir -p "$work/ctx/pkg"
(cd "$receipts" && bun run build > /dev/null && bun pm pack --destination "$work/ctx/pkg" > /dev/null)
cp "$repo/deploy/gateway/Dockerfile" "$repo/deploy/gateway/gateway-entrypoint.sh" "$work/ctx/"
docker build -q -t "$image" "$work/ctx" > /dev/null
# Locally there is no registry digest, so the image id stands in for it. The simulated provider is TOLD this digest;
# nothing measures it. On Confidential Space the launcher measures the image and the token carries its digest.
digest=$(docker image inspect -f '{{.Id}}' "$image")
echo "   image $digest"

echo "== a starter config, with an attested key in place of a key file"
mkdir -p "$work/config" "$work/data"
docker run --rm -u "$(id -u):$(id -g)" -v "$work/config:/config" "$image" init > /dev/null 2>&1 || fail "init failed"
node -e '
const fs = require("node:fs");
const file = process.argv[1];
const c = JSON.parse(fs.readFileSync(file, "utf8"));
delete c.identity.keyFile;
c.attestation = { provider: "simulated" };
c.upstream.rest.baseUrl = "http://127.0.0.1:9";
fs.writeFileSync(file, JSON.stringify(c, null, 2));
' "$work/config/gateway.json"

echo "== start it (simulated attestation)"
docker run -d --name "$name" -u "$(id -u):$(id -g)" -p "127.0.0.1:$port:8790" \
  -v "$work/config:/config:ro" -v "$work/data:/data" -e AGENT_CUSTODY_IMAGE_DIGEST="$digest" \
  "$image" gateway --config /config/gateway.json --http --host 0.0.0.0 --port 8790 > /dev/null
i=0
until curl -fsS "http://127.0.0.1:$port/health" > /dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "the gateway did not become healthy"
  sleep 1
done
[ -z "$(ls "$work/data/keys" 2>/dev/null)" ] || fail "an attested gateway wrote a key file"
attestation=$(ls "$work/data/receipts/attestations/"*.json)
echo "   no key file written; attestation logged at ${attestation#"$work"/}"

echo "== one call (the upstream is a closed local port, so the call errors; the receipt is what matters)"
id=$(cd "$receipts" && node scripts/tee-local-call.ts "http://127.0.0.1:$port" "$work/config/demo/grant.json" example.lookup '{"id":"item_1"}')
receipt="$work/data/receipts/$id.json"
echo "   receipt $id"
docker stop "$name" > /dev/null

vfy() { r=$1; shift; cli verify "$r" --principal-key "$work/config/keys/principal.pub" --log "$work/data/log.jsonl" --attestation "$attestation" "$@"; }

echo "== verify as an attested build, simulated allowed: must pass"
vfy "$receipt" --release-digest "$digest" --allow-simulated-attestation || fail "the receipt did not verify as an attested build"

echo "== without --allow-simulated-attestation: must fail"
if vfy "$receipt" --release-digest "$digest" > "$work/out" 2>&1; then fail "simulated evidence passed without the test flag"; fi
grep "attested build" "$work/out"

echo "== against another release digest: must fail"
other="sha256:$(printf '%064d' 0)"
if vfy "$receipt" --release-digest "$other" --allow-simulated-attestation > "$work/out" 2>&1; then fail "a receipt verified against another release"; fi
grep "attested build" "$work/out"

echo "== the receipt edited after it was signed: must fail"
node -e '
const fs = require("node:fs");
const b = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const st = JSON.parse(Buffer.from(b.envelope.payload, "base64").toString());
st.predicate.tool.name = "example.delete";
b.envelope.payload = Buffer.from(JSON.stringify(st)).toString("base64");
fs.writeFileSync(process.argv[2], JSON.stringify(b));
' "$receipt" "$work/tampered-receipt.json"
if vfy "$work/tampered-receipt.json" --release-digest "$digest" --allow-simulated-attestation > "$work/out" 2>&1; then fail "an edited receipt verified"; fi
grep "FAIL" "$work/out"

echo "== the attestation's evidence edited to claim another image: must fail"
node -e '
const fs = require("node:fs");
const [file, out, other] = process.argv.slice(1);
const b = JSON.parse(fs.readFileSync(file, "utf8"));
const st = JSON.parse(Buffer.from(b.envelope.payload, "base64").toString());
const ev = st.predicate.evidence.envelope;
const p = JSON.parse(Buffer.from(ev.payload, "base64").toString());
ev.payload = Buffer.from(JSON.stringify({ ...p, imageDigest: other })).toString("base64");
b.envelope.payload = Buffer.from(JSON.stringify(st)).toString("base64");
fs.writeFileSync(out, JSON.stringify(b));
' "$attestation" "$work/tampered-attestation.json" "$other"
if cli verify "$receipt" --principal-key "$work/config/keys/principal.pub" --log "$work/data/log.jsonl" --attestation "$work/tampered-attestation.json" --release-digest "$other" --allow-simulated-attestation > "$work/out" 2>&1; then fail "an edited attestation verified"; fi
grep "FAIL" "$work/out"

echo
echo "tee-local: OK. The receipt verified as an attested build (SIMULATED), and every edited or mismatched case was refused."
echo "tee-local: SIMULATED evidence proves nothing about hardware; see packages/receipts/docs/attestation.md for the real provider."
