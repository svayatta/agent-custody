#!/bin/sh
# Tests upgrade.sh against a throwaway repository with a stand-in docker: a version deploy checks out the release tag
# and not the unreleased commits after it, "docs" returns to main, and an unhealthy version puts the previous version
# and its checkout back. Needs git and GNU sed (the host's upgrade.sh uses `sed -i`). Run: ./test-upgrade.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "test-upgrade: $*" >&2; exit 1; }
git_() { git -c user.name=t -c user.email=t@example.com "$@"; }

git_ init -q --bare "$work/origin.git"
git_ clone -q "$work/origin.git" "$work/host" 2> /dev/null
mkdir -p "$work/host/deploy" "$work/bin"
cp "$here/upgrade.sh" "$work/host/deploy/upgrade.sh"
printf 'site-0.7\n' > "$work/host/deploy/Caddyfile"
printf '#!/bin/sh\nexit 0\n' > "$work/host/deploy/update-docs.sh"
chmod +x "$work/host/deploy/upgrade.sh" "$work/host/deploy/update-docs.sh"
printf 'AGENT_CUSTODY_VERSION=0.7.0\n' > "$work/host/deploy/.env"
cat > "$work/bin/docker" <<'STUB'
#!/bin/sh
# `docker compose ... ps --format` is answered, a recreate of the proxy can be made to fail, and every call is logged
echo "$*" >> "${STUB_LOG:?}"
case "$*" in
  *"--force-recreate"*caddy*) [ "${STUB_CADDY_FAIL:-0}" = 1 ] && exit 1 ;;
  *" ps "*) if [ "${STUB_HEALTHY:-1}" = 1 ]; then printf 'Up (healthy)\nUp (healthy)\nUp (healthy)\n'; else printf 'Up (unhealthy)\n'; fi ;;
esac
exit 0
STUB
chmod +x "$work/bin/docker"

cd "$work/host"
git_ checkout -q -b main
git_ add -A && git_ commit -q -m "0.7.0 deploy files" && git_ tag v0.7.0
echo "released" > deploy/marker && printf 'site-0.8\n' > deploy/Caddyfile && git_ add -A && git_ commit -q -m "release 0.8.0 files" && git_ tag v0.8.0
git_ push -q origin main --tags
echo "unreleased" > deploy/marker && printf 'site-unreleased\n' > deploy/Caddyfile && git_ add -A && git_ commit -q -m "unreleased change after the tag"
git_ push -q origin main
released=$(git rev-parse v0.8.0); tip=$(git rev-parse main)
git_ checkout -q v0.7.0
git_ checkout -q main

cd "$work/host/deploy"
export PATH="$work/bin:$PATH" STUB_LOG="$work/docker.log"
recreates() { grep -c -- "--force-recreate --no-deps caddy" "$STUB_LOG" || true; }
# the sed in upgrade.sh must be GNU; on a BSD sed run this test in a Linux container
( ./upgrade.sh 0.8.0 > "$work/out1" 2>&1 ) || { cat "$work/out1" >&2; fail "a healthy version deploy failed"; }
[ "$(git -C .. rev-parse HEAD)" = "$released" ] || fail "the version deploy is not on the release tag"
[ "$(cat marker)" = released ] || fail "the released files are not the ones on disk"
grep -q '^AGENT_CUSTODY_VERSION=0.8.0$' .env || fail "the version was not set"
[ "$(recreates)" = 1 ] || fail "the proxy was not recreated for a changed Caddyfile"

./upgrade.sh docs > "$work/out2" 2>&1 || { cat "$work/out2" >&2; fail "docs failed"; }
[ "$(git -C .. rev-parse HEAD)" = "$tip" ] || fail "docs did not return the checkout to main"

# an unhealthy version: the version, the checkout, and the proxy's file all go back (the proxy is recreated twice)
printf 'AGENT_CUSTODY_VERSION=0.7.0\n' > .env
: > "$STUB_LOG"
if STUB_HEALTHY=0 ./upgrade.sh 0.8.0 > "$work/out3" 2>&1; then fail "an unhealthy version reported success"; fi
[ "$(git -C .. rev-parse HEAD)" = "$tip" ] || fail "the rollback did not restore the previous checkout"
grep -q '^AGENT_CUSTODY_VERSION=0.7.0$' .env || fail "the rollback did not restore the previous version"
[ "$(recreates)" = 2 ] || fail "the proxy was recreated $(recreates) times, not on the way forward and back"

# a proxy that will not start on the new Caddyfile also rolls everything back
printf 'AGENT_CUSTODY_VERSION=0.7.0\n' > .env
: > "$STUB_LOG"
if STUB_CADDY_FAIL=1 ./upgrade.sh 0.8.0 > "$work/out4" 2>&1; then fail "a proxy that did not start reported success"; fi
[ "$(git -C .. rev-parse HEAD)" = "$tip" ] || fail "the failed proxy start did not roll the checkout back"
grep -q '^AGENT_CUSTODY_VERSION=0.7.0$' .env || fail "the failed proxy start did not roll the version back"
echo "test-upgrade: ok"
