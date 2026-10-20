#!/bin/sh
# The one command the deploy key may run: its line in authorized_keys forces this script, and the client's command
# arrives as SSH_ORIGINAL_COMMAND. "docs" brings the checkout to main and rebuilds the docs site. A version, such as
# 0.8.0, checks out the tag v0.8.0, so the compose file, the Caddyfile, and the scripts are the ones that were released
# and not whatever main has become, then backs up the log, moves log, signer, and portal to that published image, and
# puts the previous version and its checkout back if they are not healthy within two minutes. A version deploy leaves
# the checkout on the tag; "docs" returns it to main. By hand on the host: ./upgrade.sh docs, or ./upgrade.sh 0.8.0.
set -eu
cd "$(dirname "$0")"
what="${SSH_ORIGINAL_COMMAND:-${1:-}}"
if [ "$what" != docs ] && ! printf '%s\n' "$what" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+'; then
  echo "upgrade.sh: expected docs or a version such as 0.8.0, got '$what'" >&2
  exit 2
fi
compose() { docker compose --profile public "$@"; }

# git replaces a mounted Caddyfile rather than editing it, so a changed one needs the container recreated
before=$(git hash-object Caddyfile)
old_rev=$(git -C .. rev-parse HEAD)
if [ "$what" = docs ]; then
  git -C .. checkout -q main
  git -C .. pull -q --ff-only origin main
else
  git -C .. fetch -q origin "refs/tags/v$what:refs/tags/v$what"
  git -C .. checkout -q --detach "v$what"
fi
echo "checkout: $(git -C .. rev-parse --short HEAD)"
if [ "$(git hash-object Caddyfile)" != "$before" ]; then compose up -d --force-recreate --no-deps caddy; fi

if [ "$what" != docs ]; then
  if [ -x /etc/cron.daily/agent-custody-log-backup ]; then /etc/cron.daily/agent-custody-log-backup; else echo "no backup script; continuing without a backup" >&2; fi
  old=$(sed -n 's/^AGENT_CUSTODY_VERSION=//p' .env)
  set_version() { sed -i "s/^AGENT_CUSTODY_VERSION=.*/AGENT_CUSTODY_VERSION=$1/" .env; }
  healthy() {
    for _ in $(seq 24); do
      [ "$(compose ps --format '{{.Status}}' log signer portal | grep -c '(healthy)')" = 3 ] && return 0
      sleep 5
    done
    return 1
  }
  echo "upgrading from $old to $what"
  set_version "$what"
  if ! compose pull -q log signer portal || ! compose up -d log signer portal || ! healthy; then
    echo "upgrade.sh: $what did not come up healthy; going back to $old" >&2
    set_version "$old"
    git -C .. checkout -q --detach "$old_rev"
    if [ "$(git hash-object Caddyfile)" != "$before" ]; then compose up -d --force-recreate --no-deps caddy; fi
    compose up -d log signer portal
    healthy || echo "upgrade.sh: $old is not healthy either; look at the host" >&2
    exit 1
  fi
fi

./update-docs.sh
compose ps --format '{{.Service}}\t{{.Image}}\t{{.Status}}'
