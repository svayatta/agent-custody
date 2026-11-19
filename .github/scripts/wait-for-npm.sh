#!/usr/bin/env bash
# Waits until the npm registry serves @agent-custody/receipts at the given version to an installer. npm's registry
# lags behind a publish, and a job that installs the version before then fails with a 404 or notarget.
#
# `npm install` does not read the version's own document (/<name>/<version>); it reads the package document in the
# abbreviated install format, which the registry's CDN caches separately and can serve stale for minutes after the
# version document is live. So the wait checks both, three times in a row, the way an installer will ask.
# Silent on success.
set -u

version=${1:?usage: wait-for-npm.sh <version>}
base="https://registry.npmjs.org/@agent-custody%2freceipts"
install_accept="application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

served() {
  curl -s --max-time 10 "$base/$version" | jq -e --arg v "$version" '.version == $v' > /dev/null 2>&1 &&
    curl -s --max-time 10 -H "Accept: $install_accept" "$base" | jq -e --arg v "$version" '.versions[$v] != null' > /dev/null 2>&1
}

seen=0
for _ in $(seq 60); do
  if served; then
    seen=$((seen + 1))
    [ "$seen" -ge 3 ] && exit 0
    sleep 5
    continue
  fi
  seen=0
  sleep 15
done

echo "::error::npm did not serve @agent-custody/receipts@$version to an installer within 15 minutes. Check that the release workflow published it, then rerun this workflow."
exit 1
