#!/usr/bin/env bash
# Waits until the npm registry serves @agent-custody/receipts at the given version. npm's registry lags a few
# minutes behind a publish, and a job that installs the version before then fails with a 404 or notarget.
# Silent on success.
set -u

version=${1:?usage: wait-for-npm.sh <version>}
url="https://registry.npmjs.org/@agent-custody%2freceipts/$version"

for _ in $(seq 40); do
  if curl -s --max-time 10 "$url" | jq -e --arg v "$version" '.version == $v' > /dev/null 2>&1; then
    exit 0
  fi
  sleep 15
done

echo "::error::npm did not serve @agent-custody/receipts@$version within 10 minutes. Check that the release workflow published it, then rerun this workflow."
exit 1
