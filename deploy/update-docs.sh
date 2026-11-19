#!/bin/sh
# The docs site is no longer served from this host: DOCS_HOST redirects to the website, and the compose file has no
# docs service. This removes a docs container and image left from before, then does nothing. It keeps its name
# because upgrade.sh calls it after every deploy, including the upgrade.sh already installed on a host.
set -eu
cd "$(dirname "$0")"
docker compose --profile public up -d --no-recreate --remove-orphans caddy
docker image rm agent-custody-docs:local > /dev/null 2>&1 || true
echo "docs: retired; ${DOCS_HOST:-the docs host} redirects to https://agent-custody.dev"
