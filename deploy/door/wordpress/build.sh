#!/bin/sh
# Builds agent-custody-door.zip, the file that a site owner uploads at Plugins > Add New > Upload Plugin.
# Usage: ./build.sh [out dir]   needs zip
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "${1:-$here}" && pwd)
rm -f "$out/agent-custody-door.zip"
(cd "$here" && zip -q -r -X "$out/agent-custody-door.zip" agent-custody-door)
echo "$out/agent-custody-door.zip"
