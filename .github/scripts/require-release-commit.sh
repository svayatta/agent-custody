#!/usr/bin/env bash
# Fails unless HEAD is the commit that the tag v<version> points at and the package in it is that version. A version
# tag and `latest` are signed and published only for the tagged release commit, never for a branch that someone ran
# the workflow on by hand.
set -eu

version=${1:?usage: require-release-commit.sh <version>}
git fetch -q --depth=1 origin "refs/tags/v$version"
tag_sha=$(git rev-parse 'FETCH_HEAD^{commit}')
head_sha=$(git rev-parse HEAD)
if [ "$tag_sha" != "$head_sha" ]; then
  echo "::error::v$version points at $tag_sha, but this build is of $head_sha. A version tag and latest are built only from the tagged release commit."
  exit 1
fi
package=$(node -p "require('./packages/receipts/package.json').version")
if [ "$package" != "$version" ]; then
  echo "::error::the tagged commit has @agent-custody/receipts $package, not $version."
  exit 1
fi
