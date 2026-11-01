#!/usr/bin/env bash
# Prints the npm dist-tag for a release tag: v1.* goes to v1-legacy, v2 and later to latest.
set -euo pipefail

tag="${1:-}"
if [[ ! "$tag" =~ ^v([0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
  echo "not a release tag: '$tag'" >&2
  exit 1
fi
major="${BASH_REMATCH[1]}"
if [ "$major" -le 1 ]; then
  echo "v1-legacy"
else
  echo "latest"
fi
