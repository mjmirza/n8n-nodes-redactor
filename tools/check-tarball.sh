#!/usr/bin/env bash
# Fails if the npm tarball is missing the node entry or icons, or ships tests/secrets.
set -euo pipefail

list="$(npm pack --dry-run --json | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{for(const f of JSON.parse(d)[0].files)console.log(f.path)})')"

fail=0
for need in \
  dist/nodes/Redactor/Redactor.node.js \
  dist/nodes/Redactor/redactor.svg \
  dist/nodes/Redactor/redactor.dark.svg \
  LICENSE README.md package.json; do
  if ! grep -qx "$need" <<<"$list"; then echo "MISSING: $need"; fail=1; fi
done

if grep -nE '(__tests__|\.test\.js$|\.map$|\.env|\.npmrc|^test/|^nodes/)' <<<"$list"; then
  echo "UNEXPECTED FILES in tarball (above)"; fail=1
fi

entry="$(node -p 'require("./package.json").n8n.nodes[0]')"
if ! grep -qx "$entry" <<<"$list"; then echo "MISSING n8n entry: $entry"; fail=1; fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "tarball OK ($(wc -l <<<"$list" | tr -d ' ') files)"
