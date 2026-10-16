#!/usr/bin/env bash
# Publish in dependency order; only registry E404 or an empty response means missing.
set -euo pipefail

PACKAGES=(
  "core/bytes:@wake-protocol/bytes"
  "core/codec:@wake-protocol/codec"
  "core/crypto:@wake-protocol/crypto"
  "core/protocol:@wake-protocol/core"
  "client:@wake-protocol/client"
  "server:@wake-protocol/server"
)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

for entry in "${PACKAGES[@]}"; do
  dir="${entry%%:*}"
  name="${entry##*:}"
  pkg_dir="$ROOT/$dir"
  version="$(node -p 'require(process.argv[1]).version' "$pkg_dir/package.json")"

  if npm view "$name@$version" version --json --registry=https://registry.npmjs.org >"$TEMP_DIR/result" 2>"$TEMP_DIR/error"; then
    published="$(node -e '
      const text = require("node:fs").readFileSync(process.argv[1], "utf8").trim();
      if (text) {
        const version = JSON.parse(text);
        if (typeof version !== "string") throw new Error("Unexpected npm view response");
        process.stdout.write(version);
      }
    ' "$TEMP_DIR/result")"
    if [[ "$published" == "$version" ]]; then
      echo "Skipping $name@$version (already published)"
      continue
    fi
    if [[ -n "$published" ]]; then
      echo "Unexpected registry version for $name@$version: $published" >&2
      exit 1
    fi
  else
    # Do not treat authentication, rate limiting or network failures as missing versions.
    code="$(node -e '
      try {
        const result = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
        process.stdout.write(String(result.error?.code ?? ""));
      } catch { process.stdout.write(""); }
    ' "$TEMP_DIR/result")"
    if [[ "$code" != "E404" ]]; then
      cat "$TEMP_DIR/result" "$TEMP_DIR/error" >&2
      echo "Cannot determine whether $name@$version exists; stopping" >&2
      exit 1
    fi
  fi

  echo "Publishing $name@$version..."
  npm publish --provenance --access public "$pkg_dir"
  echo "Published $name@$version"
done
