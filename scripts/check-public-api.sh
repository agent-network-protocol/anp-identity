#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline="$repo_root/api/anp-did.txt"
actual=$(mktemp)
trap 'rm -f "$actual"' EXIT

cargo +nightly-2026-08-01 public-api \
  --manifest-path "$repo_root/crates/anp-did/Cargo.toml" -sss >"$actual"
diff -u "$baseline" "$actual"
