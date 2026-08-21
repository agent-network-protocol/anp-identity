#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline="$repo_root/api/anp-identity.txt"
key_import_baseline="$repo_root/api/anp-identity-key-import.txt"
actual=$(mktemp)
key_import_actual=$(mktemp)
key_import_additions=$(mktemp)
key_import_missing=$(mktemp)
trap 'rm -f "$actual" "$key_import_actual" "$key_import_additions" "$key_import_missing"' EXIT

cargo +nightly-2026-08-01 public-api \
  --manifest-path "$repo_root/crates/anp-identity/Cargo.toml" -sss >"$actual"
diff -u "$baseline" "$actual"

cargo +nightly-2026-08-01 public-api \
  --manifest-path "$repo_root/crates/anp-identity/Cargo.toml" \
  --features key-import -sss >"$key_import_actual"

comm -13 <(sort "$actual") <(sort "$key_import_actual") >"$key_import_additions"
comm -23 <(sort "$actual") <(sort "$key_import_actual") >"$key_import_missing"
test ! -s "$key_import_missing"
diff -u "$key_import_baseline" "$key_import_additions"
