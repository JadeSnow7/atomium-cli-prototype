#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "==> Exporting ts-rs bindings from crates/atomium-protocol into $tmp_dir..."
TS_RS_EXPORT_DIR="$tmp_dir" cargo test --manifest-path "$ROOT_DIR/Cargo.toml" -p atomium-protocol export_bindings

PKG_GENERATED="$ROOT_DIR/packages/protocol-types/src/generated"
CRATE_BINDINGS="$ROOT_DIR/crates/atomium-protocol/bindings"

drift=0

echo "==> Checking packages/protocol-types/src/generated..."
if ! diff -ru "$tmp_dir" "$PKG_GENERATED"; then
  echo "[DRIFT] packages/protocol-types/src/generated is out of sync with crates/atomium-protocol." >&2
  drift=1
fi

echo "==> Checking crates/atomium-protocol/bindings..."
if ! diff -ru "$tmp_dir" "$CRATE_BINDINGS"; then
  echo "[DRIFT] crates/atomium-protocol/bindings is out of sync with crates/atomium-protocol." >&2
  drift=1
fi

if [[ "$drift" -ne 0 ]]; then
  echo "" >&2
  echo "Protocol TypeScript bindings drift detected!" >&2
  echo "Run: pnpm run gen:protocol" >&2
  exit 1
fi

echo "[OK] Protocol Rust<->TS bindings are in sync."
