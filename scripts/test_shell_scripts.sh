#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> Running bash -n syntax checks..."
SCRIPTS_TO_CHECK=(
  "fixtures/m0-probe.sh"
  "scripts/probe_agy_auth.sh"
  "scripts/probe_agy_fallback.sh"
  "scripts/check_protocol_sync.sh"
  "scripts/test_shell_scripts.sh"
)

for rel_path in "${SCRIPTS_TO_CHECK[@]}"; do
  bash -n "$ROOT_DIR/$rel_path"
  echo "  [OK] bash -n $rel_path"
done

echo "==> Running fixtures/m0-probe.sh functional tests..."
PROBE_SCRIPT="$ROOT_DIR/fixtures/m0-probe.sh"
TARGET_FILE="$tmp/probe_payload.txt"
PAYLOAD="atomium-exact-bytes-123"

# 1. write creates file with exact bytes (no trailing newline)
bash "$PROBE_SCRIPT" write "$TARGET_FILE" "$PAYLOAD"
if [[ ! -f "$TARGET_FILE" ]]; then
  echo "[FAIL] write did not create $TARGET_FILE" >&2
  exit 1
fi

ACTUAL_BYTES="$(wc -c < "$TARGET_FILE" | tr -d '[:space:]')"
EXPECTED_BYTES="${#PAYLOAD}"
if [[ "$ACTUAL_BYTES" -ne "$EXPECTED_BYTES" ]]; then
  echo "[FAIL] byte count mismatch: expected $EXPECTED_BYTES, got $ACTUAL_BYTES" >&2
  exit 1
fi
echo "  [OK] m0-probe.sh write created exact $EXPECTED_BYTES bytes without trailing newline"

# 2. read prints exact bytes back (preserve raw bytes via printf/cmp)
READ_FILE="$tmp/read_back.txt"
bash "$PROBE_SCRIPT" read "$TARGET_FILE" > "$READ_FILE"
if ! cmp -s "$TARGET_FILE" "$READ_FILE"; then
  echo "[FAIL] read output bytes did not match written file" >&2
  exit 1
fi
echo "  [OK] m0-probe.sh read printed exact bytes back"

# 3. Invalid subcommand and missing subcommand exit with code 2
rc_invalid=0
bash "$PROBE_SCRIPT" invalid-subcommand >/dev/null 2>&1 || rc_invalid=$?
if [[ "$rc_invalid" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for invalid subcommand, got $rc_invalid" >&2
  exit 1
fi
echo "  [OK] m0-probe.sh invalid subcommand exited with 2"

rc_missing=0
bash "$PROBE_SCRIPT" >/dev/null 2>&1 || rc_missing=$?
if [[ "$rc_missing" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for missing subcommand, got $rc_missing" >&2
  exit 1
fi
echo "  [OK] m0-probe.sh missing subcommand exited with 2"

echo "All shell script checks passed."
