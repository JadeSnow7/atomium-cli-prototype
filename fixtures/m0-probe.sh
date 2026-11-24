#!/usr/bin/env bash
set -euo pipefail

# M0 synthetic boundary probe helper script.
# Invoked inside macOS Seatbelt by `atomium-cli doctor` or standalone for inspection.
MODE="${1:-help}"
case "$MODE" in
  read)
    cat "$2"
    ;;
  write)
    printf '%s' "$3" > "$2"
    ;;
  *)
    echo "Usage: $0 read <path> | write <path> <content>" >&2
    exit 2
    ;;
esac
