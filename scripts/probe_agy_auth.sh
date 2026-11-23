#!/usr/bin/env bash
# Read-only diagnostic probe for agy macOS Login Keychain & ~/.gemini/antigravity-cli state.
# NEVER modifies or deletes anything in ~/ or Login Keychain.
# NEVER prints full tokens/secrets (only first 6 chars + "..." and SHA-256 digest).

set -uo pipefail

SECURITY_BIN="/usr/bin/security"
AGY_DIR="${HOME}/.gemini/antigravity-cli"

redact_stdin() {
  local raw
  raw="$(cat)"
  if [[ -z "${raw}" ]]; then
    printf 'preview=<empty> bytes=0 sha256=%s' "$(printf '' | shasum -a 256 | awk '{print $1}')"
    return 0
  fi
  # Strip trailing newlines for preview/length display only; hash exact bytes.
  local digest byte_len prefix
  digest="$(printf '%s' "${raw}" | shasum -a 256 | awk '{print $1}')"
  byte_len="$(printf '%s' "${raw}" | wc -c | tr -d '[:space:]')"
  # Sanitize control characters in the 6-char prefix for safe terminal output.
  prefix="$(printf '%s' "${raw}" | LC_ALL=C tr '\r\n\t' '   ' | cut -c1-6)"
  printf 'preview=%s... bytes=%s sha256=%s' "${prefix}" "${byte_len}" "${digest}"
  unset raw
}

probe_keychain_item() {
  local service="$1"
  local account="$2"
  local tmp_err
  tmp_err="$(mktemp /tmp/agy-probe-err.XXXXXX 2>/dev/null || true)"
  local secret=""
  local rc=0

  if [[ -n "${tmp_err}" ]]; then
    secret="$("${SECURITY_BIN}" find-generic-password -s "${service}" -a "${account}" -w 2>"${tmp_err}")" || rc=$?
  else
    secret="$("${SECURITY_BIN}" find-generic-password -s "${service}" -a "${account}" -w 2>/dev/null)" || rc=$?
  fi

  if [[ "${rc}" -eq 0 ]]; then
    printf '  [FOUND] service=%q account=%q %s\n' "${service}" "${account}" "$(printf '%s' "${secret}" | redact_stdin)"
  else
    local err_msg=""
    if [[ -n "${tmp_err}" && -f "${tmp_err}" ]]; then
      err_msg="$(tr '\n' ' ' < "${tmp_err}" | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
    fi
    if [[ -z "${err_msg}" ]]; then
      err_msg="exit code ${rc}"
    fi
    printf '  [UNAVAILABLE] service=%q account=%q reason=%s\n' "${service}" "${account}" "${err_msg}"
  fi

  unset secret
  if [[ -n "${tmp_err}" ]]; then
    rm -f "${tmp_err}" 2>/dev/null || true
  fi
}

echo "=== Atomium agy Auth Probe (Read-Only) ==="
echo "Host: $(uname -s) $(uname -m) | User: $(id -un) | Home: ${HOME}"
echo ""

echo "--- 1. Direct Keychain Slot Check (service=gemini, account=antigravity) ---"
if [[ ! -x "${SECURITY_BIN}" ]]; then
  echo "  [ERROR] ${SECURITY_BIN} not found or not executable."
else
  probe_keychain_item "gemini" "antigravity"
fi
echo ""

echo "--- 2. Keychain Metadata Scan (entries matching 'antigravity' or 'gemini') ---"
if [[ ! -x "${SECURITY_BIN}" ]]; then
  echo "  [SKIP] ${SECURITY_BIN} unavailable."
else
  dump_err="$(mktemp /tmp/agy-dump-err.XXXXXX 2>/dev/null || true)"
  dump_out=""
  dump_rc=0
  if [[ -n "${dump_err}" ]]; then
    dump_out="$("${SECURITY_BIN}" dump-keychain 2>"${dump_err}")" || dump_rc=$?
  else
    dump_out="$("${SECURITY_BIN}" dump-keychain 2>/dev/null)" || dump_rc=$?
  fi

  if [[ "${dump_rc}" -ne 0 && -z "${dump_out}" ]]; then
    err_reason=""
    if [[ -n "${dump_err}" && -f "${dump_err}" ]]; then
      err_reason="$(tr '\n' ' ' < "${dump_err}" | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
    fi
    echo "  [BLOCKED] Unable to read Keychain metadata (rc=${dump_rc}): ${err_reason:-sandboxed or keychain locked}"
    echo "  Hint: Run this script directly in your normal macOS Terminal if executing inside a sandbox."
  else
    # Parse generic password entries from dump-keychain metadata (never uses -d).
    matches="$(printf '%s\n' "${dump_out}" | awk '
      BEGIN { in_item=0; cls=""; svce=""; acct=""; desc=""; labl=""; }
      /^keychain:/ {
        if (in_item && (tolower(svce) ~ /(antigravity|gemini)/ || tolower(acct) ~ /(antigravity|gemini)/ || tolower(labl) ~ /(antigravity|gemini)/ || tolower(desc) ~ /(antigravity|gemini)/)) {
          print cls "\t" svce "\t" acct "\t" labl;
        }
        in_item=1; cls=""; svce=""; acct=""; desc=""; labl="";
      }
      /^class:/ {
        if (match($0, /"[^"]+"/)) cls = substr($0, RSTART+1, RLENGTH-2);
      }
      /"svce"<blob>=/ {
        if (match($0, /"svce"<blob>="[^"]*"/)) {
          s = substr($0, RSTART, RLENGTH);
          sub(/^"svce"<blob>="/, "", s);
          sub(/"$/, "", s);
          svce = s;
        }
      }
      /"acct"<blob>=/ {
        if (match($0, /"acct"<blob>="[^"]*"/)) {
          s = substr($0, RSTART, RLENGTH);
          sub(/^"acct"<blob>="/, "", s);
          sub(/"$/, "", s);
          acct = s;
        }
      }
      /"desc"<blob>=/ {
        if (match($0, /"desc"<blob>="[^"]*"/)) {
          s = substr($0, RSTART, RLENGTH);
          sub(/^"desc"<blob>="/, "", s);
          sub(/"$/, "", s);
          desc = s;
        }
      }
      /0x00000007 <blob>=/ {
        if (match($0, /0x00000007 <blob>="[^"]*"/)) {
          s = substr($0, RSTART, RLENGTH);
          sub(/^0x00000007 <blob>="/, "", s);
          sub(/"$/, "", s);
          labl = s;
        }
      }
      END {
        if (in_item && (tolower(svce) ~ /(antigravity|gemini)/ || tolower(acct) ~ /(antigravity|gemini)/ || tolower(labl) ~ /(antigravity|gemini)/ || tolower(desc) ~ /(antigravity|gemini)/)) {
          print cls "\t" svce "\t" acct "\t" labl;
        }
      }
    ' | sort -u)"

    if [[ -z "${matches}" ]]; then
      echo "  No matching Keychain metadata entries found for 'antigravity' or 'gemini'."
    else
      while IFS=$'\t' read -r cls svce acct labl; do
        printf '  [META] class=%q service=%q account=%q label=%q\n' "${cls}" "${svce}" "${acct}" "${labl}"
        if [[ "${cls}" == "genp" && -n "${svce}" && -n "${acct}" ]]; then
          probe_keychain_item "${svce}" "${acct}"
        fi
      done <<< "${matches}"
    fi
  fi
  if [[ -n "${dump_err}" ]]; then
    rm -f "${dump_err}" 2>/dev/null || true
  fi
fi
echo ""

echo "--- 3. Directory Check: ${AGY_DIR} ---"
if [[ ! -e "${AGY_DIR}" ]]; then
  echo "  [MISSING] ${AGY_DIR} does not exist."
elif [[ ! -r "${AGY_DIR}" ]]; then
  echo "  [BLOCKED] ${AGY_DIR} exists but is not readable (sandbox or permission restriction)."
else
  ls -la "${AGY_DIR}" 2>&1 | sed 's/^/  /'
  echo ""
  echo "  Token-like file digests (redacted):"
  found_token_file=0
  while IFS= read -r -d '' f; do
    base="$(basename "${f}")"
    lower_base="$(printf '%s' "${base}" | tr '[:upper:]' '[:lower:]')"
    if [[ "${lower_base}" == *token* || "${lower_base}" == *auth* || "${lower_base}" == *cred* || "${lower_base}" == *oauth* || "${lower_base}" == *secret* || "${lower_base}" == *.json ]]; then
      found_token_file=1
      perms="$(ls -ld "${f}" | awk '{print $1, $3, $4}')"
      if [[ -r "${f}" ]]; then
        summary="$(redact_stdin < "${f}")"
        printf '  [FILE] %s (%s) %s\n' "${f}" "${perms}" "${summary}"
      else
        printf '  [FILE-UNREADABLE] %s (%s)\n' "${f}" "${perms}"
      fi
    fi
  done < <(find "${AGY_DIR}" -maxdepth 2 -type f -print0 2>/dev/null)

  if [[ "${found_token_file}" -eq 0 ]]; then
    echo "  (No token-like or JSON files found in ${AGY_DIR})"
  fi
fi

echo ""
echo "=== Probe Complete (No host state was modified) ==="
