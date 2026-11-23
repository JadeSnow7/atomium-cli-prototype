#!/usr/bin/env bash
# Probe whether `agy` falls back to $HOME/.gemini/antigravity-cli/antigravity-oauth-token
# when macOS Keychain and com.apple.SecurityServer are blocked by Seatbelt (sandbox-exec).
# NEVER modifies real ~/ credentials or macOS Login Keychain.

set -uo pipefail

REAL_HOME="${HOME}"
PROBE_HOME="/tmp/agy-probe-home"
PROBE_TMP="/tmp/agy-probe-tmp"
PROBE_SB="/tmp/agy-probe-fallback.sb"
CANARY_DIR="${PROBE_HOME}/.gemini/antigravity-cli"
CANARY_FILE="${CANARY_DIR}/antigravity-oauth-token"
CANARY_VALUE="atomium-canary-oauth-token-0000000000000000"

AGY_BIN="${AGY_BIN:-}"
if [[ -z "${AGY_BIN}" ]]; then
  if command -v agy >/dev/null 2>&1; then
    AGY_BIN="$(command -v agy)"
  elif [[ -x "${REAL_HOME}/.local/bin/agy" ]]; then
    AGY_BIN="${REAL_HOME}/.local/bin/agy"
  fi
fi

echo "=== Atomium agy Keychain-Block Fallback Probe ==="
echo "Real HOME:  ${REAL_HOME}"
echo "Probe HOME: ${PROBE_HOME}"
echo "Probe TMP:  ${PROBE_TMP}"
echo "SBPL File:  ${PROBE_SB}"
echo "agy Binary: ${AGY_BIN:-<not found>}"
echo ""

# 1. Create isolated probe directories (0700)
umask 077
mkdir -p "${PROBE_HOME}" "${PROBE_TMP}" "${CANARY_DIR}"
chmod 0700 "${PROBE_HOME}" "${PROBE_TMP}" "${PROBE_HOME}/.gemini" "${CANARY_DIR}"

# 2. Write synthetic canary token (0600)
printf '%s\n' "${CANARY_VALUE}" > "${CANARY_FILE}"
chmod 0600 "${CANARY_FILE}"
CANARY_SHA="$(shasum -a 256 "${CANARY_FILE}" | awk '{print $1}')"
echo "Canary file created: ${CANARY_FILE} (mode 0600, sha256=${CANARY_SHA})"

# 3. Write minimal Seatbelt profile denying Keychain & SecurityServer
cat > "${PROBE_SB}" <<EOF
(version 1)
(allow default)

; Explicitly allow isolated probe workspace paths
(allow file-read* file-write*
  (subpath "${PROBE_HOME}")
  (subpath "${PROBE_TMP}")
  (subpath "/private${PROBE_HOME}")
  (subpath "/private${PROBE_TMP}"))

; Explicitly deny host Login Keychain and SecurityServer IPC
(deny file-read* file-write*
  (subpath "${REAL_HOME}/Library/Keychains")
  (subpath "/Library/Keychains"))

(deny mach-lookup
  (global-name "com.apple.SecurityServer"))
EOF
chmod 0600 "${PROBE_SB}"
echo "Seatbelt profile written: ${PROBE_SB}"
echo ""

if [[ -z "${AGY_BIN}" || ! -x "${AGY_BIN}" ]]; then
  echo "CONCLUSION: [SKIPPED] agy binary not found (checked PATH and ${REAL_HOME}/.local/bin/agy)."
  echo "Set AGY_BIN=/path/to/agy and re-run."
  echo ""
  echo "Cleanup command:"
  echo "  rm -rf /tmp/agy-probe-*"
  exit 0
fi

# 4. Run non-destructive ACP initialize + session/new probe under sandbox-exec
OUT_FILE="${PROBE_TMP}/probe-stdout.txt"
ERR_FILE="${PROBE_TMP}/probe-stderr.txt"
AGY_LOG="${PROBE_TMP}/agy-probe.log"
: > "${OUT_FILE}"
: > "${ERR_FILE}"

# Send ACP initialize + session/new JSON-RPC messages on stdin (non-destructive)
ACP_INPUT="$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false,"auth":{"terminal":false}},"clientInfo":{"name":"atomium-probe","version":"0.1.0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/tmp/agy-probe-tmp","mcpServers":[]}}')"

echo "Running: HOME=${PROBE_HOME} TMPDIR=${PROBE_TMP} /usr/bin/sandbox-exec -f ${PROBE_SB} ${AGY_BIN} acp --stdio --sandbox --disable-telemetry --include-default-customizations=false --log-file ${AGY_LOG}"

# Record canary atime/mtime before run
BEFORE_STAT="$(stat -f '%a %m' "${CANARY_FILE}" 2>/dev/null || echo 'unknown')"

# Run with a 12-second watchdog using background subshell (macOS lacks GNU timeout by default)
PROBE_RC=0
(
  HOME="${PROBE_HOME}" \
  TMPDIR="${PROBE_TMP}" \
  LANG="C" \
  /usr/bin/sandbox-exec -f "${PROBE_SB}" \
    "${AGY_BIN}" acp --stdio --sandbox --disable-telemetry --include-default-customizations=false --log-file "${AGY_LOG}" \
    < <(printf '%s\n' "${ACP_INPUT}"; sleep 4) \
    >"${OUT_FILE}" 2>"${ERR_FILE}"
) &
CMD_PID=$!

WAITED=0
while kill -0 "${CMD_PID}" 2>/dev/null; do
  if [[ "${WAITED}" -ge 10 ]]; then
    kill "${CMD_PID}" 2>/dev/null || true
    break
  fi
  sleep 1
  WAITED=$((WAITED + 1))
done
wait "${CMD_PID}" 2>/dev/null || PROBE_RC=$?

AFTER_STAT="$(stat -f '%a %m' "${CANARY_FILE}" 2>/dev/null || echo 'unknown')"

STDOUT_CONTENT="$(cat "${OUT_FILE}" 2>/dev/null || true)"
STDERR_CONTENT="$(cat "${ERR_FILE}" 2>/dev/null || true)"
LOG_CONTENT="$(cat "${AGY_LOG}" 2>/dev/null || true)"
COMBINED="${STDOUT_CONTENT}"$'\n'"${STDERR_CONTENT}"$'\n'"${LOG_CONTENT}"

echo ""
echo "--- Probe Output Summary ---"
echo "Exit code: ${PROBE_RC}"
echo "Canary stat (atime mtime): before=[${BEFORE_STAT}] after=[${AFTER_STAT}]"
if [[ -n "${STDOUT_CONTENT}" ]]; then
  echo "stdout (first 10 lines):"
  head -n 10 "${OUT_FILE}" | sed 's/^/  /'
fi
if [[ -n "${STDERR_CONTENT}" ]]; then
  echo "stderr (first 10 lines):"
  head -n 10 "${ERR_FILE}" | sed 's/^/  /'
fi
echo ""

# 5. Clear conclusion
if printf '%s' "${STDERR_CONTENT}" | grep -qiE 'sandbox_apply: Operation not permitted|sandbox-exec:.*Operation not permitted'; then
  echo "CONCLUSION: [BLOCKED BY OUTER SANDBOX] sandbox_apply: Operation not permitted."
  echo "  Nested sandbox-exec is blocked in this environment."
  echo "  Please run this script directly in your normal Mac Terminal:"
  echo "    bash scripts/probe_agy_fallback.sh"
elif printf '%s' "${COMBINED}" | grep -qiE 'antigravity-oauth-token|oauth-token|fallback.*file|invalid_grant|invalid.*token|unauthorized|401|token.*malformed|parse.*token'; then
  echo "CONCLUSION: [FILE FALLBACK DETECTED] agy attempted to read or validate the canary token file at \$HOME/.gemini/antigravity-cli/antigravity-oauth-token."
  echo "  isolatedFile mode is viable for parallel multi-account execution."
elif printf '%s' "${COMBINED}" | grep -qiE 'keychain|SecurityServer|SecItem|authentication required|not authenticated|authMethods|login required|unauthenticated'; then
  echo "CONCLUSION: [AUTH/KEYCHAIN ERROR] agy failed with an auth or Keychain error when SecurityServer was blocked."
  echo "  Use hostKeychainSlot mode (serialized host Keychain slot) as the default mode."
else
  echo "CONCLUSION: [INCONCLUSIVE] Inspect probe logs at ${AGY_LOG} and stderr above."
  echo "  Default safely to hostKeychainSlot mode until file fallback is confirmed."
fi

echo ""
echo "Cleanup command:"
echo "  rm -rf /tmp/agy-probe-*"
