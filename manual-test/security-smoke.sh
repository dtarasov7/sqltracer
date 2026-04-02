#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

TMP1="$(mktemp /tmp/sqltracer-sec-1.XXXXXX.log)"
TMP2="$(mktemp /tmp/sqltracer-sec-2.XXXXXX.log)"
trap 'rm -f "$TMP1" "$TMP2"' EXIT

echo "[1/4] Reject remote listen without explicit override"
if "$PYTHON_BIN" sqltracer.py --no-tui --listen 0.0.0.0:55433 --upstream 127.0.0.1:5432 >"$TMP1" 2>&1; then
  echo "FAIL: remote listen guard did not trigger"
  cat "$TMP1"
  exit 1
fi
if ! grep -q -- "--allow-remote-listen" "$TMP1"; then
  echo "FAIL: expected --allow-remote-listen hint in error output"
  cat "$TMP1"
  exit 1
fi
echo "OK"

echo "[2/4] Reject insecure Vault HTTP URL by default"
if "$PYTHON_BIN" sqltracer.py --no-tui --vault-url http://vault.local:8200 --vault-path secret/sqltracer --vault-username demo --vault-password demo --allow-cli-secrets >"$TMP2" 2>&1; then
  echo "FAIL: insecure Vault URL guard did not trigger"
  cat "$TMP2"
  exit 1
fi
if ! grep -q -- "Vault URL must use https://" "$TMP2"; then
  echo "FAIL: expected https enforcement message in error output"
  cat "$TMP2"
  exit 1
fi
echo "OK"

echo "[3/4] Validate file permissions and pending-queue guard"
"$PYTHON_BIN" manual-test/security-smoke.py
echo "OK"

echo "[4/4] Security smoke suite passed"
