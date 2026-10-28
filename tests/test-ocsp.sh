#!/usr/bin/env bash
# tests/test-ocsp.sh - OCSP responder: good / revoked / unknown
NAME="test-ocsp"
set -uo pipefail

export MSYS2_ARG_CONV_EXCL="${MSYS2_ARG_CONV_EXCL:+$MSYS2_ARG_CONV_EXCL;}/O="

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NGINX="${NGINX:-nginx}"
NGX_PORT="${TEST_NGINX_PORT:-18443}"     # different from `make up` (8443)
OCSP_PORT="${TEST_OCSP_PORT:-12560}"     # different from `make up` (2560)

PASS=0
FAIL=0

# --- Assertions ----------------------------------------------------------------
ok() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
ko() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else ko "$desc"; fi
}

check_fails() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ko "$desc"; else ok "$desc"; fi
}

has_text() {
  if grep -q -- "$2" <<< "$3"; then ok "$1"; else ko "$1 (expected: $2)"; fi
}

lacks_text() {
  if grep -q -- "$2" <<< "$3"; then ko "$1 (unexpected: $2)"; else ok "$1"; fi
}

# Passes only if verification fails AND the error matches the expected reason.
expect_verify_fail() {
  local desc="$1" pattern="$2"; shift 2
  local out
  if out="$(openssl verify "$@" 2>&1)"; then
    ko "$desc (verification unexpectedly succeeded)"
  elif grep -qi -- "$pattern" <<< "$out"; then
    ok "$desc"
  else
    ko "$desc (failed, but not for the expected reason '$pattern')"
    sed 's/^/        /' <<< "$out"
  fi
}

# --- Helpers -------------------------------------------------------------------
wait_port() {
  local i
  for i in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

wait_port_closed() {
  local i
  for i in $(seq 1 50); do
    if ! (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

serial_of() { openssl x509 -in "$1" -noout -serial | cut -d= -f2; }

# --- Temporary PKI -------------------------------------------------------------
TMP="$(mktemp -d)"
PKI="$TMP/pki"
# The OpenSSL configs read the PKI location from $PKI_DIR (pki-tool sets it itself).
export PKI_DIR="$PKI"
export PKI_ROOT_PASS="test-passphrase-not-a-secret"
unset PKI_ROOT_PASS_FILE
pki() { bash "$ROOT_DIR/pki-tool" --pki-dir "$PKI" "$@"; }

NGX_ABS=""
OCSP_PID=""

cleanup() {
  if [[ -n "$NGX_ABS" ]]; then
    "$NGINX" -p "$NGX_ABS/" -c "$NGX_ABS/nginx.conf" -s stop >/dev/null 2>&1 || true
    wait_port_closed "$NGX_PORT" || true
  fi
  if [[ -n "$OCSP_PID" ]]; then
    kill "$OCSP_PID" 2>/dev/null || true
    wait "$OCSP_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

run_setup() {
  echo "$NAME: building a fresh PKI in $TMP"
  if ! setup >"$TMP/setup.log" 2>&1; then
    echo "$NAME: SETUP FAILED"
    tail -n 20 "$TMP/setup.log"
    exit 1
  fi
}

finish() {
  echo "$NAME: $PASS passed, $FAIL failed"
  [[ "$FAIL" -eq 0 ]]
}

setup() {
  pki init-root &&
  pki init-intermediate &&
  pki gen-ocsp-cert &&
  pki issue --profile client --cn alice &&
  pki issue --profile client --cn bob &&
  pki gen-crl
}
run_setup

INT_CRT="$PKI/intermediate/intermediate.crt"

openssl ocsp -index "$PKI/intermediate/index.txt" -port "$OCSP_PORT" \
  -rsigner "$PKI/ocsp/ocsp.crt" -rkey "$PKI/ocsp/ocsp.key" -CA "$INT_CRT" \
  >"$TMP/ocsp.log" 2>&1 &
OCSP_PID=$!
# Wait for the responder to announce it is listening. Do NOT probe the port with a
# bare TCP connection: the single-threaded responder would block on it.
ready=0
for _ in $(seq 1 50); do
  if grep -q "waiting for OCSP client connections" "$TMP/ocsp.log" 2>/dev/null; then ready=1; break; fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "$NAME: OCSP responder failed to start"; cat "$TMP/ocsp.log"; exit 1
fi

ocsp_query() {
  openssl ocsp -issuer "$INT_CRT" -url "http://127.0.0.1:$OCSP_PORT" \
    -CAfile "$PKI/ca-chain.crt" -no_nonce -timeout 10 "$@" 2>&1
}

echo "-- Valid certificate"
out="$(ocsp_query -cert "$PKI/clients/alice.crt")"
has_text "OCSP says good for a valid certificate" ": good" "$out"
has_text "response is signed by the dedicated OCSP certificate (verify OK)" "Response verify OK" "$out"

echo "-- Revoked certificate"
bob_serial="$(serial_of "$PKI/clients/bob.crt")"
check "revoke bob" pki revoke --serial "$bob_serial"
# 'openssl ocsp' reloads its database only after answering a request:
# send a throwaway query so the next answer reflects the revocation.
ocsp_query -serial 0x01 >/dev/null
has_text "OCSP says revoked for a revoked certificate" ": revoked" "$(ocsp_query -cert "$PKI/clients/bob.crt")"

echo "-- Unknown serial"
has_text "OCSP says unknown for a serial the CA never issued" ": unknown" "$(ocsp_query -serial 0x1234ABCD)"

finish
