#!/usr/bin/env bash
# tests/test-negative.sh - certificates that must be rejected
NAME="test-negative"
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
  pki issue --profile server --cn web.lab.local --san DNS:web.lab.local &&
  pki issue --profile client --cn alice &&
  pki issue --profile server --cn evil.example.com --san DNS:evil.example.com
}
run_setup

CHAIN="$PKI/ca-chain.crt"
SRV="$PKI/servers/web.lab.local.crt"
CLI="$PKI/clients/alice.crt"
EVIL="$PKI/servers/evil.example.com.crt"

echo "-- Wrong extendedKeyUsage"
check "control: client certificate is valid as a client" openssl verify -CAfile "$CHAIN" -purpose sslclient "$CLI"
expect_verify_fail "client certificate used as a server certificate is rejected" "purpose" \
  -CAfile "$CHAIN" -purpose sslserver "$CLI"

echo "-- Name constraints"
check "control: server certificate inside lab.local is valid" openssl verify -CAfile "$CHAIN" -purpose sslserver "$SRV"
expect_verify_fail "certificate for a name outside the constraint is rejected" "subtree" \
  -CAfile "$CHAIN" -purpose sslserver "$EVIL"

echo "-- Expired certificate"
exp="$TMP/expired"
mkdir -p "$exp"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$exp/old.key" >/dev/null 2>&1
openssl req -new -config "$ROOT_DIR/config/openssl-intermediate.cnf" -key "$exp/old.key" \
  -subj "/O=Lab PKI/CN=old.lab.local" -addext "subjectAltName=DNS:old.lab.local" \
  -out "$exp/old.csr" >/dev/null 2>&1
if PKI_DIR="$PKI" openssl ca -config "$ROOT_DIR/config/openssl-intermediate.cnf" -batch -notext -rand_serial \
     -extensions server_cert -startdate 20200101000000Z -enddate 20200201000000Z \
     -in "$exp/old.csr" -out "$exp/old.crt" >/dev/null 2>&1; then
  expect_verify_fail "expired certificate is rejected" "expired" -CAfile "$CHAIN" -purpose sslserver "$exp/old.crt"
else
  ko "could not generate the expired certificate"
fi

echo "-- Tampered certificate"
tmp_dir="$TMP/tamper"
mkdir -p "$tmp_dir"
openssl x509 -in "$CLI" -outform DER -out "$tmp_dir/orig.der"
LC_ALL=C sed 's/alice/alicf/' "$tmp_dir/orig.der" > "$tmp_dir/tampered.der"
if cmp -s "$tmp_dir/orig.der" "$tmp_dir/tampered.der"; then
  ko "could not tamper with the certificate"
else
  openssl x509 -inform DER -in "$tmp_dir/tampered.der" -out "$tmp_dir/tampered.pem"
  expect_verify_fail "tampered certificate is rejected" "signature" \
    -CAfile "$CHAIN" -purpose sslclient "$tmp_dir/tampered.pem"
fi

finish
