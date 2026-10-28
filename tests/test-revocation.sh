#!/usr/bin/env bash
NAME="test-revocation"
set -uo pipefail

export MSYS2_ARG_CONV_EXCL="${MSYS2_ARG_CONV_EXCL:+$MSYS2_ARG_CONV_EXCL;}/O="

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NGINX="${NGINX:-nginx}"
NGX_PORT="${TEST_NGINX_PORT:-18443}"     # different from `make up` (8443)
export OCSP_PORT="${TEST_OCSP_PORT:-12560}"     # different from `make up` (2560)

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

expect_verify_fail() {
  local desc="$1" pattern="$2"; shift 2
  local out
  if out="$(openssl verify "$@" 2>&1)"; then
    ko "$desc (verification unexpectedly succeeded)"
  elif grep -qi -- "$pattern" <<< "$out"; then
    ok "$desc"
  else
    ko "$desc (failed, but not for the expected reason '$pattern')"
    printf '        %s\n' "${out//$'\n'/$'\n        '}"
  fi
}

# --- Helpers -------------------------------------------------------------------
wait_port() {
  for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

wait_port_closed() {
  for _ in $(seq 1 50); do
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

# --- Nginx (mTLS service on a test port) -----------------------------------------
start_nginx() {
  local d="$TMP/nginx"
  mkdir -p "$d/certs" "$d/logs" "$d/temp"
  cat "$PKI/servers/web.lab.local.crt" "$PKI/intermediate/intermediate.crt" > "$d/certs/server.crt"
  cp -f "$PKI/servers/web.lab.local.key" "$d/certs/server.key"
  cp -f "$PKI/ca-chain.crt" "$d/certs/ca-chain.crt"
  cp -f "$PKI/crl-chain.pem" "$d/certs/crl-chain.pem"
  NGX_ABS="$(cd "$d" && { pwd -W 2>/dev/null || pwd; })"
  sed -e "s#/etc/nginx/certs#$NGX_ABS/certs#g" \
      -e "s#listen 8443 ssl#listen $NGX_PORT ssl#" \
      "$ROOT_DIR/services/nginx/nginx.conf" > "$d/nginx.conf"
  "$NGINX" -p "$NGX_ABS/" -c "$NGX_ABS/nginx.conf" >"$TMP/nginx-start.log" 2>&1 || return 1
  wait_port "$NGX_PORT"
}


mtls_status() {
  local -a client=()
  if [[ $# -ge 2 ]]; then client=(-cert "$1" -key "$2"); fi
  printf 'GET / HTTP/1.1\r\nHost: web.lab.local\r\nConnection: close\r\n\r\n' \
    | timeout 10 openssl s_client -quiet -connect "127.0.0.1:$NGX_PORT" \
        -servername web.lab.local -CAfile "$PKI/ca-chain.crt" \
        ${client[@]+"${client[@]}"} 2>/dev/null \
    | tr -d '\r' | grep -m1 '^HTTP/' || true
}

reload_nginx() {
  cp -f "$PKI/crl-chain.pem" "$TMP/nginx/certs/crl-chain.pem"
  "$NGINX" -p "$NGX_ABS/" -c "$NGX_ABS/nginx.conf" -s reload >/dev/null 2>&1
}

setup() {
  pki init-root &&
  pki init-intermediate &&
  pki issue --profile server --cn web.lab.local --san DNS:web.lab.local,IP:127.0.0.1 &&
  pki issue --profile client --cn alice &&
  pki issue --profile client --cn bob &&
  pki gen-crl &&
  pki gen-crl --root
}
run_setup

CHAIN="$PKI/ca-chain.crt"
INT_CRL="$PKI/intermediate/crl/intermediate.crl"
ALICE="$PKI/clients/alice.crt"
BOB="$PKI/clients/bob.crt"

if ! start_nginx; then
  echo "$NAME: Nginx failed to start"; cat "$TMP/nginx-start.log"; exit 1
fi

echo "-- Before revocation"
has_text "alice is accepted by Nginx" "200" "$(mtls_status "$ALICE" "$PKI/clients/alice.key")"
check "alice passes openssl verify -crl_check_all" openssl verify -crl_check_all -CAfile "$CHAIN" -CRLfile "$PKI/crl-chain.pem" "$ALICE"

echo "-- Revoke alice"
alice_serial="$(serial_of "$ALICE")"
check "revoke command succeeds" pki revoke --serial "$alice_serial" --reason keyCompromise
lacks_text "CRL does not list the serial before gen-crl" "$alice_serial" "$(openssl crl -in "$INT_CRL" -noout -text)"
check "gen-crl succeeds" pki gen-crl
has_text "CRL contains the revoked serial after gen-crl" "$alice_serial" "$(openssl crl -in "$INT_CRL" -noout -text)"
expect_verify_fail "revoked certificate fails openssl verify -crl_check_all" "revoked" \
  -crl_check_all -CAfile "$CHAIN" -CRLfile "$PKI/crl-chain.pem" "$ALICE"
check "non-revoked bob still passes -crl_check_all" openssl verify -crl_check_all -CAfile "$CHAIN" -CRLfile "$PKI/crl-chain.pem" "$BOB"

echo "-- Nginx after CRL refresh"
reload_nginx
# Nginx applies a reload asynchronously: allow a short delay before judging.
status=""
for _ in $(seq 1 25); do
  status="$(mtls_status "$ALICE" "$PKI/clients/alice.key")"
  if [[ "$status" != *"200"* ]]; then break; fi
  sleep 0.4
done
if [[ "$status" == *"200"* ]]; then ko "revoked client certificate is rejected by Nginx"; else ok "revoked client certificate is rejected by Nginx (${status:-handshake rejected})"; fi
has_text "non-revoked client is still accepted by Nginx" "200" "$(mtls_status "$BOB" "$PKI/clients/bob.key")"

finish
