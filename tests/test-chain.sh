#!/usr/bin/env bash
NAME="test-chain"
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

# check "<description>" <command...>        passes if the command succeeds
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else ko "$desc"; fi
}

# check_fails "<description>" <command...>  passes if the command fails
check_fails() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ko "$desc"; else ok "$desc"; fi
}

# has_text "<description>" "<pattern>" "<text>"
has_text() {
  if grep -q -- "$2" <<< "$3"; then ok "$1"; else ko "$1 (expected: $2)"; fi
}

# lacks_text "<description>" "<pattern>" "<text>"
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
  pki gen-ocsp-cert &&
  pki issue --profile server --cn web.lab.local --san DNS:web.lab.local,IP:127.0.0.1 &&
  pki issue --profile client --cn alice &&
  pki issue --profile codesign --cn builder &&
  pki gen-crl &&
  pki gen-crl --root
}
run_setup

ROOT_CRT="$PKI/root/root.crt"
INT_CRT="$PKI/intermediate/intermediate.crt"
CHAIN="$PKI/ca-chain.crt"
SRV="$PKI/servers/web.lab.local.crt"
CLI="$PKI/clients/alice.crt"
CODE="$PKI/codesign/builder.crt"
OCSP="$PKI/ocsp/ocsp.crt"

echo "-- Root and intermediate"
subject="$(openssl x509 -in "$ROOT_CRT" -noout -subject | sed 's/^subject= *//')"
issuer="$(openssl x509 -in "$ROOT_CRT" -noout -issuer | sed 's/^issuer= *//')"
if [[ -n "$subject" && "$subject" == "$issuer" ]]; then ok "root certificate is self-signed (subject == issuer)"; else ko "root certificate is self-signed (subject == issuer)"; fi
check "root certificate verifies against itself" openssl verify -CAfile "$ROOT_CRT" "$ROOT_CRT"
has_text "root has CA:TRUE" "CA:TRUE" "$(openssl x509 -in "$ROOT_CRT" -noout -ext basicConstraints)"
check "intermediate verifies against the root" openssl verify -CAfile "$ROOT_CRT" "$INT_CRT"
int_bc="$(openssl x509 -in "$INT_CRT" -noout -ext basicConstraints)"
has_text "intermediate has CA:TRUE" "CA:TRUE" "$int_bc"
has_text "intermediate has pathlen:0" "pathlen:0" "$int_bc"
has_text "intermediate has name constraints (lab.local)" "DNS:lab.local" "$(openssl x509 -in "$INT_CRT" -noout -ext nameConstraints)"
has_text "intermediate has a CRL distribution point" "URI:http" "$(openssl x509 -in "$INT_CRT" -noout -ext crlDistributionPoints)"

echo "-- Leaf certificates verify against the full chain"
check "server certificate verifies (purpose sslserver)" openssl verify -CAfile "$CHAIN" -purpose sslserver "$SRV"
check "client certificate verifies (purpose sslclient)" openssl verify -CAfile "$CHAIN" -purpose sslclient "$CLI"
check "code-signing certificate verifies" openssl verify -CAfile "$CHAIN" "$CODE"
check "OCSP signing certificate verifies" openssl verify -CAfile "$CHAIN" "$OCSP"

echo "-- Extensions"
srv_ext="$(openssl x509 -in "$SRV" -noout -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName,authorityInfoAccess,crlDistributionPoints)"
has_text "server: SAN contains the DNS name" "DNS:web.lab.local" "$srv_ext"
has_text "server: SAN contains the IP address" "IP Address:127.0.0.1" "$srv_ext"
has_text "server: EKU serverAuth" "TLS Web Server Authentication" "$srv_ext"
has_text "server: CA:FALSE" "CA:FALSE" "$srv_ext"
has_text "server: AIA has an OCSP URL" "OCSP - URI:http" "$srv_ext"
has_text "server: AIA has a CA Issuers URL" "CA Issuers - URI:http" "$srv_ext"
has_text "server: CDP has a CRL URL" "intermediate.crl" "$srv_ext"
cli_ext="$(openssl x509 -in "$CLI" -noout -ext extendedKeyUsage,authorityInfoAccess,crlDistributionPoints)"
has_text "client: EKU clientAuth" "TLS Web Client Authentication" "$cli_ext"
has_text "client: AIA has an OCSP URL" "OCSP - URI:http" "$cli_ext"
has_text "client: CDP has a CRL URL" "intermediate.crl" "$cli_ext"
code_ext="$(openssl x509 -in "$CODE" -noout -ext extendedKeyUsage,authorityInfoAccess,crlDistributionPoints)"
has_text "codesign: EKU codeSigning" "Code Signing" "$code_ext"
has_text "codesign: AIA has an OCSP URL" "OCSP - URI:http" "$code_ext"
has_text "codesign: CDP has a CRL URL" "intermediate.crl" "$code_ext"
has_text "OCSP certificate: EKU OCSPSigning" "OCSP Signing" "$(openssl x509 -in "$OCSP" -noout -ext extendedKeyUsage)"

echo "-- mutual TLS"
if start_nginx; then
  has_text "valid client certificate is accepted by Nginx (200)" "200" "$(mtls_status "$CLI" "$PKI/clients/alice.key")"
else
  ko "Nginx started (see $TMP/nginx-start.log)"
  cat "$TMP/nginx-start.log"
fi

echo "-- Renewal"
old_serial="$(serial_of "$CLI")"
if pki renew --serial "$old_serial" >/dev/null 2>&1; then
  new_serial="$(serial_of "$CLI")"
  if [[ -n "$new_serial" && "$new_serial" != "$old_serial" ]]; then ok "renewal produces a new serial"; else ko "renewal produces a new serial"; fi
  check "new certificate verifies" pki verify "$CLI"
  check "old certificate remains valid until expiry" pki verify "$PKI/intermediate/newcerts/$old_serial.pem"
else
  ko "renew command succeeded"
fi

finish
