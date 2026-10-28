#!/usr/bin/env bash
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=()

for t in test-chain.sh test-revocation.sh test-negative.sh test-ocsp.sh; do
  echo "=== $t ==="
  if ! bash "$DIR/$t"; then
    failed+=("$t")
  fi
  echo
done

if [[ ${#failed[@]} -eq 0 ]]; then
  echo "ALL TEST SUITES PASSED"
  exit 0
fi

echo "FAILED SUITES: ${failed[*]}"
exit 1
