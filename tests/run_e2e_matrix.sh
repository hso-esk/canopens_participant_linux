#!/usr/bin/env bash

#
# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.
#

# Matrix runner for run_e2e.sh across salt lengths (8, 12), algorithms (AES-GCM, ASCON-128),
# and crypto backends (wolfSSL, mbedTLS).
#
# Usage: tests/run_e2e_matrix.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CASE_NAMES=()
CASE_RESULTS=()
OVERALL_RC=0

run_case() {
  local name="$1"; shift
  echo
  echo "===== [$name] ====="
  if "$SCRIPT_DIR/run_e2e.sh" "$@"; then
    CASE_NAMES+=("$name"); CASE_RESULTS+=("PASS")
  else
    CASE_NAMES+=("$name"); CASE_RESULTS+=("FAIL")
    OVERALL_RC=1
  fi
}

# --- salt12 -------------------------------------------------------------------
SPSEC_BUILD_DIR="$REPO_ROOT/build_salt12" \
SPSEC_SALT_LEN=12 \
  run_case "salt12 (aes-gcm)" \
  --participant-keys "$SCRIPT_DIR/example_keys_salt12.txt"

# --- ASCON-128 (works on the plain default build - the data-plane nonce
# length is derived per-algorithm at runtime, not a build option) -----------
SPSEC_BUILD_DIR="$REPO_ROOT/build" \
  run_case "ascon" \
  --participant-keys "$SCRIPT_DIR/example_keys_short_salt.txt" --algo ascon

# --- participant crypto backend, SALT_LEN=8, AES-GCM ------------------------
SPSEC_BUILD_DIR="$REPO_ROOT/build" \
  run_case "backend: wolfssl(participant)" \
  --participant-keys "$SCRIPT_DIR/example_keys_short_salt.txt"

SPSEC_BUILD_DIR="$REPO_ROOT/build_mbedtls" \
  run_case "backend: mbedtls(participant)" \
  --participant-keys "$SCRIPT_DIR/example_keys_short_salt.txt"

echo
echo "===== run_e2e_matrix.sh summary ====="
for i in "${!CASE_NAMES[@]}"; do
  printf "%-55s %s\n" "${CASE_NAMES[$i]}" "${CASE_RESULTS[$i]}"
done
echo
if [[ $OVERALL_RC -eq 0 ]]; then
  echo "RESULT: ALL PASS"
else
  echo "RESULT: SOME FAILED"
fi
exit $OVERALL_RC
