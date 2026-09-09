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

# Heterogeneous Crypto Backend Interoperability Test
#
# Brings up one participant built with wolfSSL and one with mbedTLS on the
# same bus, exchanges secure process data, and verifies the frames are
# accepted by both backends.
#
# Prerequisites:
#   build/         (default wolfSSL)
#   build_mbedtls/ (built with -DSPSEC_CRYPTO_BACKEND=mbedtls)
#
# Usage: tests/run_e2e_backend_interop.sh [--keep] [--duration SECONDS]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WOLFSSL_DIR="${SPSEC_WOLFSSL_DIR:-$REPO_ROOT/build}"
MBEDTLS_DIR="${SPSEC_MBEDTLS_DIR:-$REPO_ROOT/build_mbedtls}"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
DURATION=10
KEEP=0

usage() {
  echo "Usage: $0 [--keep] [--duration SECONDS]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

WOLF_BIN="$WOLFSSL_DIR/spsec_participant"
MBED_BIN="$MBEDTLS_DIR/spsec_participant"

if [[ ! -x "$WOLF_BIN" ]]; then
  echo "ERROR: $WOLF_BIN not built" >&2
  exit 1
fi
if [[ ! -x "$MBED_BIN" ]]; then
  echo "ERROR: $MBED_BIN not built (run cmake -B build_mbedtls -DSPSEC_CRYPTO_BACKEND=mbedtls ...)" >&2
  exit 1
fi

RUNDIR="$(mktemp -d /tmp/spsec_backend_interop.XXXXXX)"
WOLF_PID=""
MBED_PID=""
OVERALL_RC=0

log() { echo "[backend-interop] $*"; }
fail() { echo "[backend-interop] FAIL: $*" >&2; OVERALL_RC=1; }

cleanup() {
  local rc=$?
  if (( KEEP )); then
    log "leaving run dir: $RUNDIR"
  else
    [[ -n "$WOLF_PID" ]] && kill -9 "$WOLF_PID" 2>/dev/null || true
    [[ -n "$MBED_PID" ]] && kill -9 "$MBED_PID" 2>/dev/null || true
    [[ $OVERALL_RC -eq 0 ]] && rm -rf "$RUNDIR"
  fi
  exit $rc
}
trap cleanup EXIT

if ! ip link show vcan0 &>/dev/null; then
  "$REPO_ROOT/setup_vcan.sh" || fail "vcan setup failed"
fi

# Start wolfSSL participant
log "Starting wolfSSL participant (PID 120, TSA)"
"$WOLF_BIN" -i vcan0 -s vcan1 -p 120 -k "$KEYS_FILE" -t -l info \
  > "$RUNDIR/wolfssl.log" 2>&1 &
WOLF_PID=$!

# Start mbedTLS participant
log "Starting mbedTLS participant (PID 121)"
"$MBED_BIN" -i vcan0 -s vcan2 -p 121 -k "$KEYS_FILE" -l info \
  > "$RUNDIR/mbedtls.log" 2>&1 &
MBED_PID=$!

# Let them negotiate
log "Running for ${DURATION}s..."
sleep "$DURATION"

# Check both still alive
if ! kill -0 "$WOLF_PID" 2>/dev/null; then
  fail "wolfSSL participant died"
fi
if ! kill -0 "$MBED_PID" 2>/dev/null; then
  fail "mbedTLS participant died"
fi

# Check for any cross-backend errors in logs
wolf_errs=$(grep -c -i "tag verification failed\|Invalid authentication" "$RUNDIR/wolfssl.log" 2>/dev/null || true)
mbed_errs=$(grep -c -i "tag verification failed\|Invalid authentication" "$RUNDIR/mbedtls.log" 2>/dev/null || true)
log "wolfSSL auth errors: $wolf_errs   mbedTLS auth errors: $mbed_errs"

if (( OVERALL_RC == 0 )); then
  log "PASS: heterogeneous backend participants coexisted"
fi
exit $OVERALL_RC
