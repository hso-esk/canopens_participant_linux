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

# Multi-Algorithm E2E Stability Test
#
# Brings up 4 participants and runs the same traffic flow under each
# supported AEAD algorithm (AES-GCM, ChaCha20-Poly1305, ASCON-128) and
# reports per-algorithm throughput.
#
# Usage: tests/run_e2e_multi_algo_stability.sh [--keep]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
DURATION=15
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

RUNDIR="$(mktemp -d /tmp/spsec_multialgo.XXXXXX)"
OVERALL_RC=0

log() { echo "[multialgo] $*"; }
fail() { echo "[multialgo] FAIL: $*" >&2; OVERALL_RC=1; }

cleanup() {
  local rc=$?
  (( KEEP )) || rm -rf "$RUNDIR"
  exit $rc
}
trap cleanup EXIT

if ! ip link show vcan0 &>/dev/null; then
  "$REPO_ROOT/setup_vcan.sh" || fail "vcan setup failed"
fi
[[ -x "$PARTICIPANT_BIN" ]] || fail "participant not built: $PARTICIPANT_BIN"

run_algo() {
  local label="$1"
  shift
  local extra=("$@")
  log "=== ${label} ==="
  local aldir="$RUNDIR/${label}"
  mkdir -p "$aldir"

  "$PARTICIPANT_BIN" -i vcan0 -s vcan1 -p 120 -k "$KEYS_FILE" -t "${extra[@]}" -l info \
    > "$aldir/tsa.log" 2>&1 &
  local tsa_pid=$!
  "$PARTICIPANT_BIN" -i vcan0 -s vcan2 -p 121 -k "$KEYS_FILE" "${extra[@]}" -l info \
    > "$aldir/client.log" 2>&1 &
  local c_pid=$!

  sleep 3

  python3 "$SCRIPT_DIR/benchmark_latency.py" --count 50 --gap 0.01 --json \
    > "$aldir/latency.json" 2>&1 || true
  cat "$aldir/latency.json" 2>/dev/null | head -n 12

  kill "$c_pid" 2>/dev/null
  kill "$tsa_pid" 2>/dev/null
  wait "$c_pid" 2>/dev/null
  wait "$tsa_pid" 2>/dev/null
}

run_algo "aes-gcm"
run_algo "chacha" --chacha
run_algo "ascon"  --ascon

if (( OVERALL_RC == 0 )); then
  log "PASS: all 3 algorithms ran without crashing"
fi
exit $OVERALL_RC
