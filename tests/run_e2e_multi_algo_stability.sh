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

# Multi-algorithm stability test comparing AES-GCM, ChaCha20, and ASCON.
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
CURRENT_PIDS=""
OVERALL_RC=0

log() { echo "[multialgo] $*"; }
fail() { echo "[multialgo] FAIL: $*" >&2; OVERALL_RC=1; }

cleanup() {
  local rc=$?
  if [[ -n "${CURRENT_PIDS:-}" ]]; then
    kill -9 $CURRENT_PIDS 2>/dev/null || true
  fi
  (( KEEP )) || rm -rf "$RUNDIR"
  exit $rc
}
trap cleanup EXIT

if ! ip link show vcan0 &>/dev/null; then
  "$REPO_ROOT/setup_vcan.sh" || fail "vcan setup failed"
fi
[[ -x "$PARTICIPANT_BIN" ]] || fail "participant not built: $PARTICIPANT_BIN"

wait_for_ready() {
  local logfile="$1" timeout="$2"
  local waited=0
  while (( waited < timeout * 10 )); do
    grep -q "State transition: Waiting -> Secure" "$logfile" 2>/dev/null && return 0
    sleep 0.1
    waited=$((waited + 1))
  done
  return 1
}

run_algo() {
  local label="$1"
  shift
  local extra=("$@")
  log "=== ${label} ==="
  local aldir="$RUNDIR/${label}"
  mkdir -p "$aldir"
  export SPSEC_STORAGE_PATH="$aldir/storage"
  mkdir -p "$SPSEC_STORAGE_PATH"

  "$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p 120 -k "$KEYS_FILE" -t "${extra[@]}" -l info \
    > "$aldir/tsa.log" 2>&1 &
  local tsa_pid=$!
  "$PARTICIPANT_BIN" -s vcan0 -i vcan2 -p 121 -k "$KEYS_FILE" "${extra[@]}" -l info \
    > "$aldir/client.log" 2>&1 &
  local c_pid=$!
  CURRENT_PIDS="$tsa_pid $c_pid"

  if ! wait_for_ready "$aldir/tsa.log" 5; then
    fail "TSA ($label) failed to reach SECURE state"
  fi
  if ! wait_for_ready "$aldir/client.log" 5; then
    fail "Client ($label) failed to reach SECURE state"
  fi

  if ! python3 "$SCRIPT_DIR/benchmark_latency.py" --count 50 --gap 0.01 --json \
    > "$aldir/latency.json" 2>&1; then
    fail "$label benchmark execution failed"
  fi
  cat "$aldir/latency.json" 2>/dev/null | head -n 12

  if grep -q '"error"' "$aldir/latency.json" 2>/dev/null; then
    fail "$label benchmark reported error"
  fi

  # Check both participants are still alive before stopping them
  if ! kill -0 "$tsa_pid" 2>/dev/null; then
    fail "TSA died during $label benchmark"
  fi
  if ! kill -0 "$c_pid" 2>/dev/null; then
    fail "Client died during $label benchmark"
  fi

  kill "$c_pid" "$tsa_pid" 2>/dev/null || true
  for _ in {1..20}; do
    kill -0 "$c_pid" 2>/dev/null || kill -0 "$tsa_pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$c_pid" "$tsa_pid" 2>/dev/null || true
  wait "$c_pid" 2>/dev/null || true
  wait "$tsa_pid" 2>/dev/null || true
  CURRENT_PIDS=""
}

run_algo "aes-gcm"
run_algo "chacha" --chacha
run_algo "ascon"  --ascon

if (( OVERALL_RC == 0 )); then
  log "PASS: all 3 algorithms ran without crashing and verified end-to-end traffic"
fi
exit $OVERALL_RC
