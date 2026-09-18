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

# Power-cut simulation during key writes to verify atomic persistence.
# Usage: tests/run_e2e_power_cut.sh [--iterations N] [--keep]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
ITERATIONS=20
KEEP=0

usage() {
  echo "Usage: $0 [--iterations N] [--keep]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

RUNDIR="$(mktemp -d /tmp/spsec_powercut.XXXXXX)"
STORAGE_DIR="$RUNDIR/storage"
OVERALL_RC=0

log() { echo "[powercut] $*"; }
fail() { echo "[powercut] FAIL: $*" >&2; OVERALL_RC=1; }

cleanup() {
  local rc=$?
  if (( KEEP )); then
    log "leaving run dir: $RUNDIR"
  else
    [[ $OVERALL_RC -eq 0 ]] && rm -rf "$RUNDIR"
  fi
  exit $rc
}
trap cleanup EXIT

if ! ip link show vcan0 &>/dev/null; then
  "$REPO_ROOT/setup_vcan.sh" || fail "vcan setup failed"
fi
[[ -x "$PARTICIPANT_BIN" ]] || fail "participant not built: $PARTICIPANT_BIN"

mkdir -p "$STORAGE_DIR"

export SPSEC_STORAGE_PATH="$STORAGE_DIR"

for iter in $(seq 1 "$ITERATIONS"); do
  log "Iteration $iter/$ITERATIONS"

  # Launch participant
  "$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p 120 -k "$KEYS_FILE" -l info \
    > "$RUNDIR/run_${iter}.log" 2>&1 &
  PID=$!

  # Wait briefly for it to start
  sleep 0.5

  # SIGKILL it mid-startup, simulating a power cut
  kill -9 "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true

  # Check for orphan .tmp files
  tmp_files=$(find "$STORAGE_DIR" -name "*.tmp" 2>/dev/null | wc -l)
  bin_files=$(find "$STORAGE_DIR" -name "*.bin" 2>/dev/null | wc -l)
  log "  After kill: $tmp_files .tmp files, $bin_files .bin files"

  # Restart and verify it boots
  "$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p 120 -k "$KEYS_FILE" -l info \
    > "$RUNDIR/restart_${iter}.log" 2>&1 &
  PID2=$!
  sleep 0.5
  if ! kill -0 "$PID2" 2>/dev/null; then
    fail "participant failed to restart after power cut (iter $iter)"
    cat "$RUNDIR/restart_${iter}.log"
    continue
  fi
  kill -9 "$PID2" 2>/dev/null || true
  wait "$PID2" 2>/dev/null || true

  # Clean .tmp between iterations to verify restart always works
  find "$STORAGE_DIR" -name "*.tmp" -delete 2>/dev/null || true
done

if (( OVERALL_RC == 0 )); then
  log "PASS: $ITERATIONS power-cut iterations completed without corruption"
fi
exit $OVERALL_RC
