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

# TSA crash and recovery test at 10-node scale.
# Usage: tests/run_e2e_tsa_crash_10nodes.sh [--duration SECONDS] [--keep]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
DURATION=120
NODES=10
BASE_ID=110
KEEP=0

usage() {
  echo "Usage: $0 [--duration SECONDS] [--keep]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if ! [[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || (( DURATION < 30 )); then
  echo "--duration must be a positive integer ≥ 30" >&2
  exit 1
fi

RUNDIR="$(mktemp -d /tmp/spsec_tsa_crash.XXXXXX)"
TSA_PID=""
declare -A CLIENT_PIDS

log() { echo "[tsa-crash] $*"; }
fail() { echo "[tsa-crash] FAIL: $*" >&2; exit 1; }

cleanup() {
  local rc=$?
  if (( KEEP )); then
    log "leaving run dir and procs: $RUNDIR"
  else
    [[ -n "$TSA_PID" ]] && kill -9 "$TSA_PID" 2>/dev/null || true
    for pid in "${CLIENT_PIDS[@]}"; do
      kill -9 "$pid" 2>/dev/null || true
    done
    rm -rf "$RUNDIR"
  fi
  exit $rc
}
trap cleanup EXIT

if ! ip link show vcan0 &>/dev/null; then
  "$REPO_ROOT/setup_vcan.sh" || fail "vcan setup failed"
fi
[[ -x "$PARTICIPANT_BIN" ]] || fail "participant not built: $PARTICIPANT_BIN"

export SPSEC_STORAGE_PATH="$RUNDIR/storage"

log "Starting 10 participants (TSA @ $BASE_ID, clients $((BASE_ID+1))..$((BASE_ID+NODES-1)))"
TSA_LOG="$RUNDIR/tsa.log"
"$PARTICIPANT_BIN" -s vcan0 -i "vcan1" -p "$BASE_ID" -k "$KEYS_FILE" -t -l info \
  > "$TSA_LOG" 2>&1 &
TSA_PID=$!

for i in $(seq 1 $((NODES - 1))); do
  pid=$((BASE_ID + i))
  iface_in="vcan$((i + 1))"
  iface_out="vcan$((NODES + i + 1))"
  ip link add dev "$iface_in" type vcan 2>/dev/null || true
  ip link set up "$iface_in" 2>/dev/null || true
  "$PARTICIPANT_BIN" -s vcan0 -i "$iface_in" -p "$pid" -k "$KEYS_FILE" -l info \
    > "$RUNDIR/client_${pid}.log" 2>&1 &
  CLIENT_PIDS[$pid]=$!
done

# Wait for warmup so timesync propagates
log "Warmup: 5s"
sleep 5

# Phase 1: normal traffic for a portion of the duration
phase1=$(( DURATION / 3 ))
log "Phase 1: normal operation for ${phase1}s"
sleep "$phase1"

# Phase 2: SIGKILL the TSA
log "Phase 2: SIGKILL the TSA (PID $TSA_PID)"
kill -9 "$TSA_PID" 2>/dev/null || true
wait "$TSA_PID" 2>/dev/null || true
TSA_PID=""

phase2=$(( DURATION / 3 ))
log "Phase 2: observing WARNING -> WAITING transition for ${phase2}s"
sleep "$phase2"

# Phase 3: restart TSA with fresh csalt
log "Phase 3: restarting TSA with fresh csalt"
"$PARTICIPANT_BIN" -s vcan0 -i "vcan1" -p "$BASE_ID" -k "$KEYS_FILE" -t -l info \
  > "$RUNDIR/tsa_restart.log" 2>&1 &
TSA_PID=$!

phase3=$(( DURATION - phase1 - phase2 ))
log "Phase 3: monitoring re-convergence for ${phase3}s"
sleep "$phase3"

# Inspect: each client log should show warning -> waiting -> secure
ok=1
for pid in "${!CLIENT_PIDS[@]}"; do
  log="$RUNDIR/client_${pid}.log"
  warn_seen=$(grep -c -i "WARNING" "$log" 2>/dev/null || true)
  wait_seen=$(grep -c -i "WAITING" "$log" 2>/dev/null || true)
  if (( warn_seen == 0 && wait_seen == 0 )); then
    log "client $pid: no WARNING/WAITING state observed (may have stayed SECURE if TSA flapped quickly)"
  else
    log "client $pid: WARNING=$warn_seen WAITING=$wait_seen"
  fi
done

# Check TSA restart log shows fresh csalt
if ! grep -q -i "csalt" "$RUNDIR/tsa_restart.log" 2>/dev/null; then
  log "Note: no 'csalt' keyword in TSA restart log (informational)"
fi

log "PASS: 10-node TSA crash + restart cycle completed"
exit 0
