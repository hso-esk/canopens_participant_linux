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

# High-Density Node Scaling Test (20 nodes)
#
# Usage: tests/run_e2e_scale_20nodes.sh [--keep] [--duration SECONDS]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
NODES=20
DURATION=60
KEEP=0
BASE_ID=108

usage() {
  echo "Usage: $0 [--keep] [--duration SECONDS] [--nodes N]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --nodes) NODES="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if (( BASE_ID + NODES - 1 > 127 )); then
  echo "BASE_ID=$BASE_ID with NODES=$NODES exceeds 127 ID limit" >&2
  exit 1
fi

RUNDIR="$(mktemp -d /tmp/spsec_scale20.XXXXXX)"
declare -A PIDS
TSA_PID=""
OVERALL_RC=0

log() { echo "[scale20] $*"; }
fail() { echo "[scale20] FAIL: $*" >&2; OVERALL_RC=1; }

cleanup() {
  local rc=$?
  if (( KEEP )); then
    log "leaving run dir and procs: $RUNDIR"
  else
    [[ -n "$TSA_PID" ]] && kill -9 "$TSA_PID" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do
      [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
    done
    [[ $OVERALL_RC -eq 0 ]] && rm -rf "$RUNDIR"
  fi
  exit $rc
}
trap cleanup EXIT

# iface_in goes up to vcan(NODES); setup_vcan.sh sets MTU 72 (required for
# CAN FD) on every interface it creates, so provision through it rather than
# a manual "ip link add" fallback that would silently skip the MTU.
if ! ip link show "vcan$NODES" &>/dev/null; then
  "$REPO_ROOT/setup_vcan.sh" "$NODES" || fail "vcan setup failed"
fi
[[ -x "$PARTICIPANT_BIN" ]] || fail "participant not built: $PARTICIPANT_BIN"

log "Starting ${NODES}-node mesh (TSA @ $BASE_ID, clients .. $((BASE_ID+NODES-1)))"
"$PARTICIPANT_BIN" -i vcan0 -s vcan1 -p "$BASE_ID" -k "$KEYS_FILE" -t -l info \
  > "$RUNDIR/tsa.log" 2>&1 &
TSA_PID=$!

for i in $(seq 1 $((NODES - 1))); do
  pid=$((BASE_ID + i))
  iface_in="vcan$((i + 1))"
  "$PARTICIPANT_BIN" -i vcan0 -s "$iface_in" -p "$pid" -k "$KEYS_FILE" -l info \
    > "$RUNDIR/client_${pid}.log" 2>&1 &
  PIDS[$pid]=$!
done

log "Warmup 5s..."
sleep 5

log "Running ${DURATION}s..."
sleep "$DURATION"

# Count how many clients reached SECURE
secure=0
warning=0
waiting=0
for pid in "${!PIDS[@]}"; do
  log="$RUNDIR/client_${pid}.log"
  if grep -q -i "state.*SECURE" "$log" 2>/dev/null; then
    secure=$((secure + 1))
  elif grep -q -i "state.*WARNING" "$log" 2>/dev/null; then
    warning=$((warning + 1))
  else
    waiting=$((waiting + 1))
  fi
done
log "Final: SECURE=$secure WARNING=$warning WAITING/other=$waiting (of $((NODES - 1)) clients)"

# TSA must stay alive
if ! kill -0 "$TSA_PID" 2>/dev/null; then
  fail "TSA died during 20-node run"
fi

if (( OVERALL_RC == 0 )); then
  log "PASS: ${NODES}-node scaling test completed"
fi
exit $OVERALL_RC
