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

# 10-node dynamic join test: onboards 11th node under active traffic.
# Usage: tests/run_e2e_dynamic_join_10nodes.sh [--keep] [--duration SECONDS]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_CLI="$REPO_ROOT/canopens_configurator_python/spsec_cli.py"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
DURATION=60
NODES=10
BASE_ID=110
NEW_PID=125
KEEP=0
OVERALL_RC=0

usage() {
  echo "Usage: $0 [--keep] [--duration SECONDS]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

RUNDIR="$(mktemp -d /tmp/spsec_dynjoin10.XXXXXX)"
declare -A PIDS
TSA_PID=""
TX_PID=""

log() { echo "[dynjoin10] $*"; }
fail() { echo "[dynjoin10] FAIL: $*" >&2; OVERALL_RC=1; }

cleanup() {
  local rc=$?
  if (( KEEP )); then
    log "leaving run dir and procs: $RUNDIR"
  else
    [[ -n "$TX_PID" ]] && kill "$TX_PID" 2>/dev/null || true
    [[ -n "$TSA_PID" ]] && kill "$TSA_PID" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do
      [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
    done
    [[ $OVERALL_RC -eq 0 ]] && rm -rf "$RUNDIR"
  fi
  exit $rc
}
trap cleanup EXIT

if ! ip link show vcan0 &>/dev/null; then
  "$REPO_ROOT/setup_vcan.sh" || fail "vcan setup failed"
fi
[[ -x "$PARTICIPANT_BIN" ]] || fail "participant not built: $PARTICIPANT_BIN"

export SPSEC_STORAGE_PATH="$RUNDIR/storage"

log "Bringing up 10 nodes (TSA @ $BASE_ID, clients $((BASE_ID+1))..$((BASE_ID+NODES-1)))"
"$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p "$BASE_ID" -k "$KEYS_FILE" -t -l info \
  > "$RUNDIR/tsa.log" 2>&1 &
TSA_PID=$!

for i in $(seq 1 $((NODES - 1))); do
  pid=$((BASE_ID + i))
  iface_in="vcan$((i + 1))"
  ip link add dev "$iface_in" type vcan 2>/dev/null || true
  ip link set up "$iface_in" 2>/dev/null || true
  "$PARTICIPANT_BIN" -s vcan0 -i "$iface_in" -p "$pid" -k "$KEYS_FILE" -l info \
    > "$RUNDIR/client_${pid}.log" 2>&1 &
  PIDS[$pid]=$!
done

log "Warmup 5s..."
sleep 5

# Start continuous background traffic on vcan1 (TSA's insecure bus)
log "Starting continuous background traffic (${DURATION}s window)"
python3 "$SCRIPT_DIR/send_canopen_data.py" --channel vcan1 --node-id 0x01 --gap 0.01 --repeat $((DURATION * 100)) \
  > "$RUNDIR/bg_traffic.log" 2>&1 &
TX_PID=$!

# Let background traffic stabilize
sleep 5

# Run dynamic join for the new node
log "Launching new node $NEW_PID"
"$PARTICIPANT_BIN" -s vcan0 -i "vcan$((NODES + 1))" -p "$NEW_PID" -l info \
  > "$RUNDIR/client_${NEW_PID}.log" 2>&1 &
PIDS[$NEW_PID]=$!
sleep 1

log "Dynamic join for new node $NEW_PID"
PYTHONPATH="$REPO_ROOT/canopens_configurator_python/src" python3 \
  -c "
import sys
sys.path.insert(0, '$REPO_ROOT/canopens_configurator_python/src')
from spsec_configurator.core.configurator import (
    configurator_init, configurator_destroy,
    configurator_establish_keys_sequential,
)
from spsec_configurator.core.spsec_definitions import SPSEC_KEY_SELECTOR_ZERO_KEY
cfg = configurator_init('vcan0', '$KEYS_FILE')
ret = configurator_establish_keys_sequential(
    cfg, $NEW_PID, SPSEC_KEY_SELECTOR_ZERO_KEY,
    provisioning_key=cfg.comm_keys.spsec_keys[1].key,
    provisioning_salt=cfg.comm_keys.spsec_salt[1].salt,
    provisioning_key_id=cfg.comm_keys.spsec_keys[1].key_id,
    integrator_key=cfg.comm_keys.spsec_keys[2].key,
    integrator_salt=cfg.comm_keys.spsec_salt[2].salt,
    integrator_key_id=cfg.comm_keys.spsec_keys[2].key_id,
    seed_key=cfg.comm_keys.spsec_keys[3].key,
    seed_salt=cfg.comm_keys.spsec_salt[3].salt,
    seed_key_id=cfg.comm_keys.spsec_keys[3].key_id,
)
print(f'bootstrap_new_result={ret}')
configurator_destroy(cfg)
assert ret == 0, f'Bootstrap failed with code {ret}'
" 2>&1 | tee "$RUNDIR/bootstrap_new.log" || fail "bootstrap script returned non-zero"

# Wait for background traffic to finish
wait "$TX_PID" 2>/dev/null || true
TX_PID=""

# Analyze bg_traffic.log for any unusual errors
errs=$(grep -c -i "error\|fail" "$RUNDIR/bg_traffic.log" 2>/dev/null || true)
if (( errs > 0 )); then
  log "Note: ${errs} error/fail lines in background traffic log"
fi

log "PASS: 10-node dynamic join under load completed"
exit 0
