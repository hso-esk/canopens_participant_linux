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

# Dynamic node removal test: verifies key rotation on remaining nodes.
# Usage: tests/run_e2e_dynamic_leave.sh [--keep] [--log-level LEVEL]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_SRC="$REPO_ROOT/canopens_configurator_python/src"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
PID1=120
PID2=121
PID3=122

KEEP=0
LOG_LEVEL="info"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 [--keep] [--log-level LEVEL]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

RUNDIR="$(mktemp -d /tmp/spsec_dynleave.XXXXXX)"
declare -A PIDS
OVERALL_RC=0
CHECK_NAMES=()
CHECK_RESULTS=()

log() { echo "[dyn_leave] $*"; }

add_check() {
  CHECK_NAMES+=("$1")
  CHECK_RESULTS+=("$2")
  [[ "$2" == "FAIL" ]] && OVERALL_RC=1
  return 0
}

cleanup() {
  local rc=$?
  if [[ $KEEP -eq 1 ]]; then
    log "leaving participants running ($RUNDIR); kill with: kill ${PIDS[*]:-}"
  else
    log "stopping participants gracefully (SIGTERM)..."
    for p in "${PIDS[@]:-}"; do
      [[ -z "$p" ]] && continue
      kill "$p" 2>/dev/null
    done
    for _ in {1..20}; do
      local any=0
      for p in "${PIDS[@]:-}"; do
        [[ -z "$p" ]] && continue
        kill -0 "$p" 2>/dev/null && any=1
      done
      [[ $any -eq 0 ]] && break
      sleep 0.1
    done
    for p in "${PIDS[@]:-}"; do
      [[ -z "$p" ]] && continue
      kill -9 "$p" 2>/dev/null
    done
    [[ $OVERALL_RC -eq 0 ]] && rm -rf "$RUNDIR"
  fi
  exit $rc
}
trap cleanup EXIT

wait_for_log() {
  local logfile="$1" pattern="$2" timeout="$3" waited=0
  while (( waited < timeout * 10 )); do
    grep -q "$pattern" "$logfile" 2>/dev/null && return 0
    sleep 0.1; waited=$((waited + 1))
  done
  return 1
}

for iface in vcan0 vcan1 vcan2 vcan3; do
  if ! ip link show "$iface" &>/dev/null; then
    log "$iface missing, running setup_vcan.sh (needs sudo)"
    "$REPO_ROOT/setup_vcan.sh" || { echo "[dyn_leave] vcan setup failed" >&2; exit 1; }
    break
  fi
done
[[ -x "$PARTICIPANT_BIN" ]] || { echo "[dyn_leave] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[dyn_leave] Python configurator deps missing" >&2; exit 1; }

start_participant() {
  local pid="$1" insec_if="$2" extra_args="$3"
  mkdir -p "$RUNDIR/data_$pid"
  (
    export SPSEC_STORAGE_PATH="$RUNDIR/data_$pid"
    exec "$PARTICIPANT_BIN" $extra_args -w 3000 -s vcan0 -i "$insec_if" -p "$pid" -l "$LOG_LEVEL" \
      > "$RUNDIR/p$pid.log" 2>&1
  ) &
  PIDS[$pid]=$!
}

# --- 1. Start Participants 120, 121, 122 -------------------------------------
log "starting participants PID $PID1 (TSA on vcan1), PID $PID2 (vcan2), PID $PID3 (vcan3)"
start_participant "$PID1" vcan1 "-t"
start_participant "$PID2" vcan2 ""
start_participant "$PID3" vcan3 ""

for pid in "$PID1" "$PID2" "$PID3"; do
  wait_for_log "$RUNDIR/p$pid.log" "Starting main loop" 10 || {
    echo "[dyn_leave] participant $pid did not start" >&2; OVERALL_RC=1; exit 1; }
done

add_check "all 3 participants startup" PASS

cli() {
  PYTHONPATH="$CONFIGURATOR_SRC" timeout 45 python3 -m spsec_configurator.cli.group_cli \
    -i vcan0 -k "$KEYS_FILE" -c "$RUNDIR/groups.json" "$@"
}

# --- 2. Create Group 1 and Provision 120, 121, 122 ---------------------------
log "creating Group 1 and onboarding nodes 120, 121, 122..."
cli provision-discovered --start-pid "$PID1" --end-pid "$PID3" > "$RUNDIR/provision_init.log" 2>&1
grep -q "3/3 device(s) provisioned" "$RUNDIR/provision_init.log" \
  && add_check "provisioned 3-node group via key ladder" PASS \
  || add_check "provisioned 3-node group via key ladder" FAIL

cli create-group 1 "LeaveCluster" -d "Dynamic leave test group" > /dev/null 2>&1
cli add-device 1 "$PID1" > /dev/null 2>&1
cli add-device 1 "$PID2" > /dev/null 2>&1
cli add-device 1 "$PID3" > /dev/null 2>&1

log "waiting for all nodes to achieve time synchronization..."
wait_for_log "$RUNDIR/p$PID2.log" "Time synchronized, set SECURE state" 15 \
  && wait_for_log "$RUNDIR/p$PID3.log" "Time synchronized, set SECURE state" 15 \
  && add_check "all 3 nodes achieved SECURE state" PASS \
  || add_check "all 3 nodes achieved SECURE state" FAIL

sleep 2.0

# --- 3. Verify Initial Group Communication -----------------------------------
RX_SCRIPT="$SCRIPT_DIR/receive_can_data.py"
TX_SCRIPT="$SCRIPT_DIR/send_canopen_data.py"

log "testing initial Node 122 -> Node 120 data flow (vcan3 -> vcan1)..."
INIT_RX="$RUNDIR/init_rx.txt"
python3 "$RX_SCRIPT" --channel vcan1 --count 8 --timeout 5 --out "$INIT_RX" --standard-only &
RX_PROC=$!
sleep 0.4
python3 "$TX_SCRIPT" --channel vcan3 --node-id "0x03" --gap 0.05
wait "$RX_PROC" 2>/dev/null || true

INIT_COUNT=0
if [[ -f "$INIT_RX" ]]; then
  INIT_COUNT=$(grep -c "^[0-9a-fA-F]" "$INIT_RX" || true)
fi
log "initial traffic test: received $INIT_COUNT frames on vcan1"
[[ "$INIT_COUNT" -ge 1 ]] \
  && add_check "initial data plane communication verified across group" PASS \
  || add_check "initial data plane communication verified across group" FAIL

# --- 4. Dynamic Removal of Node 122 ------------------------------------------
log "executing dynamic node removal: removing Node $PID3 from Group 1 with rekey and reset..."
cli remove-device 1 "$PID3" --rekey -r > "$RUNDIR/remove.log" 2>&1
grep -qi "removed\|success" "$RUNDIR/remove.log" \
  && add_check "dynamic remove-device 1 122 completed successfully" PASS \
  || add_check "dynamic remove-device 1 122 completed successfully" FAIL

# Allow key rotation to settle across survivors
sleep 2.0

# --- 5. Verify Survivor Communication (vcan1 <-> vcan2) -----------------------
log "verifying survivor nodes (120 and 121) communicate with rotated key..."
SURV_RX="$RUNDIR/surv_rx.txt"
python3 "$RX_SCRIPT" --channel vcan2 --count 8 --timeout 5 --out "$SURV_RX" --standard-only &
RX_SURV_PROC=$!
sleep 0.4
python3 "$TX_SCRIPT" --channel vcan1 --node-id "0x01" --gap 0.05
wait "$RX_SURV_PROC" 2>/dev/null || true

SURV_COUNT=0
if [[ -f "$SURV_RX" ]]; then
  SURV_COUNT=$(grep -c "^[0-9a-fA-F]" "$SURV_RX" || true)
fi
log "survivor traffic test: received $SURV_COUNT frames on vcan2"
[[ "$SURV_COUNT" -ge 1 ]] \
  && add_check "survivors communicate securely under rotated key (120 -> 121)" PASS \
  || add_check "survivors communicate securely under rotated key (120 -> 121)" FAIL

# --- 6. Verify Revoked Node 122 Traffic is Blocked ---------------------------
log "verifying Node $PID3 traffic is DROPPED by survivors (vcan3 -> vcan1)..."
BLOCKED_RX="$RUNDIR/blocked_rx.txt"
python3 "$RX_SCRIPT" --channel vcan1 --count 8 --timeout 2.0 --out "$BLOCKED_RX" --standard-only &
RX_BLOCKED_PROC=$!
sleep 0.4
python3 "$TX_SCRIPT" --channel vcan3 --node-id "0x03" --gap 0.05
wait "$RX_BLOCKED_PROC" 2>/dev/null || true

BLOCKED_COUNT=0
if [[ -f "$BLOCKED_RX" ]]; then
  BLOCKED_COUNT=$(grep -c "^[0-9a-fA-F]" "$BLOCKED_RX" || true)
fi
log "revoked node traffic test: captured $BLOCKED_COUNT frames on vcan1 (expected 0)"
[[ "$BLOCKED_COUNT" -eq 0 ]] \
  && add_check "traffic from revoked Node 122 is DROPPED by group" PASS \
  || add_check "traffic from revoked Node 122 is DROPPED by group" FAIL

# --- 7. Check Process Health --------------------------------------------------
HEALTH_OK=1
for pid in "$PID1" "$PID2" "$PID3"; do
  kill -0 "${PIDS[$pid]}" 2>/dev/null || { HEALTH_OK=0; log "participant $pid died unexpectedly"; }
  if grep -q "DLL Address ID guard violation" "$RUNDIR/p$pid.log"; then
    HEALTH_OK=0; log "participant $pid logged guard violation";
  fi
done
[[ $HEALTH_OK -eq 1 ]] \
  && add_check "participants remained healthy with zero guard violations" PASS \
  || add_check "participants remained healthy with zero guard violations" FAIL

echo
echo "===== run_e2e_dynamic_leave.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-60s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
[[ $OVERALL_RC -eq 0 ]] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit $OVERALL_RC
