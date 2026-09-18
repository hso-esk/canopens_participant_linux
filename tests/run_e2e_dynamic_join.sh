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

# Dynamic node onboarding under active traffic without packet loss.
# Usage: tests/run_e2e_dynamic_join.sh [--keep] [--log-level LEVEL]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_SRC="$REPO_ROOT/canopens_configurator_python/src"
CONFIGURATOR_CLI="$REPO_ROOT/canopens_configurator_python/spsec_cli.py"
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

RUNDIR="$(mktemp -d /tmp/spsec_dynjoin.XXXXXX)"
declare -A PIDS
OVERALL_RC=0
CHECK_NAMES=()
CHECK_RESULTS=()

log() { echo "[dyn_join] $*"; }

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
    "$REPO_ROOT/setup_vcan.sh" || { echo "[dyn_join] vcan setup failed" >&2; exit 1; }
    break
  fi
done
[[ -x "$PARTICIPANT_BIN" ]] || { echo "[dyn_join] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[dyn_join] Python configurator deps missing" >&2; exit 1; }

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

# --- 1. Start Initial Participants (120 TSA & 121 Client) ---------------------
log "starting participants PID $PID1 (TSA) and PID $PID2 (Client)"
start_participant "$PID1" vcan1 "-t"
start_participant "$PID2" vcan2 ""

for pid in "$PID1" "$PID2"; do
  wait_for_log "$RUNDIR/p$pid.log" "Starting main loop" 10 || {
    echo "[dyn_join] participant $pid did not start" >&2; OVERALL_RC=1; exit 1; }
done

add_check "initial participants startup (120 & 121)" PASS

cli() {
  PYTHONPATH="$CONFIGURATOR_SRC" timeout 45 python3 -m spsec_configurator.cli.group_cli \
    -i vcan0 -k "$KEYS_FILE" "$@"
}

# --- 2. Provision Initial Nodes 120 & 121 -------------------------------------
log "provisioning initial nodes via key ladder..."
cli provision-discovered --start-pid "$PID1" --end-pid "$PID2" > "$RUNDIR/provision_init.log" 2>&1
grep -q "2/2 device(s) provisioned" "$RUNDIR/provision_init.log" \
  && add_check "initial key ladder provisioning (PIDs 120 & 121)" PASS \
  || add_check "initial key ladder provisioning (PIDs 120 & 121)" FAIL

# Wait for initial time synchronization between 120 and 121
log "waiting for timesync between initial nodes..."
wait_for_log "$RUNDIR/p$PID2.log" "Time synchronized, set SECURE state" 15 \
  && add_check "initial nodes reached SECURE state" PASS \
  || add_check "initial nodes reached SECURE state" FAIL

sleep 2.0

# --- 3. Start Continuous Background Traffic Flow (vcan1 -> vcan2) -------------
RX_SCRIPT="$SCRIPT_DIR/receive_can_data.py"
TX_SCRIPT="$SCRIPT_DIR/send_canopen_data.py"
STREAM_COUNT=16
STREAM_OUT="$RUNDIR/stream_rx.txt"

log "starting background receiver on vcan2 (expecting $STREAM_COUNT frames)..."
python3 "$RX_SCRIPT" --channel vcan2 --count "$STREAM_COUNT" --timeout 15 --out "$STREAM_OUT" --standard-only &
RX_PROC=$!
sleep 0.5

log "spawning continuous traffic generator on vcan1 (gap=0.35s across ~6s)..."
python3 "$TX_SCRIPT" --channel vcan1 --node-id "0x01" --repeat 2 --gap 0.35 &
TX_PROC=$!

# Let streaming establish for ~0.8s
sleep 0.8

# --- 4. Dynamic Addition of Node 122 Under Active Load ------------------------
log "LAUNCHING Node $PID3 during active traffic..."
start_participant "$PID3" vcan3 ""
wait_for_log "$RUNDIR/p$PID3.log" "Starting main loop" 10 || {
  echo "[dyn_join] participant $PID3 did not start" >&2; OVERALL_RC=1; exit 1; }

log "executing dynamic onboarding for Node $PID3 over vcan0..."
cli provision-discovered --start-pid "$PID3" --end-pid "$PID3" > "$RUNDIR/provision_dyn.log" 2>&1
grep -q "1/1 device(s) provisioned" "$RUNDIR/provision_dyn.log" \
  && add_check "dynamically provisioned Node 122 during active traffic" PASS \
  || add_check "dynamically provisioned Node 122 during active traffic" FAIL

# Wait for Node 122 to establish time synchronization
wait_for_log "$RUNDIR/p$PID3.log" "Time synchronized, set SECURE state" 15 \
  && add_check "dynamically joined Node 122 reached SECURE state" PASS \
  || add_check "dynamically joined Node 122 reached SECURE state" FAIL

# Wait for continuous background traffic stream to complete
wait "$TX_PROC" 2>/dev/null || true
wait "$RX_PROC" 2>/dev/null || true

# --- 5. Verify Zero Frame Loss on Background Stream ---------------------
RECV_COUNT=0
if [[ -f "$STREAM_OUT" ]]; then
  RECV_COUNT=$(grep -c "^[0-9a-fA-F]" "$STREAM_OUT" || true)
fi
log "stream completed: sent $STREAM_COUNT frames, received $RECV_COUNT frames on vcan2"
[[ "$RECV_COUNT" -eq "$STREAM_COUNT" ]] \
  && add_check "zero packet loss between 120 and 121 during join ($RECV_COUNT/$STREAM_COUNT)" PASS \
  || add_check "zero packet loss between 120 and 121 during join ($RECV_COUNT/$STREAM_COUNT)" FAIL

# --- 6. Verify Node 122 CAN Send Secure Traffic to Group ----------------------
log "verifying Node 122 can bridge secure traffic to Node 120 (vcan3 -> vcan1)..."
NODE3_RX="$RUNDIR/node3_rx.txt"
python3 "$RX_SCRIPT" --channel vcan1 --count 8 --timeout 5 --out "$NODE3_RX" --standard-only &
RX3_PROC=$!
sleep 0.5
python3 "$TX_SCRIPT" --channel vcan3 --node-id "0x03" --repeat 1 --gap 0.05
wait "$RX3_PROC" 2>/dev/null || true

N3_RECV=0
if [[ -f "$NODE3_RX" ]]; then
  N3_RECV=$(grep -c "^[0-9a-fA-F]" "$NODE3_RX" || true)
fi
log "Node 122 traffic test: received $N3_RECV frames on vcan1"
[[ "$N3_RECV" -ge 1 ]] \
  && add_check "Node 122 successfully communicates with group (vcan3 -> vcan1)" PASS \
  || add_check "Node 122 successfully communicates with group (vcan3 -> vcan1)" FAIL

# --- 7. Check Process Health --------------------------------------------------
HEALTH_OK=1
for pid in "$PID1" "$PID2" "$PID3"; do
  kill -0 "${PIDS[$pid]}" 2>/dev/null || { HEALTH_OK=0; log "participant $pid died unexpectedly"; }
  if grep -q "DLL Address ID guard violation" "$RUNDIR/p$pid.log"; then
    HEALTH_OK=0; log "participant $pid logged guard violation";
  fi
done
[[ $HEALTH_OK -eq 1 ]] \
  && add_check "all 3 participants remained healthy with zero guard violations" PASS \
  || add_check "all 3 participants remained healthy with zero guard violations" FAIL

echo
echo "===== run_e2e_dynamic_join.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-60s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
[[ $OVERALL_RC -eq 0 ]] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit $OVERALL_RC
