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

# Full Factory Reset Roundtrip Test
#
# Verifies that sending the factory reset magic to register 0x7F erases
# operational keys across power cycles while preserving the Provisioning Key.
#
# Usage: tests/run_e2e_factory_reset.sh [--keep] [--log-level LEVEL]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_SRC="$REPO_ROOT/canopens_configurator_python/src"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
TARGET_PID=122

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

RUNDIR="$(mktemp -d /tmp/spsec_reset_e2e.XXXXXX)"
PARTICIPANT_PID=""
OVERALL_RC=0
CHECK_NAMES=()
CHECK_RESULTS=()

log() { echo "[factory_reset_e2e] $*"; }

add_check() {
  CHECK_NAMES+=("$1")
  CHECK_RESULTS+=("$2")
  [[ "$2" == "FAIL" ]] && OVERALL_RC=1
  return 0
}

cleanup() {
  local rc=$?
  if [[ $KEEP -eq 1 ]]; then
    log "leaving participant running ($RUNDIR); kill with: kill $PARTICIPANT_PID"
  else
    if [[ -n "$PARTICIPANT_PID" ]]; then
      kill "$PARTICIPANT_PID" 2>/dev/null
      for _ in {1..20}; do kill -0 "$PARTICIPANT_PID" 2>/dev/null || break; sleep 0.1; done
      kill -9 "$PARTICIPANT_PID" 2>/dev/null
      wait "$PARTICIPANT_PID" 2>/dev/null
    fi
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

if ! ip link show vcan0 &>/dev/null || ! ip link show vcan2 &>/dev/null; then
  log "vcan interfaces missing, running setup_vcan.sh (needs sudo)"
  "$REPO_ROOT/setup_vcan.sh" || { echo "[factory_reset_e2e] vcan setup failed" >&2; exit 1; }
fi
[[ -x "$PARTICIPANT_BIN" ]] || { echo "[factory_reset_e2e] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[factory_reset_e2e] Python configurator deps missing" >&2; exit 1; }

export SPSEC_STORAGE_PATH="$RUNDIR/data"

# --- 1. Start Participant ----------------------------------------------------
log "starting participant PID $TARGET_PID (RUNDIR=$RUNDIR)"
"$PARTICIPANT_BIN" -s vcan0 -i vcan2 -p "$TARGET_PID" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$TARGET_PID.log" 2>&1 &
PARTICIPANT_PID=$!
wait_for_log "$RUNDIR/p$TARGET_PID.log" "Starting main loop" 10 || {
  echo "[factory_reset_e2e] participant did not start" >&2; OVERALL_RC=1; exit 1; }

add_check "participant initial startup" PASS

cli() {
  local keys="$1"; shift
  PYTHONPATH="$CONFIGURATOR_SRC" timeout 30 python3 -m spsec_configurator.cli.group_cli \
    -i vcan0 -k "$keys" "$@" 2>/dev/null
}

# --- 2. Initial Bootstrapping ------------------------------------------------
log "provisioning PID $TARGET_PID through key ladder"
cli "$KEYS_FILE" provision-discovered \
  --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" > "$RUNDIR/provision.log"
grep -q "1/1 device(s) provisioned" "$RUNDIR/provision.log" \
  && add_check "initial key ladder provisioning (Zero -> Prov -> Int -> Seed)" PASS \
  || add_check "initial key ladder provisioning (Zero -> Prov -> Int -> Seed)" FAIL

# Verify Integrator Key session works
int_count="$(cli "$KEYS_FILE" discover --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" --key integrator \
  | sed -n 's/^Discovered \([0-9]\+\) device.*/\1/p' | head -1)"
[[ "$int_count" == "1" ]] \
  && add_check "Integrator Key session verified before reset" PASS \
  || add_check "Integrator Key session verified before reset" FAIL

# --- 3. Execute Factory Reset over Integrator Session -------------------------
log "executing factory reset (reg 0x7F write via Integrator session)"
cli "$KEYS_FILE" factory-reset "$TARGET_PID" > "$RUNDIR/reset.log"
grep -q "Successfully reset PID $TARGET_PID" "$RUNDIR/reset.log" \
  && add_check "factory reset command executed with success code 0" PASS \
  || add_check "factory reset command executed with success code 0" FAIL

# Verify storage contains the manufacturer reset flag
FLAG_FILE="$(ls "${SPSEC_STORAGE_PATH}_${TARGET_PID}/config/manufacturer_reset"* 2>/dev/null | head -n 1)"
[[ -n "$FLAG_FILE" && -f "$FLAG_FILE" ]] \
  && add_check "manufacturer_reset persistence flag written to storage" PASS \
  || add_check "manufacturer_reset persistence flag written to storage" FAIL

# --- 4. Simulate Power Cycle -------------------------------------------------
log "simulating power-cycle for PID $TARGET_PID..."
kill "$PARTICIPANT_PID" 2>/dev/null
for _ in {1..20}; do kill -0 "$PARTICIPANT_PID" 2>/dev/null || break; sleep 0.1; done
kill -9 "$PARTICIPANT_PID" 2>/dev/null
wait "$PARTICIPANT_PID" 2>/dev/null

# Relaunch participant using SAME non-volatile storage
"$PARTICIPANT_BIN" -s vcan0 -i vcan2 -p "$TARGET_PID" -l "$LOG_LEVEL" \
  > "$RUNDIR/p${TARGET_PID}_restarted.log" 2>&1 &
PARTICIPANT_PID=$!
wait_for_log "$RUNDIR/p${TARGET_PID}_restarted.log" "Starting main loop" 10 || {
  echo "[factory_reset_e2e] restarted participant did not start" >&2; OVERALL_RC=1; exit 1; }

# Confirm reset applied during boot
grep -q "Manufacturer reset applied - keys erased from storage" "$RUNDIR/p${TARGET_PID}_restarted.log" \
  && add_check "participant power-cycle erased Integrator & Seed keys" PASS \
  || add_check "participant power-cycle erased Integrator & Seed keys" FAIL

# --- 5. Verify Post-Reset Key States -----------------------------------------
log "verifying Integrator Key session fails (keys wiped)..."
int_after="$(cli "$KEYS_FILE" discover --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" --key integrator \
  | sed -n 's/^Discovered \([0-9]\+\) device.*/\1/p' | head -1)"
[[ "$int_after" == "0" || -z "$int_after" ]] \
  && add_check "Integrator Key session refused after factory reset" PASS \
  || add_check "Integrator Key session refused after factory reset" FAIL

log "verifying Provisioning Key session succeeds (recovery anchor preserved)..."
prov_after="$(cli "$KEYS_FILE" discover --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" --key provisioning \
  | sed -n 's/^Discovered \([0-9]\+\) device.*/\1/p' | head -1)"
[[ "$prov_after" == "1" ]] \
  && add_check "Provisioning Key session opens successfully after reset" PASS \
  || add_check "Provisioning Key session opens successfully after reset" FAIL

# --- 6. Re-bootstrap Device --------------------------------------------------
log "re-bootstrapping PID $TARGET_PID through key ladder..."
cli "$KEYS_FILE" bootstrap "$TARGET_PID" > "$RUNDIR/reprovision.log"
grep -qi "bootstrap.*success\|successfully bootstrap" "$RUNDIR/reprovision.log" || grep -q "0" <<< "$?" \
  && add_check "re-bootstrapping device with fresh ladder succeeds" PASS \
  || add_check "re-bootstrapping device with fresh ladder succeeds" FAIL

# Verify re-provisioned device now has active Integrator key again
int_recovered="$(cli "$KEYS_FILE" discover --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" --key integrator \
  | sed -n 's/^Discovered \([0-9]\+\) device.*/\1/p' | head -1)"
[[ "$int_recovered" == "1" ]] \
  && add_check "device restored to fully operational state" PASS \
  || add_check "device restored to fully operational state" FAIL

# Check no DLL guard violations
! grep -q "DLL Address ID guard violation" "$RUNDIR/p${TARGET_PID}_restarted.log" \
  && add_check "no DLL Address ID guard violations" PASS \
  || add_check "no DLL Address ID guard violations" FAIL

echo
echo "===== run_e2e_factory_reset.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-58s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
[[ $OVERALL_RC -eq 0 ]] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit $OVERALL_RC
