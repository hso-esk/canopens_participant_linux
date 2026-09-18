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

# End-to-end test for multi-participant GUI operations and provisioning.
# Usage: tests/run_e2e_gui.sh [--keep] [--log-level LEVEL] [--visible] [--keys FILE]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_DIR="$REPO_ROOT/canopens_configurator_python"
CONFIGURATOR_SRC="$CONFIGURATOR_DIR/src"
CONFIGURATOR_TESTS="$CONFIGURATOR_DIR/tests"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"

KEEP=0
LOG_LEVEL="info"
GUI_VISIBLE=0
PID1=120
PID2=121

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    --visible) GUI_VISIBLE=1; shift ;;
    --keys) KEYS_FILE="$(readlink -f "$2")"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--keep] [--log-level LEVEL] [--visible] [--keys FILE]"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

RUNDIR="$(mktemp -d /tmp/spsec_gui_e2e.XXXXXX)"
declare -A PIDS
CHECK_NAMES=(); CHECK_RESULTS=(); OVERALL_RC=0

log()  { echo "[gui_e2e] $*"; }
fail() { echo "[gui_e2e] FAIL: $*" >&2; OVERALL_RC=1; }
add_check() {
  CHECK_NAMES+=("$1"); CHECK_RESULTS+=("$2")
  [[ "$2" == "FAIL" ]] && OVERALL_RC=1
  return 0
}

cleanup() {
  local rc=$?
  if [[ $KEEP -eq 1 ]]; then
    log "leaving processes running ($RUNDIR); kill with: kill ${PIDS[*]:-}"
  else
    for pid in "${PIDS[@]:-}"; do
      [[ -z "$pid" ]] && continue
      kill "$pid" 2>/dev/null
      for _ in {1..20}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -9 "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    done
    [[ $OVERALL_RC -eq 0 ]] && rm -rf "$RUNDIR"
  fi
  exit "$rc"
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

# --- Preconditions ------------------------------------------------------------
if ! ip link show vcan0 &>/dev/null || ! ip link show vcan1 &>/dev/null \
   || ! ip link show vcan2 &>/dev/null; then
  log "vcan interfaces missing, running setup_vcan.sh (needs sudo)"
  "$REPO_ROOT/setup_vcan.sh" || { echo "[gui_e2e] vcan setup failed" >&2; exit 1; }
fi

[[ -x "$PARTICIPANT_BIN" ]] || { echo "[gui_e2e] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
[[ -f "$KEYS_FILE" ]] || { echo "[gui_e2e] Keys file not found: $KEYS_FILE" >&2; exit 1; }

python3 -c "import can, Crypto, tkinter" 2>/dev/null || {
  echo "[gui_e2e] Python configurator or tkinter dependencies missing" >&2; exit 1; }

XVFB_CMD=""
if [ -z "${DISPLAY:-}" ]; then
  if command -v xvfb-run &>/dev/null; then
    XVFB_CMD="xvfb-run -a "
  else
    echo "[gui_e2e] SKIP: No display available (DISPLAY unset and xvfb-run not installed)"
    exit 0
  fi
fi

stale_participants() {
  local target p
  target="$(readlink -f "$PARTICIPANT_BIN" 2>/dev/null)" || return 0
  [ -n "$target" ] || return 0
  for p in /proc/[0-9]*; do
    if [ "$(readlink -f "$p/exe" 2>/dev/null)" = "$target" ]; then
      echo "${p#/proc/} $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    fi
  done
}

if [ -n "$(stale_participants)" ]; then
  echo "[gui_e2e] stale participants running; pkill -f spsec_participant" >&2; exit 1
fi

export SPSEC_STORAGE_PATH="$RUNDIR/data"

# --- 1. Start participants ---------------------------------------------------
log "starting participants: PID $PID1 (TSA on vcan1) and PID $PID2 (client on vcan2)"
"$PARTICIPANT_BIN" -t -s vcan0 -i vcan1 -p "$PID1" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$PID1.log" 2>&1 &
PIDS[$PID1]=$!

"$PARTICIPANT_BIN" -s vcan0 -i vcan2 -p "$PID2" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$PID2.log" 2>&1 &
PIDS[$PID2]=$!

for pid in "$PID1" "$PID2"; do
  wait_for_log "$RUNDIR/p$pid.log" "Starting main loop" 10 \
    || fail "participant $pid did not start within 10s"
done
add_check "participants startup and main loop initialization" "$([[ $OVERALL_RC -eq 0 ]] && echo PASS || echo FAIL)"

# --- 2. Execute GUI Automated Test -------------------------------------------
log "executing live GUI test (discovery, provision, timesync, bidirectional data, reset)"
GUI_OUTPUT="$RUNDIR/gui_test.log"

PYTHONPATH="$CONFIGURATOR_SRC:$CONFIGURATOR_TESTS" \
SPSEC_LIVE_KEYS="$KEYS_FILE" \
SPSEC_LIVE_PIDS="$PID1,$PID2" \
SPSEC_LIVE_IFACE="vcan0" \
SPSEC_LIVE_RUNDIR="$RUNDIR" \
SPSEC_LIVE_INSEC_120="vcan1" \
SPSEC_LIVE_INSEC_121="vcan2" \
GUI_VISIBLE="$GUI_VISIBLE" \
$XVFB_CMD python3 -m unittest discover -s "$CONFIGURATOR_TESTS" -p "test_gui_e2e_live.py" -v \
  > "$GUI_OUTPUT" 2>&1
GUI_RC=$?

cat "$GUI_OUTPUT"

if [[ $GUI_RC -eq 0 ]]; then
  add_check "GUI discovery, provisioning, timesync, and data test" "PASS"
else
  fail "GUI test exited with status $GUI_RC"
  add_check "GUI discovery, provisioning, timesync, and data test" "FAIL"
fi

grep -q "Discovered devices in GUI: \[$PID1, $PID2\]" "$GUI_OUTPUT" \
  && add_check "GUI discovered both participants (PID $PID1 and $PID2)" "PASS" \
  || add_check "GUI discovered both participants (PID $PID1 and $PID2)" "FAIL"

grep -q "PID $PID1 provisioning completed successfully" "$GUI_OUTPUT" \
  && grep -q "PID $PID2 provisioning completed successfully" "$GUI_OUTPUT" \
  && add_check "GUI provisioned both participants via key ladder" "PASS" \
  || add_check "GUI provisioned both participants via key ladder" "FAIL"

grep -q "Time synchronization verified: both nodes transitioned to SECURE state" "$GUI_OUTPUT" \
  && add_check "participants established time synchronization (SECURE)" "PASS" \
  || add_check "participants established time synchronization (SECURE)" "FAIL"

grep -q "Bidirectional data plane verified successfully" "$GUI_OUTPUT" \
  && add_check "bidirectional data plane verified (vcan1 <-> vcan2)" "PASS" \
  || add_check "bidirectional data plane verified (vcan1 <-> vcan2)" "FAIL"

grep -q "PID $PID1 Factory Reset completed" "$GUI_OUTPUT" \
  && add_check "GUI disabled participant $PID1 via Factory Reset" "PASS" \
  || add_check "GUI disabled participant $PID1 via Factory Reset" "FAIL"

grep -q "Confirmed: Insecure traffic from disabled node is DROPPED" "$GUI_OUTPUT" \
  && add_check "post-disable data blocking verified (traffic dropped)" "PASS" \
  || add_check "post-disable data blocking verified (traffic dropped)" "FAIL"

# --- 3. Process Health and Teardown Check -------------------------------------
log "checking participant process health..."
ALIVE_OK=1
for pid in "$PID1" "$PID2"; do
  # Refresh PID if process was power-cycled during factory reset
  live_pid=$(pgrep -f "spsec_participant.*-p $pid" | head -n 1)
  [[ -n "$live_pid" ]] && PIDS[$pid]=$live_pid

  kill -0 "${PIDS[$pid]}" 2>/dev/null || { fail "participant $pid died unexpectedly"; ALIVE_OK=0; }
  if grep -q "DLL Address ID guard violation" "$RUNDIR/p$pid.log"; then
    fail "participant $pid logged a guard violation"
    ALIVE_OK=0
  fi
done
add_check "participants remained healthy (no crash or guard violation)" "$([[ $ALIVE_OK -eq 1 ]] && echo PASS || echo FAIL)"

log "disabling participants via graceful shutdown (SIGTERM)..."
SHUTDOWN_OK=1
for pid in "$PID1" "$PID2"; do
  kill -TERM "${PIDS[$pid]}" 2>/dev/null
  waited=0
  while kill -0 "${PIDS[$pid]}" 2>/dev/null && (( waited < 50 )); do
    sleep 0.1; waited=$((waited + 1))
  done
  if kill -0 "${PIDS[$pid]}" 2>/dev/null; then
    fail "participant $pid did not exit after SIGTERM"
    SHUTDOWN_OK=0
  fi
done
add_check "participants disabled/terminated cleanly on signal" "$([[ $SHUTDOWN_OK -eq 1 ]] && echo PASS || echo FAIL)"

echo
echo "===== run_e2e_gui.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-58s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
if [[ $OVERALL_RC -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$OVERALL_RC"
