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

# Interactive step-by-step multi-participant GUI demonstration.
# Usage: tests/run_interactive_gui.sh [--auto] [--keep] [--log-level LEVEL] [--keys FILE]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_DIR="$REPO_ROOT/canopens_configurator_python"
CONFIGURATOR_SRC="$CONFIGURATOR_DIR/src"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"

KEEP=0
AUTO_FLAG=""
LOG_LEVEL="info"
PID1=120
PID2=121

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto) AUTO_FLAG="--auto"; shift ;;
    --keep) KEEP=1; shift ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    --keys) KEYS_FILE="$(readlink -f "$2")"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--auto] [--keep] [--log-level LEVEL] [--keys FILE]"
      echo ""
      echo "Options:"
      echo "  --auto            Start with auto-advance enabled (3s delay between stages)"
      echo "  --keep            Keep participant processes running after GUI exits"
      echo "  --log-level LVL   Participant logging level (debug, info, warn, error)"
      echo "  --keys FILE       Path to keys file (default: example_keys_short_salt.txt)"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

RUNDIR="$(mktemp -d /tmp/spsec_interactive_gui.XXXXXX)"
declare -A PIDS

log()  { echo "[interactive_gui] $*"; }
fail() { echo "[interactive_gui] FAIL: $*" >&2; exit 1; }

cleanup() {
  local rc=$?
  if [[ $KEEP -eq 1 ]]; then
    log "leaving participants running ($RUNDIR); kill manually with: kill ${PIDS[*]:-}"
  else
    log "stopping participants gracefully (SIGTERM)..."
    for pid in "$PID1" "$PID2"; do
      live_pid=$(pgrep -f "spsec_participant.*-p $pid" | head -n 1)
      [[ -n "$live_pid" ]] && PIDS[$pid]=$live_pid
    done

    for pid in "${PIDS[@]:-}"; do
      [[ -z "$pid" ]] && continue
      kill "$pid" 2>/dev/null
      for _ in {1..20}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -9 "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    done
    rm -rf "$RUNDIR"
    log "cleanup complete."
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
  "$REPO_ROOT/setup_vcan.sh" || fail "vcan setup failed"
fi

[[ -x "$PARTICIPANT_BIN" ]] || fail "$PARTICIPANT_BIN not found; build first (e.g. cd build && make)"
[[ -f "$KEYS_FILE" ]] || fail "Keys file not found: $KEYS_FILE"

python3 -c "import can, Crypto, tkinter" 2>/dev/null || {
  fail "Python dependencies (python-can, pycryptodome, tkinter) missing"
}

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
  log "stale participants detected; cleaning up before launch..."
  pkill -f spsec_participant 2>/dev/null || true
  sleep 0.5
fi

export SPSEC_STORAGE_PATH="$RUNDIR/data"

# --- 1. Start Participants ---------------------------------------------------
log "starting participants PID $PID1 (TSA on vcan1) and PID $PID2 (client on vcan2)"
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
log "participants PID $PID1 and PID $PID2 are running on vcan0."

# --- 2. Launch Interactive GUI -----------------------------------------------
export DISPLAY="${DISPLAY:-:1}"
log "opening interactive GUI on DISPLAY=$DISPLAY..."

PYTHONPATH="$CONFIGURATOR_SRC" python3 -m spsec_configurator.gui.interactive_runner \
  --interface vcan0 \
  --keys "$KEYS_FILE" \
  --pids "$PID1,$PID2" \
  --rundir "$RUNDIR" \
  --insec-120 vcan1 \
  --insec-121 vcan2 \
  $AUTO_FLAG

GUI_RC=$?
log "GUI session ended with code $GUI_RC."
exit "$GUI_RC"
