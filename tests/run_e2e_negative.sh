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

# Fault injection and negative tests for tag corruption and unauthorized access.
# Usage: tests/run_e2e_negative.sh [--keep] [--log-level LEVEL]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_SRC="$REPO_ROOT/canopens_configurator_python/src"
CONFIGURATOR_TESTS="$REPO_ROOT/canopens_configurator_python/tests"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
TARGET_PID=120

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

RUNDIR="$(mktemp -d /tmp/spsec_negative.XXXXXX)"
PARTICIPANT_PID=""
OVERALL_RC=0

log()  { echo "[negative] $*"; }

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

if ! ip link show vcan0 &>/dev/null || ! ip link show vcan1 &>/dev/null; then
  log "vcan interfaces missing, running setup_vcan.sh (needs sudo)"
  "$REPO_ROOT/setup_vcan.sh" || { echo "[negative] vcan setup failed" >&2; exit 1; }
fi
[[ -x "$PARTICIPANT_BIN" ]] || { echo "[negative] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[negative] Python configurator deps missing" >&2; exit 1; }
# Match on /proc/PID/exe to avoid comm truncation false negatives.
stale_participants() {
  local target p exe
  target="$(readlink -f "$PARTICIPANT_BIN" 2>/dev/null)" || return 0
  [ -n "$target" ] || return 0
  for p in /proc/[0-9]*; do
    # Strip deleted suffix to detect stale processes holding old inodes.
    exe="$(readlink "$p/exe" 2>/dev/null)"
    exe="${exe% (deleted)}"
    if [ "$exe" = "$target" ]; then
      echo "${p#/proc/} $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    fi
  done
}

if [ -n "$(stale_participants)" ]; then
  echo "[negative] stale participants running; pkill -f spsec_participant" >&2; exit 1
fi

export SPSEC_STORAGE_PATH="$RUNDIR/data"

log "starting participant $TARGET_PID (RUNDIR=$RUNDIR)"
"$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p "$TARGET_PID" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$TARGET_PID.log" 2>&1 &
PARTICIPANT_PID=$!

wait_for_log "$RUNDIR/p$TARGET_PID.log" "Starting main loop" 10 || {
  echo "[negative] participant did not start" >&2; OVERALL_RC=1; exit 1; }

log "running fault-injection suite"
cd "$REPO_ROOT/canopens_configurator_python"
SPSEC_LIVE_PID="$TARGET_PID" \
SPSEC_LIVE_IFACE=vcan0 \
SPSEC_LIVE_KEYS="$KEYS_FILE" \
PYTHONPATH="$CONFIGURATOR_SRC" \
  timeout 300 python3 -m unittest discover -s "$CONFIGURATOR_TESTS" \
    -p "test_negative_live.py" -v 2>&1 | tee "$RUNDIR/negative.log"
rc=${PIPESTATUS[0]}

# A skipped suite means the env wiring broke - that must not read as success.
if grep -q "no live participant" "$RUNDIR/negative.log"; then
  echo "[negative] FAIL: suite skipped itself; live-participant env not picked up" >&2
  OVERALL_RC=1
elif [[ $rc -ne 0 ]]; then
  echo "[negative] FAIL: fault-injection suite reported failures" >&2
  OVERALL_RC=1
fi

if ! kill -0 "$PARTICIPANT_PID" 2>/dev/null; then
  echo "[negative] FAIL: participant died under fault injection" >&2
  OVERALL_RC=1
fi

echo
echo "RUNDIR: $RUNDIR"
if [[ $OVERALL_RC -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $OVERALL_RC
