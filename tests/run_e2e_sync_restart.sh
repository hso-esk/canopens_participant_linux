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

# End-to-end test for Sync-role restart recovery.
# Usage: tests/run_e2e_sync_restart.sh [--keep] [--log-level LEVEL]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_CLI="$REPO_ROOT/canopens_configurator_python/spsec_cli.py"

KEEP=0
LOG_LEVEL="info"
PARTICIPANT_KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"

# Shorten the Sync-restart detection window so the test does not have to wait
# out the 15 s production default.
SYNC_WAIT_MS=3000

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 [--keep] [--log-level LEVEL]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

RUNDIR="$(mktemp -d /tmp/spsec_sync_restart.XXXXXX)"
declare -A PIDS
CHECK_NAMES=()
CHECK_RESULTS=()
OVERALL_RC=0

log()  { echo "[sync_restart] $*"; }
fail() { echo "[sync_restart] FAIL: $*" >&2; OVERALL_RC=1; }

add_check() {
  CHECK_NAMES+=("$1")
  CHECK_RESULTS+=("$2")
  [[ "$2" == "FAIL" ]] && OVERALL_RC=1
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
  exit $rc
}
trap cleanup EXIT

wait_for_log() {
  local logfile="$1" pattern="$2" timeout="$3"
  local waited=0
  while (( waited < timeout * 10 )); do
    grep -q "$pattern" "$logfile" 2>/dev/null && return 0
    sleep 0.1
    waited=$((waited + 1))
  done
  return 1
}

# --- Preconditions -------------------------------------------------------------
if ! ip link show vcan0 &>/dev/null || ! ip link show vcan1 &>/dev/null \
   || ! ip link show vcan2 &>/dev/null || ! ip link show vcan3 &>/dev/null; then
  log "vcan interfaces missing, running setup_vcan.sh (needs sudo)"
  "$REPO_ROOT/setup_vcan.sh" || { echo "[sync_restart] vcan setup failed" >&2; exit 1; }
fi

export SPSEC_STORAGE_PATH="$RUNDIR/data"

[[ -x "$PARTICIPANT_BIN" ]] || { echo "[sync_restart] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
[[ -f "$CONFIGURATOR_CLI" ]] || { echo "[sync_restart] configurator submodule missing" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[sync_restart] Python configurator deps missing; pip install -r $REPO_ROOT/canopens_configurator_python/requirements.txt" >&2
  exit 1
}
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
  echo "[sync_restart] stale spsec_participant processes running; pkill -f spsec_participant" >&2
  exit 1
fi

start_sync_role() {
  "$PARTICIPANT_BIN" -t -s vcan0 -i vcan3 -p 120 -l "$LOG_LEVEL" \
    >> "$RUNDIR/p120.log" 2>&1 &
  PIDS[120]=$!
}

# --- 1. Bring the group up ------------------------------------------------------
log "starting participants (RUNDIR=$RUNDIR)"
start_sync_role
"$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p 121 -l "$LOG_LEVEL" \
  --sync-broadcast-wait "$SYNC_WAIT_MS" > "$RUNDIR/p121.log" 2>&1 &
PIDS[121]=$!
"$PARTICIPANT_BIN" -s vcan0 -i vcan2 -p 122 -l "$LOG_LEVEL" \
  --sync-broadcast-wait "$SYNC_WAIT_MS" > "$RUNDIR/p122.log" 2>&1 &
PIDS[122]=$!

for pid in 120 121 122; do
  wait_for_log "$RUNDIR/p$pid.log" "Starting main loop" 10 \
    || fail "participant $pid did not start within 10s"
done

for pid in 120 121 122; do
  log "provisioning participant $pid"
  python3 "$CONFIGURATOR_CLI" -i vcan0 -p "$pid" -k "$PARTICIPANT_KEYS_FILE" \
    > "$RUNDIR/cfg$pid.log" 2>&1 || fail "configurator failed for pid $pid"
done

# Both followers must reach a synchronized state before the restart, otherwise
# the test proves nothing about recovery.
SYNCED_OK=1
for pid in 121 122; do
  if ! wait_for_log "$RUNDIR/p$pid.log" "Time synchronized successfully" 20; then
    fail "participant $pid never synchronized before the restart"
    SYNCED_OK=0
  fi
done
add_check "followers synchronized before restart" "$([[ $SYNCED_OK -eq 1 ]] && echo PASS || echo FAIL)"

# Mark how far each follower's log had progressed, so the assertions below only
# consider lines produced *after* the restart.
declare -A MARK
for pid in 121 122; do MARK[$pid]=$(wc -l < "$RUNDIR/p$pid.log"); done

# Restart the Sync role with fresh csalt to verify follower re-sync.
log "restarting the Sync role (pid 120)"
kill "${PIDS[120]}" 2>/dev/null
for _ in {1..20}; do kill -0 "${PIDS[120]}" 2>/dev/null || break; sleep 0.1; done
kill -9 "${PIDS[120]}" 2>/dev/null
wait "${PIDS[120]}" 2>/dev/null
sleep 0.5
start_sync_role
wait_for_log "$RUNDIR/p120.log" "Starting main loop" 10 \
  || fail "Sync role did not come back up"

# --- 3. Assert the followers notice and recover ---------------------------------
# Detection: the silence window elapses and an unverifiable broadcast arrives.
DETECT_OK=1
for pid in 121 122; do
  if ! wait_for_log "$RUNDIR/p$pid.log" "assuming Sync role restarted" 30; then
    fail "participant $pid never detected the Sync-role restart"
    DETECT_OK=0
  fi
done
add_check "followers detect the Sync restart" "$([[ $DETECT_OK -eq 1 ]] && echo PASS || echo FAIL)"

# Recovery: a *new* successful synchronization after the restart, i.e. they
# re-ran parameter authentication and picked up the new salt.
RECOVER_OK=1
for pid in 121 122; do
  deadline=$((SECONDS + 40))
  recovered=0
  while (( SECONDS < deadline )); do
    if tail -n +"$(( ${MARK[$pid]} + 1 ))" "$RUNDIR/p$pid.log" \
         | grep -q "Time synchronized successfully"; then
      recovered=1
      break
    fi
    sleep 0.2
  done
  if [[ $recovered -eq 0 ]]; then
    fail "participant $pid never re-synchronized after the Sync restart"
    RECOVER_OK=0
  fi
done
add_check "followers re-authenticate and re-synchronize" "$([[ $RECOVER_OK -eq 1 ]] && echo PASS || echo FAIL)"

ALIVE_OK=1
for pid in 120 121 122; do
  kill -0 "${PIDS[$pid]}" 2>/dev/null || { fail "participant $pid died"; ALIVE_OK=0; }
done
add_check "all participants still running" "$([[ $ALIVE_OK -eq 1 ]] && echo PASS || echo FAIL)"

# --- Summary --------------------------------------------------------------------
echo
echo "===== run_e2e_sync_restart.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-55s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
if [[ $OVERALL_RC -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $OVERALL_RC
