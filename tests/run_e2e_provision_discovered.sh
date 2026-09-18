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

# End-to-end test for discovery and key ladder onboarding.
# Usage: tests/run_e2e_provision_discovered.sh [--keep] [--log-level LEVEL]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_CLI="$REPO_ROOT/canopens_configurator_python/spsec_cli.py"
CONFIGURATOR_SRC="$REPO_ROOT/canopens_configurator_python/src"
KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"

KEEP=0
LOG_LEVEL="info"
UNPROV_PID=120   # left untouched, must be detected and provisioned
PROV_PID=121     # provisioned up front, must be skipped

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 [--keep] [--log-level LEVEL]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

RUNDIR="$(mktemp -d /tmp/spsec_provdisc.XXXXXX)"
declare -A PIDS
CHECK_NAMES=(); CHECK_RESULTS=(); OVERALL_RC=0

log()  { echo "[provdisc] $*"; }
fail() { echo "[provdisc] FAIL: $*" >&2; OVERALL_RC=1; }
add_check() {
  CHECK_NAMES+=("$1"); CHECK_RESULTS+=("$2")
  [[ "$2" == "FAIL" ]] && OVERALL_RC=1
  # Must return success: callers use `cond && add_check ... PASS || add_check
  # ... FAIL`, and a non-zero return here would fire the || branch as well.
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

# --- Preconditions ------------------------------------------------------------
if ! ip link show vcan0 &>/dev/null || ! ip link show vcan1 &>/dev/null \
   || ! ip link show vcan2 &>/dev/null; then
  log "vcan interfaces missing, running setup_vcan.sh (needs sudo)"
  "$REPO_ROOT/setup_vcan.sh" || { echo "[provdisc] vcan setup failed" >&2; exit 1; }
fi
[[ -x "$PARTICIPANT_BIN" ]] || { echo "[provdisc] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
[[ -f "$CONFIGURATOR_CLI" ]] || { echo "[provdisc] configurator submodule missing" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[provdisc] Python configurator deps missing" >&2; exit 1; }
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
  echo "[provdisc] stale participants running; pkill -f spsec_participant" >&2; exit 1
fi

export SPSEC_STORAGE_PATH="$RUNDIR/data"

# --- 1. Two unprovisioned participants ----------------------------------------
log "starting participants (RUNDIR=$RUNDIR)"
"$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p "$UNPROV_PID" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$UNPROV_PID.log" 2>&1 &
PIDS[$UNPROV_PID]=$!
"$PARTICIPANT_BIN" -s vcan0 -i vcan2 -p "$PROV_PID" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$PROV_PID.log" 2>&1 &
PIDS[$PROV_PID]=$!

for pid in "$UNPROV_PID" "$PROV_PID"; do
  wait_for_log "$RUNDIR/p$pid.log" "Starting main loop" 10 \
    || fail "participant $pid did not start within 10s"
done

# --- 2. Provision one of them the ordinary way --------------------------------
log "provisioning PID $PROV_PID up front (so it must be SKIPPED later)"
python3 "$CONFIGURATOR_CLI" -i vcan0 -p "$PROV_PID" -k "$KEYS_FILE" \
  > "$RUNDIR/prov_$PROV_PID.log" 2>&1 || fail "manual provisioning of $PROV_PID failed"
sleep 1

# --- 3. Dry run: classification only -------------------------------------------
log "provision-discovered --dry-run"
PYTHONPATH="$CONFIGURATOR_SRC" timeout 180 python3 -m spsec_configurator.cli.group_cli \
  -i vcan0 -k "$KEYS_FILE" provision-discovered \
  --start-pid "$UNPROV_PID" --end-pid "$PROV_PID" --dry-run \
  > "$RUNDIR/dryrun.log" 2>&1

grep -q "1 unprovisioned, 1 already provisioned" "$RUNDIR/dryrun.log" \
  && add_check "classifies 1 unprovisioned / 1 provisioned" "PASS" \
  || add_check "classifies 1 unprovisioned / 1 provisioned" "FAIL"

grep -q "PID $PROV_PID: skipped" "$RUNDIR/dryrun.log" \
  && add_check "already-provisioned device is skipped" "PASS" \
  || add_check "already-provisioned device is skipped" "FAIL"

# Identity read back over the Zero Key proves the allow-list + the
# read-length negotiation fix.
PYTHONPATH="$CONFIGURATOR_SRC" timeout 120 python3 -m spsec_configurator.cli.group_cli \
  -i vcan0 -k "$KEYS_FILE" discover --start-pid "$PROV_PID" --end-pid "$PROV_PID" \
  > "$RUNDIR/discover.log" 2>&1
grep -qE "core=[0-9]+\.[0-9]+, mapping=302-" "$RUNDIR/discover.log" \
  && add_check "Zero-Key discovery reads core+mapping version" "PASS" \
  || add_check "Zero-Key discovery reads core+mapping version" "FAIL"

# --- 4. Real run ----------------------------------------------------------------
log "provision-discovered (for real)"
PYTHONPATH="$CONFIGURATOR_SRC" timeout 240 python3 -m spsec_configurator.cli.group_cli \
  -i vcan0 -k "$KEYS_FILE" provision-discovered \
  --start-pid "$UNPROV_PID" --end-pid "$PROV_PID" \
  > "$RUNDIR/provision.log" 2>&1

grep -q "PID $UNPROV_PID: provisioned" "$RUNDIR/provision.log" \
  && add_check "unprovisioned device reports provisioned" "PASS" \
  || add_check "unprovisioned device reports provisioned" "FAIL"

# --- 5. Confirm it actually stuck ------------------------------------------------
sleep 1
PYTHONPATH="$CONFIGURATOR_SRC" timeout 180 python3 -m spsec_configurator.cli.group_cli \
  -i vcan0 -k "$KEYS_FILE" provision-discovered \
  --start-pid "$UNPROV_PID" --end-pid "$PROV_PID" --dry-run \
  > "$RUNDIR/recheck.log" 2>&1

# The whole point: after provisioning, nothing is left to provision.
grep -q "0 unprovisioned" "$RUNDIR/recheck.log" \
  && add_check "device reads back as provisioned (keys persisted)" "PASS" \
  || add_check "device reads back as provisioned (keys persisted)" "FAIL"

ALIVE_OK=1
for pid in "$UNPROV_PID" "$PROV_PID"; do
  kill -0 "${PIDS[$pid]}" 2>/dev/null || { fail "participant $pid died"; ALIVE_OK=0; }
done
add_check "participants still running" "$([[ $ALIVE_OK -eq 1 ]] && echo PASS || echo FAIL)"

echo
echo "===== run_e2e_provision_discovered.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-55s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
if [[ $OVERALL_RC -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $OVERALL_RC
