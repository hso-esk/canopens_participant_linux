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

# End-to-end test: bring up 3 SPsec participants, provision via configurator,
# exchange CANopen traffic, and assert results.
#
# Usage: tests/run_e2e.sh [--keep] [--log-level LEVEL] [--keys FILE] [--strict] [--algo aes-gcm|chacha|ascon]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Allow override of build directory for sanitizer builds, salt-length/backend
# variants, etc.
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_CLI="$REPO_ROOT/canopens_configurator_python/spsec_cli.py"

KEEP=0
LOG_LEVEL="info"
KEYS_FILE="$SCRIPT_DIR/example_keys.txt"
PARTICIPANT_KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"
STRICT=0
ALGO="aes-gcm"
ALGO_FLAG=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    --keys) KEYS_FILE="$2"; shift 2 ;;
    --participant-keys) PARTICIPANT_KEYS_FILE="$2"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --algo) ALGO="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--keep] [--log-level LEVEL] [--keys FILE] [--strict] [--algo aes-gcm|chacha|ascon]"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

case "$ALGO" in
  aes-gcm) ALGO_FLAG=() ;;
  chacha) ALGO_FLAG=(--chacha) ;;
  ascon) ALGO_FLAG=(--ascon) ;;
  *) echo "[run_e2e] Unknown --algo: $ALGO (use aes-gcm, chacha, or ascon)" >&2; exit 1 ;;
esac

RUNDIR="$(mktemp -d /tmp/spsec_e2e.XXXXXX)"
declare -A PIDS
CHECK_NAMES=()
CHECK_RESULTS=()
OVERALL_RC=0

log()  { echo "[run_e2e] $*"; }
fail() { echo "[run_e2e] FAIL: $*" >&2; OVERALL_RC=1; }

add_check() {
  CHECK_NAMES+=("$1")
  CHECK_RESULTS+=("$2")
  [[ "$2" == "FAIL" ]] && OVERALL_RC=1
}

cleanup() {
  local rc=$?
  if [[ $KEEP -eq 1 ]]; then
    log "leaving processes running ($RUNDIR); kill manually with: kill ${PIDS[*]:-}"
  else
    for pid in "${PIDS[@]:-}"; do
      [[ -z "$pid" ]] && continue
      kill "$pid" 2>/dev/null
      for _ in {1..20}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -9 "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    done
  fi
  exit "$rc"
}
trap cleanup EXIT

# --- 1. Bus setup -----------------------------------------------------------
if ! ip link show vcan0 &>/dev/null || ! ip link show vcan1 &>/dev/null \
   || ! ip link show vcan2 &>/dev/null || ! ip link show vcan3 &>/dev/null; then
  log "vcan interfaces missing, running setup_vcan.sh (needs sudo)"
  if ! "$REPO_ROOT/setup_vcan.sh"; then
    echo "[run_e2e] Failed to set up vcan interfaces. Run ./setup_vcan.sh manually." >&2
    exit 1
  fi
fi

# --- 2. Isolated storage ------------------------------------------------------
export SPSEC_STORAGE_PATH="$RUNDIR/data"

# --- 3. Build check -----------------------------------------------------------
if [[ ! -x "$PARTICIPANT_BIN" ]]; then
  echo "[run_e2e] $PARTICIPANT_BIN not found. Build it first (build_linux/ or set SPSEC_BUILD_DIR)." >&2
  exit 1
fi
newest_src="$(find "$REPO_ROOT/src" "$REPO_ROOT/common" "$REPO_ROOT/platform" "$REPO_ROOT/spsec_can_protocol" "$REPO_ROOT/spsec_participant" -name '*.c' -newer "$PARTICIPANT_BIN" 2>/dev/null | head -1)"
if [[ -n "$newest_src" ]]; then
  echo "[run_e2e] $PARTICIPANT_BIN is older than $newest_src. Rebuild before running." >&2
  exit 1
fi

if [[ ! -f "$KEYS_FILE" ]]; then
  echo "[run_e2e] Keys file not found: $KEYS_FILE" >&2
  exit 1
fi
if [[ ! -f "$PARTICIPANT_KEYS_FILE" ]]; then
  echo "[run_e2e] Participant keys file not found: $PARTICIPANT_KEYS_FILE" >&2
  exit 1
fi
if [[ ! -f "$CONFIGURATOR_CLI" ]]; then
  echo "[run_e2e] $CONFIGURATOR_CLI not found - is the canopens_configurator_python submodule checked out (git submodule update --init)?" >&2
  exit 1
fi
if ! python3 -c "import can, Crypto" 2>/dev/null; then
  echo "[run_e2e] Python configurator dependencies missing. Run:" >&2
  echo "  pip install -r $REPO_ROOT/canopens_configurator_python/requirements.txt" >&2
  exit 1
fi

# Check for existing participant processes to prevent address ID collisions
stale_participants() {
  local target p exe
  target="$(readlink -f "$PARTICIPANT_BIN" 2>/dev/null)" || return 0
  [ -n "$target" ] || return 0
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null)"
    exe="${exe% (deleted)}"
    if [ "$exe" = "$target" ]; then
      echo "${p#/proc/} $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    fi
  done
}

if [ -n "$(stale_participants)" ]; then
  echo "[run_e2e] stale spsec_participant processes are running:" >&2
  stale_participants >&2
  echo "[run_e2e] kill them first: pkill -f spsec_participant" >&2
  exit 1
fi

# --- 4. Launch participants ----------------------------------------------------
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

log "starting participants (RUNDIR=$RUNDIR, algo=$ALGO)"
"$PARTICIPANT_BIN" -t -s vcan0 -i vcan3 -p 120 -l "$LOG_LEVEL" "${ALGO_FLAG[@]}" \
  > "$RUNDIR/p120.log" 2>&1 &
PIDS[120]=$!
"$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p 121 -l "$LOG_LEVEL" "${ALGO_FLAG[@]}" \
  > "$RUNDIR/p121.log" 2>&1 &
PIDS[121]=$!
"$PARTICIPANT_BIN" -s vcan0 -i vcan2 -p 122 -l "$LOG_LEVEL" "${ALGO_FLAG[@]}" \
  > "$RUNDIR/p122.log" 2>&1 &
PIDS[122]=$!

for pid in 120 121 122; do
  if ! wait_for_log "$RUNDIR/p$pid.log" "Starting main loop" 10; then
    fail "participant $pid did not report 'Starting main loop' within 10s"
  fi
done

# --- 5. Provisioning ------------------------------------------------------------
CONFIGURATOR_OK=1
for pid in 120 121 122; do
  log "provisioning participant $pid"
  if ! python3 "$CONFIGURATOR_CLI" -i vcan0 -p "$pid" -k "$PARTICIPANT_KEYS_FILE" "${ALGO_FLAG[@]}" \
       > "$RUNDIR/cfg$pid.log" 2>&1; then
    fail "configurator run for pid $pid exited non-zero (see $RUNDIR/cfg$pid.log)"
    CONFIGURATOR_OK=0
  fi
done
add_check "configurator provisioning" "$([[ $CONFIGURATOR_OK -eq 1 ]] && echo PASS || echo FAIL)"

# --- 6. Data plane ---------------------------------------------------------------
log "starting receiver on vcan2"
python3 "$SCRIPT_DIR/receive_can_data.py" --channel vcan2 --count 8 --timeout 15 \
  --out "$RUNDIR/rx.txt" > "$RUNDIR/rx.log" 2>&1 &
RX_PID=$!

sleep 0.5
log "sending CANopen traffic on vcan1"
python3 "$SCRIPT_DIR/send_canopen_data.py" --channel vcan1 --node-id 0x01 --gap 0.05 \
  --out "$RUNDIR/tx.txt" > "$RUNDIR/tx.log" 2>&1

wait "$RX_PID" 2>/dev/null

# --- 7. Assertions -----------------------------------------------------------------
ALIVE_OK=1
for pid in 120 121 122; do
  if ! kill -0 "${PIDS[$pid]}" 2>/dev/null; then
    fail "participant $pid is not running at end of test"
    ALIVE_OK=0
  fi
done
add_check "participants alive" "$([[ $ALIVE_OK -eq 1 ]] && echo PASS || echo FAIL)"

GUARD_OK=1
for pid in 120 121 122; do
  if grep -q "DLL Address ID guard violation" "$RUNDIR/p$pid.log"; then
    fail "participant $pid logged a DLL Address ID guard violation (self-loopback regression)"
    GUARD_OK=0
  fi
done
add_check "TC-CFG-029: no DLL Address ID guard violations (self-loopback)" "$([[ $GUARD_OK -eq 1 ]] && echo PASS || echo FAIL)"

ERROR_OK=1
for pid in 120 121 122; do
  # Filter expected benign startup and key-rotation log messages
  if grep -E " - ERROR - " "$RUNDIR/p$pid.log" | grep -qv -e "Storage not initialized" -e "Counter LSB mismatch" -e "wc_AesGcmDecrypt failed" -e "ASCON auth tag mismatch" -e "Invalid padding_size" -e "Failed to process secure message" -e "Invalid arguments.*random_bytes" -e "Failed to process message type 16"; then
    fail "participant $pid logged an ERROR line"
    ERROR_OK=0
  fi
done
add_check "no ERROR log lines" "$([[ $ERROR_OK -eq 1 ]] && echo PASS || echo FAIL)"

RX_COUNT=0
[[ -f "$RUNDIR/rx.txt" ]] && RX_COUNT=$(wc -l < "$RUNDIR/rx.txt")
if [[ "$RX_COUNT" -ge 1 ]]; then
  add_check "at least one frame received on vcan2" "PASS"
else
  fail "no frames captured on vcan2"
  add_check "at least one frame received on vcan2" "FAIL"
fi

if [[ $STRICT -eq 1 ]]; then
  if [[ -f "$RUNDIR/tx.txt" ]] && diff -q "$RUNDIR/tx.txt" "$RUNDIR/rx.txt" >/dev/null 2>&1; then
    add_check "strict tx/rx frame match" "PASS"
  else
    fail "strict tx/rx frame match failed (COB-ID remapping not confirmed, see --strict note in plan)"
    add_check "strict tx/rx frame match" "FAIL"
  fi
fi

# --- 9. Summary -----------------------------------------------------------------
echo
echo "===== run_e2e.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf "%-55s %s\n" "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "--- sent (tx.txt) ---"
cat "$RUNDIR/tx.txt" 2>/dev/null
echo "--- received (rx.txt) ---"
cat "$RUNDIR/rx.txt" 2>/dev/null
echo
echo "RUNDIR: $RUNDIR"
if [[ $OVERALL_RC -eq 0 ]]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi

exit $OVERALL_RC
