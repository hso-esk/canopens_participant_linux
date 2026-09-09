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

# End-to-end test for multi-segment code update transfer (register 0x92).
#
# Usage: tests/run_e2e_code_update.sh [--keep] [--log-level LEVEL]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_SRC="$REPO_ROOT/canopens_configurator_python/src"
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

RUNDIR="$(mktemp -d /tmp/spsec_code_update.XXXXXX)"
PARTICIPANT_PID=""
OVERALL_RC=0
CHECK_NAMES=()
CHECK_RESULTS=()

log() { echo "[code-update] $*"; }

add_check() {
  CHECK_NAMES+=("$1")
  CHECK_RESULTS+=("$2")
  [[ "$2" == "FAIL" ]] && OVERALL_RC=1
  # Must not inherit the test above: `cond && add_check PASS || add_check FAIL`
  # would otherwise fire both branches whenever a PASS is recorded.
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

if ! ip link show vcan0 &>/dev/null; then
  log "vcan0 missing, running setup_vcan.sh (needs sudo)"
  "$REPO_ROOT/setup_vcan.sh" || { echo "[code-update] vcan setup failed" >&2; exit 1; }
fi
[[ -x "$PARTICIPANT_BIN" ]] || { echo "[code-update] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[code-update] Python configurator deps missing" >&2; exit 1; }

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
  echo "[code-update] stale participants running; kill them first:" >&2
  stale_participants >&2
  exit 1
fi

# Provision public auth key and enable code update capability before launch
PUBKEY_HEX="$(python3 -c 'print("a1"*32)')"
PUBKEY_FILE="$RUNDIR/public_auth_key.hex"
printf '%s' "$PUBKEY_HEX" > "$PUBKEY_FILE"
export SPSEC_PUBLIC_AUTH_KEY_FILE="$PUBKEY_FILE"
export SPSEC_CODE_UPDATE_ENABLED=1
export SPSEC_STORAGE_PATH="$RUNDIR/data"

cli() {
  PYTHONPATH="$CONFIGURATOR_SRC" timeout 180 python3 -m spsec_configurator.cli.group_cli \
    -i vcan0 -k "$KEYS_FILE" "$@" 2>/dev/null
}

"$PARTICIPANT_BIN" -b -s vcan0 -i vcan1 -p "$TARGET_PID" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$TARGET_PID.log" 2>&1 &
PARTICIPANT_PID=$!
wait_for_log "$RUNDIR/p$TARGET_PID.log" "Starting main loop" 10 || {
  echo "[code-update] participant did not start" >&2; OVERALL_RC=1; exit 1; }

log "provisioning through the full ladder"
cli provision-discovered --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" \
  > "$RUNDIR/provision.log"
if grep -q "1/1 device(s) provisioned" "$RUNDIR/provision.log"; then
  add_check "device provisions through the ladder" PASS
else
  add_check "device provisions through the ladder" FAIL
fi

# Build a 4096-byte image with a known pattern: byte i has value (i & 0xFF).
# 128 segments of 32 bytes each. The fixed pattern allows asserting that the file is
# the concatenation, not a single truncated segment.
python3 -c "
import sys
sys.stdout.buffer.write(bytes(i & 0xFF for i in range(4096)))
" > "$RUNDIR/image.bin"

IMAGE_LEN="$(wc -c < "$RUNDIR/image.bin")"
[[ "$IMAGE_LEN" -eq 4096 ]] \
  && add_check "image fixture is exactly 4096 bytes" PASS \
  || add_check "image fixture is 4096 bytes (got $IMAGE_LEN)" FAIL

log "uploading 4096-byte image to 92h"
cli code-update "$TARGET_PID" --file "$RUNDIR/image.bin" --key integrator \
  > "$RUNDIR/upload.log" 2>&1
upload_rc=$?
grep -q "Image stored" "$RUNDIR/upload.log" \
  && add_check "code-update CLI reports success" PASS \
  || { add_check "code-update CLI reports success" FAIL; cat "$RUNDIR/upload.log" >&2; }
STORED_FILE="$RUNDIR/data_${TARGET_PID}/code_update/update_file.bin"
# failed) or be only 32 bytes (last segment only).
if [[ -f "$STORED_FILE" ]]; then
  # Bin format: 1 byte on disk per byte of plaintext.
  stored_size="$(wc -c < "$STORED_FILE")"
  [[ "$stored_size" -eq 4096 ]] \
    && add_check "participant stored 4096 bytes (got $stored_size)" PASS \
    || add_check "participant stored 4096 bytes (got $stored_size)" FAIL
  if cmp -s "$RUNDIR/image.bin" "$STORED_FILE"; then
    add_check "stored image is byte-identical to the upload" PASS
  else
    add_check "stored image is byte-identical to the upload" FAIL
  fi
else
  add_check "participant wrote code_update/update_file" FAIL
fi
# The log should show exactly one "Code update file saved to storage" line
# and 127 "segment accepted" lines, never 128 file-save lines. The apply
# path used to log "Code update file saved to storage" on every segment.
save_count="$(grep -c 'Code update file saved to storage' "$RUNDIR/p$TARGET_PID.log" || true)"
[[ "$save_count" -eq 1 ]] \
  && add_check "storage written exactly once (got $save_count)" PASS \
  || add_check "storage written exactly once (got $save_count)" FAIL

segment_count="$(grep -c '92h segment accepted' "$RUNDIR/p$TARGET_PID.log" || true)"
# 127 partial segments acknowledged + 1 final = 128 segments. The
# "segment accepted" log fires only for partial segments (accum_len < total).
[[ "$segment_count" -eq 127 ]] \
  && add_check "127 partial segments acknowledged (got $segment_count)" PASS \
  || add_check "127 partial segments acknowledged (got $segment_count)" FAIL

# The participant must still be running cleanly.
kill -0 "$PARTICIPANT_PID" 2>/dev/null \
  && add_check "participant still running" PASS \
  || add_check "participant still running" FAIL

echo
echo "===== run_e2e_code_update.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-58s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
if [[ $OVERALL_RC -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $OVERALL_RC
