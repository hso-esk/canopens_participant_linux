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

# Seed Key Rotation Test
#
# Verifies that an Integrator-key session can rotate the Seed key set on an
# active participant, updating data-plane communication without erasing existing
# Provisioning or Integrator keys.
#
# Usage: tests/run_e2e_rekey_seed.sh [--keep] [--log-level LEVEL]
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

RUNDIR="$(mktemp -d /tmp/spsec_rekey.XXXXXX)"
PARTICIPANT_PID=""
OVERALL_RC=0
CHECK_NAMES=()
CHECK_RESULTS=()

log() { echo "[rekey] $*"; }

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

if ! ip link show vcan0 &>/dev/null || ! ip link show vcan1 &>/dev/null; then
  log "vcan interfaces missing, running setup_vcan.sh (needs sudo)"
  "$REPO_ROOT/setup_vcan.sh" || { echo "[rekey] vcan setup failed" >&2; exit 1; }
fi
[[ -x "$PARTICIPANT_BIN" ]] || { echo "[rekey] $PARTICIPANT_BIN not found; build first" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || {
  echo "[rekey] Python configurator deps missing" >&2; exit 1; }

# Match on /proc/PID/exe, not on a name or a command line: `pgrep -f` also
# matches any shell merely mentioning the binary, and `pgrep -x` never matches
# because Linux truncates comm to 15 chars ("spsec_participa").
stale_participants() {
  local target p exe
  target="$(readlink -f "$PARTICIPANT_BIN" 2>/dev/null)" || return 0
  [ -n "$target" ] || return 0
  for p in /proc/[0-9]*; do
    # A participant started before a rebuild still holds the OLD inode, and the
    # kernel then renders its exe link as "<path> (deleted)". Strip that suffix,
    # otherwise every stale process survives a rebuild undetected - which is
    # exactly how one kept poisoning the bus.
    exe="$(readlink "$p/exe" 2>/dev/null)"
    exe="${exe% (deleted)}"
    if [ "$exe" = "$target" ]; then
      echo "${p#/proc/} $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    fi
  done
}
if [ -n "$(stale_participants)" ]; then
  echo "[rekey] stale participants running; kill them first:" >&2
  stale_participants >&2
  exit 1
fi

# A second key file identical to the first except for the Seed key set, so a
# successful rotation is observable: the old Seed key must stop working and the
# new one must start.
NEW_KEYS="$RUNDIR/rekeyed_seed.txt"
{
  grep -vE '^seed_(key|salt):' "$KEYS_FILE"
  echo "seed_key:99999999999999999999999999999999aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  echo "seed_salt:8877665544332211"
} > "$NEW_KEYS"

export SPSEC_STORAGE_PATH="$RUNDIR/data"

log "starting participant $TARGET_PID (RUNDIR=$RUNDIR)"
"$PARTICIPANT_BIN" -s vcan0 -i vcan1 -p "$TARGET_PID" -l "$LOG_LEVEL" \
  > "$RUNDIR/p$TARGET_PID.log" 2>&1 &
PARTICIPANT_PID=$!
wait_for_log "$RUNDIR/p$TARGET_PID.log" "Starting main loop" 10 || {
  echo "[rekey] participant did not start" >&2; OVERALL_RC=1; exit 1; }

cli() {
  local keys="$1"; shift
  PYTHONPATH="$CONFIGURATOR_SRC" timeout 180 python3 -m spsec_configurator.cli.group_cli \
    -i vcan0 -k "$keys" "$@" 2>/dev/null
}

# The Seed key cannot open a session (REQ-PART-025), so a rotation is verified
# through the Seed Key ID register (43h), read over a Zero-Key session, plus the
# participant's own "Seed key/salt applied" records.
seed_key_id() {
  cli "$KEYS_FILE" discover --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" --key zero \
    | sed -n 's/.*seed=0x0*\([0-9a-fA-F]\+\).*/\1/p' | head -1
}

applied_count() {
  grep -c "$1" "$RUNDIR/p$TARGET_PID.log"
}

log "provisioning through the full ladder"
cli "$KEYS_FILE" provision-discovered \
  --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" > "$RUNDIR/provision.log"
grep -q "1/1 device(s) provisioned" "$RUNDIR/provision.log" \
  && add_check "device provisions through the ladder" PASS \
  || add_check "device provisions through the ladder" FAIL

# Every key must survive the ladder. The participant used to wipe "lower
# priority" keys on each successful handshake, which destroyed the Provisioning
# key the moment the ladder opened its Integrator session.
! grep -q "Resetting lower-priority key" "$RUNDIR/p$TARGET_PID.log" \
  && add_check "no keys are burned during the ladder" PASS \
  || add_check "no keys are burned during the ladder" FAIL

# SPsec102 makes the Provisioning key the highest-trust fallback anchor, and
# SPsec201 §2.5 recovers a device through it, so it must still open a session.
prov_count="$(cli "$KEYS_FILE" discover --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" --key provisioning \
  | sed -n 's/^Discovered \([0-9]\+\) device.*/\1/p' | head -1)"
[[ "$prov_count" == "1" ]] \
  && add_check "Provisioning key still opens a session after provisioning" PASS \
  || add_check "Provisioning key still opens a session after provisioning" FAIL

log "rotating the Seed key over an Integrator session"
cli "$NEW_KEYS" rekey-seed "$TARGET_PID" --seed-key-id 7 > "$RUNDIR/rekey.log"
grep -q "seed key rekeyed" "$RUNDIR/rekey.log" \
  && add_check "rekey-seed reports success" PASS \
  || add_check "rekey-seed reports success" FAIL

# The rotation must be real, not just reported: the participant must have
# applied a fresh Seed key AND salt (two applies each - one from the ladder,
# one from the rotation).
[[ "$(applied_count 'Seed key applied')" -ge 2 ]] \
  && add_check "participant applied a new Seed key" PASS \
  || add_check "participant applied a new Seed key" FAIL

[[ "$(applied_count 'Seed salt applied')" -ge 2 ]] \
  && add_check "participant applied a new Seed salt" PASS \
  || add_check "participant applied a new Seed salt" FAIL

# The rotation must re-key the DATA PLANE at the moment of the write, not at the
# next key epoch. Without this the odd/even Communication Keys stay derived from
# the previous seed for up to ~28 min while the new Seed salt is already live as
# nonce padding - i.e. new nonce, old key, every frame failing to authenticate.
grep -q "communication keys invalidated" "$RUNDIR/p$TARGET_PID.log" \
  && add_check "Seed write re-keys the data plane immediately" PASS \
  || add_check "Seed write re-keys the data plane immediately" FAIL

# 43h must carry the rotated Key ID, readable over a Zero-Key session.
[[ "$(seed_key_id)" == "7" ]] \
  && add_check "Seed Key ID register reflects the rotation" PASS \
  || add_check "Seed Key ID register reflects the rotation (got $(seed_key_id))" FAIL

# A Seed key must not be usable to open a configuration session. Invoked
# directly rather than through cli(), which discards stderr - argparse reports
# the rejection there.
PYTHONPATH="$CONFIGURATOR_SRC" python3 -m spsec_configurator.cli.group_cli \
  -i vcan0 -k "$NEW_KEYS" discover --start-pid "$TARGET_PID" --end-pid "$TARGET_PID" \
  --key seed > "$RUNDIR/seed_session.log" 2>&1
seed_rc=$?
{ [[ $seed_rc -ne 0 ]] && grep -qi "invalid choice: 'seed'" "$RUNDIR/seed_session.log"; } \
  && add_check "CLI refuses --key seed" PASS \
  || add_check "CLI refuses --key seed" FAIL

# The CLI guard is convenience; the real control is participant-side. Drive the
# core API directly with the Seed selector - the handshake must be refused.
PYTHONPATH="$CONFIGURATOR_SRC" python3 - "$NEW_KEYS" > "$RUNDIR/seed_handshake.log" 2>&1 <<'PYEOF'
import sys
from spsec_configurator.core.configurator import (
    configurator_init, configurator_destroy, configurator_start_session)
from spsec_configurator.core.spsec_definitions import SPSEC_KEY_SELECTOR_SEED_KEY

cfg = configurator_init("vcan0", sys.argv[1])
try:
    ret = configurator_start_session(cfg, 120, SPSEC_KEY_SELECTOR_SEED_KEY, 3.0)
finally:
    configurator_destroy(cfg)
print("SEED_SESSION_RET", ret)
sys.exit(0 if ret != 0 else 1)
PYEOF
seed_hs_rc=$?
[[ $seed_hs_rc -eq 0 ]] \
  && add_check "participant refuses a Seed-key handshake" PASS \
  || add_check "participant refuses a Seed-key handshake" FAIL

grep -q "Seed key rejected for handshake" "$RUNDIR/p$TARGET_PID.log" \
  && add_check "participant logs the Seed-key rejection" PASS \
  || add_check "participant logs the Seed-key rejection" FAIL

# A Seed session used to destroy the Integrator key, making the rotation above
# a one-way door. Rotation must stay repeatable.
log "re-rotating back to the original Seed key"
cli "$KEYS_FILE" rekey-seed "$TARGET_PID" --seed-key-id 9 > "$RUNDIR/rekey_again.log"
grep -q "seed key rekeyed" "$RUNDIR/rekey_again.log" \
  && add_check "Seed key rotation is repeatable" PASS \
  || add_check "Seed key rotation is repeatable" FAIL

[[ "$(seed_key_id)" == "9" ]] \
  && add_check "second rotation takes effect" PASS \
  || add_check "second rotation takes effect (got $(seed_key_id))" FAIL

! grep -q "Resetting lower-priority key" "$RUNDIR/p$TARGET_PID.log" \
  && add_check "no keys are burned by any session" PASS \
  || add_check "no keys are burned by any session" FAIL

kill -0 "$PARTICIPANT_PID" 2>/dev/null \
  && add_check "participant still running" PASS \
  || add_check "participant still running" FAIL

echo
echo "===== run_e2e_rekey_seed.sh summary ====="
for i in "${!CHECK_NAMES[@]}"; do
  printf '%-58s %s\n' "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
done
echo
echo "RUNDIR: $RUNDIR"
if [[ $OVERALL_RC -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $OVERALL_RC
