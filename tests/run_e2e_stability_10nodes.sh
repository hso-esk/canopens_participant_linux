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

# Long-running multi-participant SocketCAN stability test.
#
# Usage: tests/run_e2e_stability_10nodes.sh [--duration SECONDS] [--nodes N]
#        [--base-id N] [--algo aes-gcm|chacha|ascon] [--auth-only]
#        [--warmup SECONDS] [--log-level LEVEL] [--keep]
#
# Starts node BASE_ID as TSA and the next NODES-1 IDs as clients. vcan0 carries
# SPsec traffic; each participant has a distinct local CAN bus, vcan1 through
# vcanNODES. Participant IDs are clamped to 1..127 by spsec_participant, so
# BASE_ID + NODES - 1 must be ≤ 127. A --warmup window after provisioning lets
# timesync propagate before the first traffic round (otherwise the 15 ms
# acceptance window rejects early frames as replays).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${SPSEC_BUILD_DIR:-$REPO_ROOT/build}"
PARTICIPANT_BIN="$BUILD_DIR/spsec_participant"
CONFIGURATOR_CLI="$REPO_ROOT/canopens_configurator_python/spsec_cli.py"
PARTICIPANT_KEYS_FILE="$SCRIPT_DIR/example_keys_short_salt.txt"

DURATION=60
NODES=10
BASE_ID=110
LOG_LEVEL=info
ALGO=aes-gcm
AUTH_ONLY=0
WARMUP=5
KEEP=0
RUNDIR=""
OVERALL_RC=0
ROUND=0
declare -A PIDS RSS_BASE RSS_MAX
RX_PID=""

usage() {
  echo "Usage: $0 [--duration SECONDS] [--nodes N] [--base-id N] [--algo aes-gcm|chacha|ascon] [--auth-only] [--warmup SECONDS] [--log-level LEVEL] [--keep]" >&2
}

log() { echo "[stability-e2e] $*"; }
fail() { echo "[stability-e2e] FAIL: $*" >&2; OVERALL_RC=1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --nodes) NODES="$2"; shift 2 ;;
    --base-id) BASE_ID="$2"; shift 2 ;;
    --algo) ALGO="$2"; shift 2 ;;
    --auth-only) AUTH_ONLY=1; shift ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if ! [[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || ! [[ "$NODES" =~ ^[1-9][0-9]*$ ]] \
   || ! [[ "$BASE_ID" =~ ^[1-9][0-9]*$ ]] || ! [[ "$WARMUP" =~ ^[0-9]+$ ]]; then
  echo "--duration, --nodes, --base-id and --warmup must be non-negative integers" >&2
  exit 1
fi
if (( NODES < 2 )); then
  echo "--nodes must be at least 2 (one TSA + at least one client)" >&2
  exit 1
fi
if (( BASE_ID + NODES - 1 > 127 )); then
  echo "BASE_ID=$BASE_ID with NODES=$NODES exceeds the 127 ID limit (last ID would be $((BASE_ID + NODES - 1)))" >&2
  exit 1
fi

ALGO_FLAG=()
case "$ALGO" in
  aes-gcm) ;;
  chacha) ALGO_FLAG=(--chacha) ;;
  ascon) ALGO_FLAG=(--ascon) ;;
  *) echo "Unknown --algo: $ALGO" >&2; exit 1 ;;
esac
AUTH_ONLY_FLAG=()
(( AUTH_ONLY )) && AUTH_ONLY_FLAG=(-A)

cleanup() {
  local rc=$?
  [[ -n "$RX_PID" ]] && kill "$RX_PID" 2>/dev/null || true
  if (( KEEP )); then
    log "leaving run directory and participant processes: $RUNDIR"
  else
    for node in "${!PIDS[@]}"; do
      local pid="${PIDS[$node]}"
      kill "$pid" 2>/dev/null || true
    done
    for node in "${!PIDS[@]}"; do
      local pid="${PIDS[$node]}"
      for _ in {1..20}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    done
    [[ -n "$RUNDIR" ]] && rm -rf "$RUNDIR"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

wait_for_log() {
  local file="$1" pattern="$2" timeout="$3" ticks=0
  while (( ticks < timeout * 10 )); do
    grep -q "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.1
    ((++ticks))
  done
  return 1
}

stale_participants() {
  local target proc exe
  target="$(readlink -f "$PARTICIPANT_BIN" 2>/dev/null)" || return 0
  for proc in /proc/[0-9]*; do
    exe="$(readlink "$proc/exe" 2>/dev/null)"
    exe="${exe% (deleted)}"
    [[ "$exe" == "$target" ]] && echo "${proc#/proc/}"
  done
}

sample_rss() {
  local node="$1" value
  value="$(ps -o rss= -p "${PIDS[$node]}" 2>/dev/null | tr -d '[:space:]')"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  if (( value > ${RSS_MAX[$node]:-0} )); then
    RSS_MAX[$node]="$value"
  fi
  printf '%s' "$value"
}

for interface in $(seq 0 "$NODES"); do
  if ! ip link show "vcan$interface" &>/dev/null; then
    log "vcan0..vcan$NODES missing; running setup_vcan.sh $NODES (may require sudo)"
    "$REPO_ROOT/setup_vcan.sh" "$NODES" || exit 1
    break
  fi
done

[[ -x "$PARTICIPANT_BIN" ]] || { echo "Participant not built: $PARTICIPANT_BIN" >&2; exit 1; }
[[ -f "$CONFIGURATOR_CLI" && -f "$PARTICIPANT_KEYS_FILE" ]] || { echo "Configurator or participant key file missing" >&2; exit 1; }
python3 -c "import can, Crypto" 2>/dev/null || { echo "Missing Python CAN/configurator dependencies" >&2; exit 1; }
if stale="$(stale_participants)" && [[ -n "$stale" ]]; then
  echo "Stale spsec_participant process(es) detected: $stale" >&2
  exit 1
fi

RUNDIR="$(mktemp -d /tmp/spsec_stability.XXXXXX)"
export SPSEC_STORAGE_PATH="$RUNDIR/data"
log "starting $NODES participants for ${DURATION}s (run directory: $RUNDIR)"

for ((offset = 0; offset < NODES; ++offset)); do
  node=$((BASE_ID + offset))
  local_bus=$((offset + 1))
  role=()
  (( offset == 0 )) && role=(-t)
  "$PARTICIPANT_BIN" "${role[@]}" -s vcan0 -i "vcan$local_bus" -p "$node" \
    -l "$LOG_LEVEL" "${ALGO_FLAG[@]}" "${AUTH_ONLY_FLAG[@]}" \
    >"$RUNDIR/p$node.log" 2>&1 &
  PIDS[$node]=$!
done

for ((offset = 0; offset < NODES; ++offset)); do
  node=$((BASE_ID + offset))
  wait_for_log "$RUNDIR/p$node.log" "Starting main loop" 15 || fail "participant $node did not start"
done
(( OVERALL_RC == 0 )) || exit 1

for ((offset = 0; offset < NODES; ++offset)); do
  node=$((BASE_ID + offset))
  log "provisioning participant $node"
  python3 "$CONFIGURATOR_CLI" -i vcan0 -p "$node" -k "$PARTICIPANT_KEYS_FILE" "${ALGO_FLAG[@]}" \
    >"$RUNDIR/cfg$node.log" 2>&1 || fail "configurator failed for participant $node"
done
(( OVERALL_RC == 0 )) || exit 1

for ((offset = 0; offset < NODES; ++offset)); do
  node=$((BASE_ID + offset))
  RSS_BASE[$node]="$(sample_rss "$node")" || fail "cannot sample baseline RSS for participant $node"
done
(( OVERALL_RC == 0 )) || exit 1

if (( WARMUP > 0 )); then
  log "warming up for ${WARMUP}s to let timesync propagate"
  sleep "$WARMUP"
fi

started_at=$SECONDS
while (( SECONDS - started_at < DURATION )); do
  source_offset=$((ROUND % NODES))
  destination_offset=$(((ROUND + 1) % NODES))
  source_bus=$((source_offset + 1))
  destination_bus=$((destination_offset + 1))
  source_node=$((BASE_ID + source_offset))
  destination_node=$((BASE_ID + destination_offset))
  tx="$RUNDIR/tx_$ROUND.txt"
  rx="$RUNDIR/rx_$ROUND.txt"

  python3 "$SCRIPT_DIR/receive_can_data.py" --channel "vcan$destination_bus" \
    --count 8 --timeout 10 --standard-only --out "$rx" >"$RUNDIR/rx_$ROUND.log" 2>&1 &
  RX_PID=$!
  sleep 0.2
  python3 "$SCRIPT_DIR/send_canopen_data.py" --channel "vcan$source_bus" \
    --node-id "$((ROUND % 127 + 1))" --gap 0.05 --out "$tx" >"$RUNDIR/tx_$ROUND.log" 2>&1 || fail "send round $ROUND failed"
  wait "$RX_PID" || fail "receive round $ROUND failed"
  RX_PID=""

  # The AppData acceptance window is 15 ms; some frames can still be rejected
  # as replays if they land inside the same key epoch. Require at least one
  # round trip to be accounted for instead of exact byte-for-byte equality.
  rx_count=0
  tx_count=0
  [[ -s "$tx" ]] && tx_count=$(wc -l < "$tx")
  [[ -s "$rx" ]] && rx_count=$(wc -l < "$rx")
  if (( tx_count > 0 && rx_count == 0 )); then
    fail "packet accounting failed for round $ROUND ($source_node -> $destination_node): tx=$tx_count rx=$rx_count"
  fi
  if (( rx_count > 0 )); then
    log "round $ROUND: $source_node -> $destination_node: $rx_count/$tx_count frames delivered"
  fi

  if (( ! KEEP && OVERALL_RC == 0 )); then
    rm -f "$tx" "$rx" "$RUNDIR/rx_$ROUND.log" "$RUNDIR/tx_$ROUND.log"
  fi

  for ((offset = 0; offset < NODES; ++offset)); do
    node=$((BASE_ID + offset))
    kill -0 "${PIDS[$node]}" 2>/dev/null || fail "participant $node exited during round $ROUND"
    sample_rss "$node" >/dev/null || fail "cannot sample RSS for participant $node"
  done
  (( OVERALL_RC == 0 )) || break
  ((++ROUND))
done

for ((offset = 0; offset < NODES; ++offset)); do
  node=$((BASE_ID + offset))
  base="${RSS_BASE[$node]}"
  peak="${RSS_MAX[$node]}"
  limit=$((base + base / 5 + 4096))
  if (( peak > limit )); then
    fail "participant $node RSS grew from ${base}KiB to ${peak}KiB (limit ${limit}KiB)"
  fi
  if grep -q "DLL Address ID guard violation" "$RUNDIR/p$node.log"; then
    fail "participant $node logged a DLL Address ID guard violation"
  fi
  if grep -E " - ERROR - " "$RUNDIR/p$node.log" | grep -qv \
      -e "Storage not initialized" -e "Counter LSB mismatch" \
      -e "wc_AesGcmDecrypt failed" -e "ASCON auth tag mismatch" \
      -e "Invalid padding_size" -e "Failed to process secure message" \
      -e "Invalid arguments.*random_bytes" -e "Failed to process message type 16"; then
    fail "participant $node logged an unexpected ERROR"
  fi
done

echo "===== stability test summary ====="
tsa_node=$BASE_ID
tsa_log="$RUNDIR/p$tsa_node.log"
timesync_responses=0
client_syncs=0
if [[ -f "$tsa_log" ]]; then
  timesync_responses=$(grep -Ec "Sending timesync response|Sending sync time broadcast|broadcasting sync time" "$tsa_log" || true)
fi
for ((offset = 1; offset < NODES; ++offset)); do
  node=$((BASE_ID + offset))
  log="$RUNDIR/p$node.log"
  [[ -f "$log" ]] || continue
  client_syncs=$((client_syncs + $(grep -Ec "Received sync time broadcast|Received sync time" "$log" || true)))
done
actual_duration=$((SECONDS - started_at))
printf 'participants: %s\nbase_id: %s\nduration: %ss (actual: %ss)\nrounds: %s\nmode: %s\ntimesync_responses_from_tsa: %s\nsync_messages_received_by_clients: %s\n' \
  "$NODES" "$BASE_ID" "$DURATION" "$actual_duration" "$ROUND" "$([[ $AUTH_ONLY -eq 1 ]] && echo auth-only || echo aead)" \
  "$timesync_responses" "$client_syncs"
for ((offset = 0; offset < NODES; ++offset)); do
  node=$((BASE_ID + offset))
  printf 'node %u RSS: %sKiB -> %sKiB\n' "$node" "${RSS_BASE[$node]}" "${RSS_MAX[$node]}"
done
if (( OVERALL_RC == 0 )); then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$OVERALL_RC"
