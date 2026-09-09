#!/usr/bin/env bash

# /*
#  * Copyright (c) 2026
#  *
#  * Hochschule Offenburg, University of Applied Sciences
#  * Institute for reliable Embedded Systems
#  * and Communications Electronic (ivESK)
#  *
#  * This file is licensed as described in the "LICENSE" file
#  * included within the root folder of this work.
#  */

# Wireshark Dissector Field Extraction Test
#
# Generates a pcapng file containing three SPsec CAN frames and verifies
# that wireshark/spsec.lua decodes them correctly.
#
# Prerequisites:
#   sudo apt-get install tshark
#
# Usage: tests/run_wireshark_dissector_test.sh [--keep]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DISSECTOR="${SPSEC_DISSECTOR:-$REPO_ROOT/wireshark/spsec.lua}"
OUT_DIR="$(mktemp -d /tmp/spsec_wireshark.XXXXXX)"
KEEP=0

usage() {
  echo "Usage: $0 [--keep]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if ! command -v tshark >/dev/null 2>&1; then
  echo "ERROR: tshark not installed (sudo apt-get install tshark)" >&2
  exit 1
fi

if [[ ! -f "$DISSECTOR" ]]; then
  echo "ERROR: dissector not found: $DISSECTOR" >&2
  exit 1
fi

# tshark may be sandboxed. Copy the dissector to a world-readable location
# and chmod 644 so it can be loaded regardless of the original file's
# ownership.
PUBLIC_DISSECTOR="$OUT_DIR/spsec.lua"
cp "$DISSECTOR" "$PUBLIC_DISSECTOR"
chmod 644 "$PUBLIC_DISSECTOR"
DISSECTOR="$PUBLIC_DISSECTOR"

PCAP="$OUT_DIR/spsec.pcap"

# Generate the pcapng file. The SHB body must be exactly 28 bytes:
#   BOM(4) | maj(2) | min(2) | section_length(8) | options(12)
# The section_length at SHB-body offset 8..15 holds the byte length of
# the entire section starting from after the section_length field. This field
# is patched after writing the rest of the file.
python3 - <<'PYEOF' >"$PCAP"
import struct
import sys

# Classic PCAP (LINKTYPE_CAN_SOCKETCAN = 227)
pcap = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 227)

def canfd_pkt(arb_id, payload):
    data = payload + b'\x00' * (64 - len(payload))
    pkt_data = struct.pack(">IBBBx", arb_id | 0x80000000, len(payload), 0, 0) + data
    return struct.pack("<IIII", 0, 0, len(pkt_data), len(pkt_data)) + pkt_data

def make_arb(prefix, cpmt, pid):
    return (prefix << 24) | (0xFF << 16) | (cpmt << 8) | (pid & 0x7F)

pid = 120
pcap += canfd_pkt(make_arb(0x1E, 0, pid), bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
pcap += canfd_pkt(make_arb(0x1E, 1, pid), bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]))
pcap += canfd_pkt(make_arb(0x1E, 6, pid), bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]))

sys.stdout.buffer.write(pcap)
PYEOF

if [[ ! -s "$PCAP" ]]; then
  echo "ERROR: pcap generation produced empty file" >&2
  [[ $KEEP -eq 0 ]] && rm -rf "$OUT_DIR"
  exit 1
fi

echo "[wireshark-test] Generated pcap: $PCAP"
ls -la "$PCAP"

# Read the capture with the dissector
echo "[wireshark-test] Running tshark with dissector..."
tshark -r "$PCAP" -X "lua_script:$DISSECTOR" -Y "spsec" -T fields -e spsec.id_cpmt -e spsec.id_counter -e spsec.auth_tag 2>"$OUT_DIR/tshark.err" >"$OUT_DIR/tshark.out"
tshark_rc=$?
if (( tshark_rc != 0 )); then
  echo "FAIL: tshark exited $tshark_rc" >&2
  cat "$OUT_DIR/tshark.err" >&2
  [[ $KEEP -eq 0 ]] && rm -rf "$OUT_DIR"
  exit 1
fi
if grep -q -E "Lua: Error|Some fields aren't valid" "$OUT_DIR/tshark.err"; then
  echo "FAIL: dissector failed to load (see tshark.err)" >&2
  cat "$OUT_DIR/tshark.err" >&2
  [[ $KEEP -eq 0 ]] && rm -rf "$OUT_DIR"
  exit 1
fi
frame_count=$(wc -l < "$OUT_DIR/tshark.out")
echo "[wireshark-test] frame_count: $frame_count"
if (( frame_count < 3 )); then
  echo "FAIL: expected >=3 frames, got $frame_count" >&2
  [[ $KEEP -eq 0 ]] && rm -rf "$OUT_DIR"
  exit 1
fi

echo "[wireshark-test] PASS"
[[ $KEEP -eq 0 ]] && rm -rf "$OUT_DIR"
exit 0
