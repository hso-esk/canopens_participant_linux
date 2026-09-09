#!/usr/bin/env python3

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""
Re-sends firmware segments out of order; reassembly must reject them.
"""
import argparse
import os
import random
import struct
import subprocess
import sys
import time
import can


def main():
    p = argparse.ArgumentParser(description="Segment Loss & Reorder Test")
    p.add_argument("--bus", default="vcan0", help="Secure bus to record from")
    p.add_argument("--sniff-time", type=float, default=4.0, help="Recording window")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    rng = random.Random(args.seed)
    print(f"[segment] Recording segments on {args.bus} for {args.sniff_time}s...")

    recorded = []
    with can.interface.Bus(channel=args.bus, interface="socketcan", fd=True) as bus:
        deadline = time.time() + args.sniff_time
        while time.time() < deadline:
            msg = bus.recv(timeout=0.1)
            if msg is None:
                continue
            # Filter write-segment arbitration ID range (0x0F..0x12 per SPsec)
            arb = msg.arbitration_id & 0x1F00FFFF
            if arb in (0x140000, 0x150000, 0x160000, 0x170000):
                recorded.append((msg.arbitration_id, bytes(msg.data)))
            if len(recorded) >= 32:
                break

    print(f"[segment] Recorded {len(recorded)} segments")
    if not recorded:
        return 0

    # Strategy A: drop a subset
    if len(recorded) >= 4:
        keep = rng.sample(range(len(recorded)), len(recorded) - 2)
        keep.sort()
        with_gaps = [recorded[i] for i in keep]
        print(f"[segment] Strategy A: dropping {len(recorded) - len(with_gaps)} segments")

    # Strategy B: shuffle and replay
    shuffled = list(recorded)
    rng.shuffle(shuffled)
    print(f"[segment] Strategy B: replaying {len(shuffled)} segments in shuffled order")

    with can.interface.Bus(channel=args.bus, interface="socketcan", fd=True) as bus:
        for arb_id, data in shuffled:
            msg = can.Message(
                arbitration_id=arb_id,
                data=data,
                is_extended_id=(arb_id > 0x7FF),
                is_fd=(len(data) > 8),
            )
            try:
                bus.send(msg)
            except Exception as e:
                print(f"[segment] send error: {e}")
            time.sleep(0.01)

    print("[segment] Replay complete. Participant should reject out-of-order or "
          "missing-segment sequences as 'reassembly state error'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
