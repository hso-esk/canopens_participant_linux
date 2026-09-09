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
Replays recorded frames; must be rejected by counter/timestamp checks.
"""
import argparse
import os
import subprocess
import sys
import time
import can


def main():
    p = argparse.ArgumentParser(description="Replay Attack Injection Test")
    p.add_argument("--bus", default="vcan0", help="Secure bus interface")
    p.add_argument("--sniff-time", type=float, default=3.0, help="Time to record valid frames")
    p.add_argument("--replay-count", type=int, default=5, help="Times to replay each frame")
    p.add_argument("--wait", type=float, default=0.05, help="Delay between replays")
    args = p.parse_args()

    print(f"[replay] Sniffing valid frames on {args.bus} for {args.sniff_time}s...")
    recorded = []
    with can.interface.Bus(channel=args.bus, interface="socketcan") as bus:
        deadline = time.time() + args.sniff_time
        while time.time() < deadline and len(recorded) < 5:
            msg = bus.recv(timeout=0.1)
            if msg is None:
                continue
            if msg.arbitration_id > 0x7FF and len(msg.data) > 0:
                recorded.append((msg.arbitration_id, bytes(msg.data)))
        print(f"[replay] Recorded {len(recorded)} frames.")

    if not recorded:
        print("[replay] No frames recorded; nothing to replay", file=sys.stderr)
        return 0

    # Replay each frame multiple times
    print(f"[replay] Replaying {args.replay_count} times each...")
    with can.interface.Bus(channel=args.bus, interface="socketcan") as bus:
        for arb_id, data in recorded:
            for _ in range(args.replay_count):
                msg = can.Message(
                    arbitration_id=arb_id,
                    data=data,
                    is_extended_id=(arb_id > 0x7FF),
                    is_fd=(len(data) > 8),
                )
                try:
                    bus.send(msg)
                except Exception as e:
                    print(f"[replay] Send error: {e}")
                time.sleep(args.wait)

    print("[replay] Replay injection complete. The participant should drop these frames")
    print("        via the monotonic counter check and 15 ms timestamp window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
