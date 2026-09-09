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
Injects frames outside the 15ms accept window; must be dropped, no desync.
"""
import argparse
import os
import struct
import sys
import time
import can


def make_arb_id(base, tag, ts_low16):
    """Construct an arbitration ID with discriminator + timestamp field."""
    return (tag << 24) | (ts_low16 & 0xFFFF) | (base & 0xFFF)


def main():
    p = argparse.ArgumentParser(description="Clock Skew Boundary Test")
    p.add_argument("--bus", default="vcan0")
    p.add_argument("--count", type=int, default=10)
    args = p.parse_args()

    print(f"[skew] Injecting out-of-window frames on {args.bus}...")

    skews_ns = [
        ("past_small",   -20_000_000),     # -20 ms
        ("past_large", -1_000_000_000),    # -1 s
        ("future_small",  20_000_000),     # +20 ms
        ("future_large", 1_000_000_000),   # +1 s
    ]

    with can.interface.Bus(channel=args.bus, interface="socketcan") as bus:
        for label, offset_ns in skews_ns:
            for i in range(args.count):
                now_ns = time.perf_counter_ns()
                skewed_ts_ns = (now_ns + offset_ns) & 0xFFFFFFFFFFFFFFFF
                # Use a 64-bit ns timestamp packed as 8-byte little-endian
                ts_bytes = struct.pack("<Q", skewed_ts_ns)
                arb_id = 0x18000000 | ((i + 1) & 0xFFF)
                msg = can.Message(
                    arbitration_id=arb_id,
                    data=ts_bytes + bytes(8),
                    is_extended_id=True,
                )
                try:
                    bus.send(msg)
                except Exception as e:
                    print(f"[skew] {label} send error: {e}")
                time.sleep(0.01)

    print("[skew] All skewed frames injected.")
    print("       Participants should drop them as 'outside acceptance window'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
