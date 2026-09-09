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
Flips bits in valid frames (ID/AAD/tag) and replays them; all must be rejected.
"""
import argparse
import os
import random
import sys
import time
import can


def flip_bit(data, position):
    byte_idx = position // 8
    bit_idx = position % 8
    if byte_idx >= len(data):
        return bytearray(data)
    out = bytearray(data)
    out[byte_idx] ^= (1 << bit_idx)
    return bytes(out)


def main():
    p = argparse.ArgumentParser(description="Live Bus Bit-Flipping Fuzzer")
    p.add_argument("--bus", default="vcan0")
    p.add_argument("--sniff-time", type=float, default=2.0)
    p.add_argument("--flips", type=int, default=20)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    rng = random.Random(args.seed)
    print(f"[flip] Recording baseline frames on {args.bus} for {args.sniff_time}s...")
    recorded = []
    with can.interface.Bus(channel=args.bus, interface="socketcan") as bus:
        deadline = time.time() + args.sniff_time
        while time.time() < deadline and len(recorded) < 3:
            msg = bus.recv(timeout=0.1)
            if msg is None:
                continue
            if msg.arbitration_id > 0x7FF and len(msg.data) > 0:
                recorded.append(msg)

    if not recorded:
        print("[flip] No frames recorded; aborting", file=sys.stderr)
        return 0

    print(f"[flip] {len(recorded)} baseline frames; injecting {args.flips} bit-flipped variants...")
    with can.interface.Bus(channel=args.bus, interface="socketcan") as bus:
        for base in recorded:
            for _ in range(args.flips):
                tampered_id = base.arbitration_id ^ (1 << rng.randint(0, 28))
                if rng.random() < 0.5:
                    tampered_id ^= 0x08000000  # also flip a discriminator bit
                pos = rng.randint(0, max(1, len(base.data) * 8 - 1))
                tampered_data = flip_bit(base.data, pos)
                msg = can.Message(
                    arbitration_id=tampered_id,
                    data=tampered_data,
                    is_extended_id=(tampered_id > 0x7FF),
                    is_fd=(len(tampered_data) > 8),
                )
                try:
                    bus.send(msg)
                except Exception as e:
                    print(f"[flip] send error: {e}")
                time.sleep(0.005)

    print("[flip] All tampered frames injected. Participants should reject every one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
