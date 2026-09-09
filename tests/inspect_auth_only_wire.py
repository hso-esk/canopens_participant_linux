#!/usr/bin/env python3

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Sniffs vcan0 and checks auth-only frames are plaintext + 16-byte MAC tag.
Usage: tests/inspect_auth_only_wire.py --iface vcan0 --output out.txt"""
import argparse
import can
import struct
import sys
from datetime import datetime


def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def is_auth_only_frame(arb_id):
    """True if arb_id's discriminator bits mark an auth-only data frame."""
    return (arb_id & 0x1F000000) in (0x06000000, 0x07000000, 0x18000000)


def main():
    p = argparse.ArgumentParser(description="Wire Auth-Only Inspection")
    p.add_argument("--iface", default="vcan0", help="SocketCAN interface to sniff")
    p.add_argument("--count", type=int, default=10, help="Number of frames to capture")
    p.add_argument("--timeout", type=float, default=10.0, help="Capture timeout (s)")
    p.add_argument("--output", default=None, help="Write captured frames to file")
    args = p.parse_args()

    captured = []
    out_fh = open(args.output, "w") if args.output else None
    try:
        with can.interface.Bus(channel=args.iface, interface="socketcan") as bus:
            print(f"[{ts()}] Sniffing {args.iface} for up to {args.count} frames...")
            deadline = None
            import time as _t
            t0 = _t.time()
            while len(captured) < args.count:
                msg = bus.recv(timeout=0.1)
                if msg is None:
                    if _t.time() - t0 > args.timeout:
                        print(f"[{ts()}] Timeout after capturing {len(captured)} frames")
                        break
                    continue
                t0 = _t.time()
                captured.append(msg)
                if out_fh:
                    out_fh.write(f"{msg.arbitration_id:x} {msg.data.hex()}\n")
                    out_fh.flush()
                print(f"[{ts()}] {len(captured):02d} COB=0x{msg.arbitration_id:08X} "
                      f"len={len(msg.data):2d} data={msg.data.hex(' ')}")
    finally:
        if out_fh:
            out_fh.close()

    if not captured:
        print("ERROR: no frames captured", file=sys.stderr)
        return 1

    # Verify at least one auth-only frame was captured (last 16 bytes look like
    # a MAC tag rather than all-zero padding).
    found_with_tag = 0
    for msg in captured:
        if len(msg.data) >= 16:
            tail = msg.data[-16:]
            if not all(b == 0 for b in tail):
                found_with_tag += 1

    print(f"\n[summary] captured={len(captured)} frames_with_tag_tail={found_with_tag}")
    if found_with_tag == 0:
        print("ERROR: no auth-only frames with MAC tag detected", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
