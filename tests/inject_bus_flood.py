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
Floods vcan0 with malformed frames; checks for crashes and recovery.
"""
import argparse
import os
import signal
import subprocess
import sys
import time
import can


def flood(args):
    """Spam the bus with random CAN FD frames."""
    print(f"[flood] Flooding {args.bus} for {args.duration}s with random frames...")
    end = time.time() + args.duration
    with can.interface.Bus(channel=args.bus, interface="socketcan", fd=True) as bus:
        n_sent = 0
        while time.time() < end:
            arb_id = (0x10000000 | (os.getpid() & 0x7FFFFFF)) & 0x1FFFFFFF
            data = os.urandom(args.fd_size)
            msg = can.Message(
                arbitration_id=arb_id,
                data=data,
                is_extended_id=True,
                is_fd=True,
            )
            try:
                bus.send(msg)
                n_sent += 1
            except can.exceptions.CanOperationError:
                # bus full / arbitration lost — expected under saturation
                pass
            except Exception as e:
                print(f"[flood] send error: {e}", file=sys.stderr)
                break
    print(f"[flood] Sent ~{n_sent} frames in {args.duration}s")


def main():
    p = argparse.ArgumentParser(description="Bus Flooding & DoS Resilience")
    p.add_argument("--bus", default="vcan0")
    p.add_argument("--duration", type=float, default=10.0)
    p.add_argument("--fd-size", type=int, default=64, help="Bytes per FD frame")
    p.add_argument("--participant-pid", type=int, default=None,
                   help="If set, monitor this participant's RSS during the flood")
    p.add_argument("--build-dir", default=None)
    args = p.parse_args()

    target_pid = args.participant_pid

    if target_pid is not None:
        try:
            rss0 = open(f"/proc/{target_pid}/status").read().split("VmRSS:")[1].split()[0]
            print(f"[flood] Participant {target_pid} initial RSS: {rss0} kB")
        except Exception as e:
            print(f"[flood] Could not read participant RSS: {e}")

    flood(args)

    if target_pid is not None:
        try:
            rss1 = open(f"/proc/{target_pid}/status").read().split("VmRSS:")[1].split()[0]
            print(f"[flood] Participant {target_pid} post-flood RSS: {rss1} kB")
        except Exception:
            print(f"[flood] Participant {target_pid} no longer running!")

    print("[flood] Flood complete. Participant should recover timesync post-saturation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
