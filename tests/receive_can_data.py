# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

import argparse
import can
from datetime import datetime


def receive_can_message(channel="vcan2", count=3, timeout=120, out_path=None, standard_only=False):
    out_file = open(out_path, "w") if out_path else None
    try:
        # Initialize CAN bus with socketcan interface
        with can.interface.Bus(
            channel=channel,
            interface='socketcan',
            bitrate=500000,         # Arbitration bitrate
            data_bitrate=2000000,   # Data bitrate for FD
            fd=True                 # Enable CAN FD
        ) as bus:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4]}] Waiting for CAN message...")

            received = 0
            while received < count:
                message = bus.recv(timeout=timeout)
                if message:
                    if standard_only and message.arbitration_id > 0x7FF:
                        continue
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4]}] Received message {received}: data: {message.data}")
                    if out_file:
                        out_file.write(f"{message.arbitration_id:x} {message.data.hex()}\n")
                        out_file.flush()
                    received += 1
                else:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4]}] No message received within timeout period")
                    return None

    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4]}] An error occurred: {e}")
    finally:
        if out_file:
            out_file.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--channel", default="vcan2")
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("--out", default=None, help="Write '<arb_id_hex> <data_hex>' per received frame to this file")
    p.add_argument("--standard-only", action="store_true", help="Capture only 11-bit standard CANopen frames")
    args = p.parse_args()
    receive_can_message(args.channel, args.count, args.timeout, args.out, standard_only=args.standard_only)
