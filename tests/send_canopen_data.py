# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

import argparse
import time
import can
from datetime import datetime

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def frame(cob_id, data_bytes):
    return {"cob_id": cob_id, "data": bytes(data_bytes)}

def build_frames(node_id):
    # CANopen example frames (classic CAN, 11-bit IDs, <= 8 data bytes) [web:37]
    return [
        # NMT: COB-ID 0x000, 2 bytes: command, node-id (0 = broadcast) [web:16]
        frame(0x000, [0x82, node_id]),   # Reset communication [web:16]
        frame(0x000, [0x80, node_id]),   # Enter pre-operational [web:16]
        frame(0x000, [0x01, node_id]),   # Enter operational (start remote node) [web:16]

        # SYNC: COB-ID 0x080, often 0 bytes [web:37]
        frame(0x080, []),

        # SDO download request: COB-ID 0x600 + node-id, 8 bytes [web:33][web:37]
        # Example shown by Beckhoff uses 0x22 for a 4-byte write; Index0/Index1/SubIdx then Data0..Data3. [web:33]
        frame(0x600 + node_id, [0x22, 0x00, 0x20, 0x00, 0x78, 0x56, 0x34, 0x12]),  # write 0x12345678 to 0x2000:00 [web:33]

        # SDO expedited 1-byte download is commonly 0x2F (1 byte), then index/sub, then data padded. [web:31]
        frame(0x600 + node_id, [0x2F, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00]),  # write 0x01 to 0x2000:00 [web:31]

        # Default PDO COB-IDs (examples): TPDO1 = 0x180+node, RPDO1 = 0x200+node [web:37]
        frame(0x180 + node_id, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        frame(0x200 + node_id, [0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00]),
    ]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--channel", default="vcan1")
    p.add_argument("--node-id", type=lambda x: int(x, 0), default=0x01)
    p.add_argument("--gap", type=float, default=0.05, help="Delay between frames, seconds")
    p.add_argument("--repeat", type=int, default=1, help="Repeat the 8-frame sequence N times")
    p.add_argument("--out", default=None, help="Write '<arb_id_hex> <data_hex>' per sent frame to this file")
    args = p.parse_args()

    frames = build_frames(args.node_id)
    out_file = open(args.out, "w") if args.out else None
    sent_idx = 0
    total_frames = len(frames) * args.repeat
    try:
        with can.interface.Bus(channel=args.channel, interface="socketcan", bitrate=500000, data_bitrate=2000000, fd=True) as bus:
            for rep in range(args.repeat):
                for f in frames:
                    sent_idx += 1
                    msg = can.Message(
                        arbitration_id=f["cob_id"],
                        data=f["data"],
                        is_extended_id=False,   # CANopen defaults are 11-bit IDs [web:37]
                        is_fd=True
                    )
                    print(f"[{ts()}] {sent_idx:02d}/{total_frames} COB-ID=0x{f['cob_id']:03X} data={msg.data.hex(' ')}")
                    bus.send(msg)
                    if out_file:
                        out_file.write(f"{f['cob_id']:x} {f['data'].hex()}\n")
                        out_file.flush()
                    time.sleep(args.gap)
    finally:
        if out_file:
            out_file.close()

if __name__ == "__main__":
    main()
