# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

import can
from datetime import datetime

# Create a CAN message with the specified bytearray
messages = [
    bytearray(b'\x02\xdd\xd2\xae\xfe\xf1j\xe1\xdd\xe7P\xben\x1f'),
    bytearray(b'\x02\xdd\xd2\xae\xfe\xf1j\xe1\xdd\xe7P\xben\x1f\xba'),
    bytearray(b'\x02\xdd\xd2\xae\xfe\xf1j\xe1\xdd\xe7P\xben\x1f\xba\xad'),
]


for i, data in enumerate(messages):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4]}] Sending message {i}: data: {data}")
    message = can.Message(arbitration_id=0x123, data=list(data), is_extended_id=True, is_fd=True)

    # Send the message over a CAN bus
    try:
        with can.interface.Bus(
                channel='vcan1',  # Replace with your channel
                interface='socketcan',
                bitrate=500000,         # Arbitration bitrate
                data_bitrate=2000000,   # Data bitrate for FD
                fd=True                 # Enable CAN FD
            ) as bus:
            bus.send(message)
            # print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4]}] Message sent successfully")
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4]}] An error occurred: {e}")
