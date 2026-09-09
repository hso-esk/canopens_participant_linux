#! /bin/bash

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.


# Sets up vcan0 through vcanN (default: vcan10).
# Must be run as root (sudo). Safe to re-run (idempotent).

set -e

MAX_VCAN="${1:-${NUM_VCAN:-10}}"
if ! [[ "$MAX_VCAN" =~ ^[0-9]+$ ]]; then
    echo "Usage: $0 [highest-vcan-index]" >&2
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "$0: must be run as root (sudo $0 $*)" >&2
    exit 1
fi

# Load the vcan kernel module
modprobe vcan

# Create and configure the virtual CAN interfaces
for ((i = 0; i <= MAX_VCAN; ++i)); do
    # Create the interface only if it does not already exist
    if ! ip link show vcan$i &>/dev/null; then
        ip link add dev vcan$i type vcan
    fi

    # Set MTU to 72 to support CAN FD message sizes (must be down to change MTU)
    ip link set vcan$i mtu 72

    # Bring the interface online
    ip link set up vcan$i
done

# Check and show the configuration
ip -br link show type vcan
