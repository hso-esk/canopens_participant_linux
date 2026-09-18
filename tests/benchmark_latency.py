# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""
Measures end-to-end latency: plaintext in on vcan1, encrypted, out on vcan2.
"""

import argparse
import json
import statistics
import struct
import sys
import threading
import time
import can


def run_latency_benchmark(tx_channel="vcan1", rx_channel="vcan2", count=100, gap=0.01, timeout=5.0):
    send_times = {}
    recv_times = {}
    latencies_us = []
    stop_event = threading.Event()

    def rx_worker():
        try:
            with can.interface.Bus(channel=rx_channel, interface="socketcan", fd=True) as rx_bus:
                while not stop_event.is_set():
                    msg = rx_bus.recv(timeout=0.1)
                    if msg is None:
                        continue
                    now_ns = time.perf_counter_ns()
                    if (msg.arbitration_id & 0x1FFFFFFF) == 0x181 and len(msg.data) >= 8:
                        seq = struct.unpack(">I", msg.data[:4])[0]
                        if seq in send_times and seq not in recv_times:
                            recv_times[seq] = now_ns
                            latencies_us.append((now_ns - send_times[seq]) / 1000.0)
                            if len(latencies_us) >= count:
                                break
        except Exception as e:
            print(f"Error in rx_worker: {e}")

    rx_thread = threading.Thread(target=rx_worker, daemon=True)
    rx_thread.start()

    # Allow listener to attach
    time.sleep(0.05)

    with can.interface.Bus(channel=tx_channel, interface="socketcan", fd=True) as tx_bus:
        for seq in range(count):
            now_ns = time.perf_counter_ns()
            send_times[seq] = now_ns
            # 4-byte sequence number + 4-byte dummy payload
            data = struct.pack(">II", seq, 0x12345678)
            msg = can.Message(arbitration_id=0x181, data=data, is_extended_id=False, is_fd=True)
            tx_bus.send(msg)
            time.sleep(gap)

    # Wait for remaining messages
    deadline = time.time() + timeout
    while time.time() < deadline and len(latencies_us) < count:
        time.sleep(0.01)

    stop_event.set()
    rx_thread.join(timeout=1.0)

    if not latencies_us:
        return {"error": "No messages received", "count": 0}

    latencies_sorted = sorted(latencies_us)
    p50_idx = int(len(latencies_sorted) * 0.50)
    p95_idx = int(len(latencies_sorted) * 0.95)
    p99_idx = int(len(latencies_sorted) * 0.99)

    stats = {
        "sent": count,
        "received": len(latencies_us),
        "loss_rate": (count - len(latencies_us)) / count,
        "min_us": round(min(latencies_us), 1),
        "mean_us": round(statistics.mean(latencies_us), 1),
        "median_us": round(latencies_sorted[p50_idx], 1),
        "p95_us": round(latencies_sorted[min(p95_idx, len(latencies_sorted) - 1)], 1),
        "p99_us": round(latencies_sorted[min(p99_idx, len(latencies_sorted) - 1)], 1),
        "max_us": round(max(latencies_us), 1),
        "stdev_us": round(statistics.stdev(latencies_us), 1) if len(latencies_us) > 1 else 0.0,
    }
    return stats


def main():
    p = argparse.ArgumentParser(description="CANopenS E2E Latency Benchmark")
    p.add_argument("--tx-channel", default="vcan1")
    p.add_argument("--rx-channel", default="vcan2")
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--gap", type=float, default=0.005)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    stats = run_latency_benchmark(
        tx_channel=args.tx_channel,
        rx_channel=args.rx_channel,
        count=args.count,
        gap=args.gap,
        timeout=args.timeout,
    )

    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        if "error" in stats:
            print(f"FAILED: {stats['error']}")
        else:
            print(f"Results: {stats['received']}/{stats['sent']} frames received")
            print(f"  Min:    {stats['min_us']} us")
            print(f"  Mean:   {stats['mean_us']} us")
            print(f"  Median: {stats['median_us']} us")
            print(f"  P95:    {stats['p95_us']} us")
            print(f"  P99:    {stats['p99_us']} us")
            print(f"  Max:    {stats['max_us']} us")
            print(f"  Stdev:  {stats['stdev_us']} us")

    if "error" in stats:
        sys.exit(1)


if __name__ == "__main__":
    main()
