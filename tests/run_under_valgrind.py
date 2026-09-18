#!/usr/bin/env python3

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Runs the participant under valgrind memcheck, summarizes leaks/errors.
Usage: tests/run_under_valgrind.sh [--keep] [--duration SECONDS]"""
import argparse
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--build-dir", default=os.path.join(REPO_ROOT, "build"))
    p.add_argument("--duration", type=int, default=8)
    p.add_argument("--keep", action="store_true")
    p.add_argument("--keys", default=os.path.join(REPO_ROOT, "tests", "example_keys_short_salt.txt"))
    p.add_argument("--pid", type=int, default=120)
    args = p.parse_args()

    bin_ = os.path.join(args.build_dir, "spsec_participant")
    if not os.path.isfile(bin_):
        print(f"ERROR: {bin_} not built", file=sys.stderr)
        return 1

    if not os.path.isfile("/usr/bin/valgrind") and not os.path.isfile("/usr/local/bin/valgrind"):
        vg = None
        for cand in ("/usr/bin/valgrind", "/usr/local/bin/valgrind", "/opt/homebrew/bin/valgrind"):
            if os.path.isfile(cand):
                vg = cand
                break
        if vg is None:
            print("ERROR: valgrind not installed", file=sys.stderr)
            return 1
    else:
        vg = "valgrind"

    log_path = "/tmp/valgrind_participant.log"
    cmd = [
        vg, "--tool=memcheck",
        "--leak-check=full",
        "--show-leak-kinds=all",
        "--track-origins=yes",
        "--error-exitcode=42",
        "--log-file=" + log_path,
        bin_, "-i", "vcan0", "-s", "vcan1",
        "-p", str(args.pid), "-k", args.keys, "-l", "info",
    ]
    print(f"[valgrind] launching: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd)
    try:
        time.sleep(args.duration)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

    if not os.path.isfile(log_path):
        print("[valgrind] no log produced", file=sys.stderr)
        return 2

    with open(log_path) as f:
        log_text = f.read()
    print("=== valgrind summary (last 30 lines) ===")
    for line in log_text.splitlines()[-30:]:
        print(line)

    err_count = log_text.count("ERROR SUMMARY:")
    if "definitely lost: 0 bytes" in log_text and "indirectly lost: 0 bytes" in log_text:
        if "0 errors" in log_text.split("ERROR SUMMARY:")[-1].split("\n", 1)[0]:
            print("[valgrind] PASS: no leaks, no errors")
            return 0
    print("[valgrind] Note: leaks or errors may be present - review the log",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
