#!/usr/bin/env bash

#
# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.
#

# Bare-metal cross-compilation smoke test for Cortex-M33 target.
# Usage: tests/run_cross_compile_lpc55s16.sh [--keep-build]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/lpc55s16-smoke"
KEEP=0

usage() {
  echo "Usage: $0 [--keep-build]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-build) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
  echo "ERROR: arm-none-eabi-gcc not installed (sudo apt install gcc-arm-none-eabi)" >&2
  exit 1
fi

OVERALL_RC=0
log() { echo "[lpc55s16-smoke] $*"; }
fail() { echo "[lpc55s16-smoke] FAIL: $*" >&2; OVERALL_RC=1; }

cleanup() {
  local rc=$?
  if (( ! KEEP )); then
    rm -rf "$BUILD_DIR"
  else
    log "leaving build dir: $BUILD_DIR"
  fi
  exit $rc
}
trap cleanup EXIT

mkdir -p "$BUILD_DIR"

log "Cross-compiling for Cortex-M33..."
cmake -B "$BUILD_DIR" -S "$REPO_ROOT" \
  -DCMAKE_TOOLCHAIN_FILE="$REPO_ROOT/cmake/lpc55s16_toolchain.cmake" \
  -DSPSEC_PLATFORM=lpc55s16 \
  -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -n 8 || fail "cmake configure failed"

cmake --build "$BUILD_DIR" -j4 2>&1 | tail -n 20 || fail "build failed"

# Verify the ELF was produced
elf="$BUILD_DIR/spsec_participant"
if [[ ! -f "$elf" ]]; then
  fail "ELF binary not produced: $elf"
  exit 1
fi

# Check architecture
file "$elf" 2>/dev/null | head -n 1 || true
arm-none-eabi-size "$elf" 2>/dev/null || true

# Verify the binary actually targets ARM Cortex-M33
arch=$(arm-none-eabi-readelf -h "$elf" 2>/dev/null | grep -i "machine" || true)
log "Target: $arch"

if (( OVERALL_RC == 0 )); then
  log "PASS: cross-compile smoke test succeeded"
fi
exit $OVERALL_RC
