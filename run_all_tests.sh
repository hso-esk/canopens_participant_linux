#!/usr/bin/env bash
#
# Comprehensive Test Suite Runner for SPsec CANopen Participant & Configurator
#
# Runs all available test suites:
#   1. CTest Unit Tests (wolfSSL backend)
#   2. CTest Unit Tests (mbedTLS backend)
#   3. CTest Unit Tests (12-byte salt configuration)
#   4. Wireshark SPsec Dissector field extraction (tshark)
#   5. Python Configurator Unit & Integration Tests (pytest)
#   6. Cross-Mode Protocol Isolation (AEAD vs. Auth-Only)
#   7. E2E Rekey & Seed Key Lifecycle
#   8. E2E Factory Reset & Recovery
#   9. E2E Code Update (Segmented OTA transfer)
#  10. E2E Dynamic Join (Onboarding under traffic)
#  11. E2E Dynamic Leave (Revocation and key rotation)
#  12. E2E Provision Discovered Devices
#  13. E2E Sync-Role Restart Recovery
#  14. E2E Fault Injection & Negative Security Tests
#  15. E2E Power-Cut Mid-Write Persistence Simulation
#  16. E2E Multi-Algorithm Stability (AES-GCM, ChaCha20, ASCON-128)
#  17. E2E Algorithm & Backend Full Matrix (run_e2e_matrix.sh)
#  18. 10-Node Cluster Communication Stability
#  19. 10-Node Dynamic Join Under Active Load
#  20. 10-Node TSA Crash & Re-convergence
#  21. 20-Node High-Density Mesh Scaling
#  22. GUI Automated Lifecycle Test
#  23. Embedded Baremetal Cross-Compile Smoke Test (if arm-none-eabi-gcc is present)
#
# Usage:
#   ./run_all_tests.sh [options]
#
# Options:
#   --build       Reconfigure and rebuild all binary variants before testing
#   --quick       Run quicker versions of long tests (fewer iterations/shorter durations)
#   --unit-only   Run only CTest unit tests and Python configurator pytest
#   -h, --help    Show this help message

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

# Color support
if [[ -t 1 ]]; then
  GREEN="\033[0;32m"
  RED="\033[0;31m"
  YELLOW="\033[0;33m"
  BLUE="\033[0;34m"
  BOLD="\033[1m"
  RESET="\033[0m"
else
  GREEN="" RED="" YELLOW="" BLUE="" BOLD="" RESET=""
fi

AUTO_BUILD=0
QUICK=0
UNIT_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)     AUTO_BUILD=1; shift ;;
    --quick)     QUICK=1; shift ;;
    --unit-only) UNIT_ONLY=1; shift ;;
    -h|--help)
      grep '^#' "$0" | cut -c 3-
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

TEST_NAMES=()
TEST_RESULTS=()
TEST_DURATIONS=()
TEST_DETAILS=()

START_ALL=$(date +%s)

record_result() {
  local name="$1"
  local result="$2"
  local duration="$3"
  local details="${4:-}"

  TEST_NAMES+=("$name")
  TEST_RESULTS+=("$result")
  TEST_DURATIONS+=("${duration}s")
  TEST_DETAILS+=("$details")

  ((TOTAL_TESTS++))
  case "$result" in
    PASS)
      ((PASSED_TESTS++))
      echo -e "  -> ${GREEN}${BOLD}PASS${RESET} (${duration}s)"
      ;;
    FAIL)
      ((FAILED_TESTS++))
      echo -e "  -> ${RED}${BOLD}FAIL${RESET} (${duration}s)"
      ;;
    SKIP)
      ((SKIPPED_TESTS++))
      echo -e "  -> ${YELLOW}${BOLD}SKIP${RESET} ($details)"
      ;;
  esac
}

run_test_step() {
  local name="$1"
  local cmd="$2"

  echo
  echo -e "${BLUE}${BOLD}[RUN]${RESET} $name"
  local t0 t1 duration rc
  t0=$(date +%s)

  if eval "$cmd"; then
    t1=$(date +%s)
    duration=$((t1 - t0))
    record_result "$name" "PASS" "$duration"
  else
    rc=$?
    t1=$(date +%s)
    duration=$((t1 - t0))
    record_result "$name" "FAIL" "$duration" "exit code $rc"
  fi
}

skip_test_step() {
  local name="$1"
  local reason="$2"
  echo
  echo -e "${BLUE}${BOLD}[SKIP]${RESET} $name - $reason"
  record_result "$name" "SKIP" "0" "$reason"
}

# --- 1. Environment & Pre-requisite Checks -------------------------------------
echo -e "${BOLD}================================================================${RESET}"
echo -e "${BOLD}          CANopenS SPsec Comprehensive Test Suite Runner        ${RESET}"
echo -e "${BOLD}================================================================${RESET}"

# Build directories setup
BUILD_WOLFSSL="$REPO_ROOT/build"
BUILD_MBEDTLS="$REPO_ROOT/build_mbedtls"
BUILD_SALT12="$REPO_ROOT/build_salt12"

ensure_build() {
  local dir="$1"
  local cmake_args="$2"
  if [[ $AUTO_BUILD -eq 1 || ! -f "$dir/spsec_participant" ]]; then
    echo -e "${BLUE}Configuring and building $dir...${RESET}"
    cmake -B "$dir" -S "$REPO_ROOT" $cmake_args || return 1
    cmake --build "$dir" -j"$(nproc 2>/dev/null || echo 2)" || return 1
  fi
  return 0
}

# Auto-build or verify builds
if ! ensure_build "$BUILD_WOLFSSL" "-DSPSEC_CRYPTO_BACKEND=wolfssl"; then
  echo -e "${RED}Failed to build wolfSSL participant in $BUILD_WOLFSSL${RESET}" >&2
  exit 1
fi
if [[ $UNIT_ONLY -eq 0 ]]; then
  if ! ensure_build "$BUILD_MBEDTLS" "-DSPSEC_CRYPTO_BACKEND=mbedtls"; then
    echo -e "${RED}Failed to build mbedTLS participant in $BUILD_MBEDTLS${RESET}" >&2
    exit 1
  fi
  if ! ensure_build "$BUILD_SALT12" "-DSPSEC_SALT_LEN=12"; then
    echo -e "${RED}Failed to build 12-byte salt participant in $BUILD_SALT12${RESET}" >&2
    exit 1
  fi
fi

# Ensure virtual CAN interfaces (vcan0..vcan20) if non-unit tests are running
if [[ $UNIT_ONLY -eq 0 ]]; then
  if ! ip link show vcan0 &>/dev/null || ! ip link show vcan20 &>/dev/null; then
    echo -e "${YELLOW}Virtual CAN interfaces missing (need vcan0..vcan20). Running setup_vcan.sh...${RESET}"
    if sudo -n true 2>/dev/null; then
      sudo "$REPO_ROOT/setup_vcan.sh" 20
    else
      echo -e "${YELLOW}Notice: sudo password may be prompted to set up vcan interfaces:${RESET}"
      sudo "$REPO_ROOT/setup_vcan.sh" 20 || echo "Warning: vcan setup script failed"
    fi
  fi
fi

# --- 2. CTest Unit Tests -------------------------------------------------------
echo
echo -e "${BOLD}--- Phase 1: CTest C Unit Tests ---${RESET}"

run_test_step "CTest (wolfSSL backend, default)" \
  "ctest --test-dir '$BUILD_WOLFSSL' --output-on-failure"

if [[ -d "$BUILD_MBEDTLS" ]]; then
  run_test_step "CTest (mbedTLS backend)" \
    "ctest --test-dir '$BUILD_MBEDTLS' --output-on-failure"
else
  skip_test_step "CTest (mbedTLS backend)" "$BUILD_MBEDTLS not found"
fi

if [[ -d "$BUILD_SALT12" ]]; then
  run_test_step "CTest (12-byte salt configuration)" \
    "ctest --test-dir '$BUILD_SALT12' --output-on-failure"
else
  skip_test_step "CTest (12-byte salt configuration)" "$BUILD_SALT12 not found"
fi

# --- 3. Wireshark Dissector Test ----------------------------------------------
if command -v tshark &>/dev/null; then
  run_test_step "Wireshark Protocol Dissector (tshark)" \
    "'$REPO_ROOT/tests/run_wireshark_dissector_test.sh'"
else
  skip_test_step "Wireshark Protocol Dissector" "tshark not installed"
fi

# --- 4. Python Configurator Unit Tests ----------------------------------------
echo
echo -e "${BOLD}--- Phase 2: Python Configurator Test Suite (pytest) ---${RESET}"
if command -v pytest &>/dev/null; then
  run_test_step "Python Configurator (pytest unit + functional)" \
    "PYTHONPATH='$REPO_ROOT/canopens_configurator_python/src' pytest '$REPO_ROOT/canopens_configurator_python/tests'"
else
  skip_test_step "Python Configurator pytest" "pytest command not found"
fi

if [[ $UNIT_ONLY -eq 1 ]]; then
  echo
  echo "(--unit-only requested; skipping end-to-end multi-node integration tests)"
else
  # --- 5. E2E Single-Bus Feature Tests ----------------------------------------
  echo
  echo -e "${BOLD}--- Phase 3: End-to-End Integration & Security Tests ---${RESET}"

  run_test_step "Cross-Mode Protocol Isolation (AEAD vs. Auth-Only)" \
    "python3 '$REPO_ROOT/tests/run_cross_mode_isolation.py' --duration 5"

  run_test_step "E2E Dynamic Join (Onboarding follower under active load)" \
    "'$REPO_ROOT/tests/run_e2e_dynamic_join.sh'"

  run_test_step "E2E Dynamic Leave (Node revocation & rekey)" \
    "'$REPO_ROOT/tests/run_e2e_dynamic_leave.sh'"

  run_test_step "E2E Rekey Seed (Integrator-managed seed rotation)" \
    "'$REPO_ROOT/tests/run_e2e_rekey_seed.sh'"

  run_test_step "E2E Factory Reset (0x7F reset & persistence wipe)" \
    "'$REPO_ROOT/tests/run_e2e_factory_reset.sh'"

  run_test_step "E2E Code Update (4 KB segmented firmware transfer)" \
    "'$REPO_ROOT/tests/run_e2e_code_update.sh'"

  run_test_step "E2E Provision Discovered Devices" \
    "'$REPO_ROOT/tests/run_e2e_provision_discovered.sh'"

  run_test_step "E2E Sync-Role Restart Recovery" \
    "'$REPO_ROOT/tests/run_e2e_sync_restart.sh'"

  run_test_step "E2E Fault Injection & Negative Security Tests" \
    "'$REPO_ROOT/tests/run_e2e_negative.sh'"

  power_iters=20
  [[ $QUICK -eq 1 ]] && power_iters=5
  run_test_step "E2E Power-Cut Mid-Write Simulation ($power_iters iters)" \
    "'$REPO_ROOT/tests/run_e2e_power_cut.sh' --iterations $power_iters"

  run_test_step "E2E Multi-Algorithm Stability (AES-GCM / ChaCha20 / ASCON)" \
    "'$REPO_ROOT/tests/run_e2e_multi_algo_stability.sh'"

  run_test_step "E2E Algorithm & Backend Full Matrix (run_e2e_matrix.sh)" \
    "'$REPO_ROOT/tests/run_e2e_matrix.sh'"

  run_test_step "Heterogeneous Crypto Backend Interoperability" \
    "'$REPO_ROOT/tests/run_e2e_backend_interop.sh' --duration 8"

  run_test_step "GUI Automated Full Lifecycle" \
    "'$REPO_ROOT/tests/run_e2e_gui.sh'"

  # --- 6. Multi-Node Cluster Tests ---------------------------------------------
  echo
  echo -e "${BOLD}--- Phase 4: Multi-Node Cluster & Scalability Tests ---${RESET}"

  stab_duration=10
  [[ $QUICK -eq 1 ]] && stab_duration=5
  run_test_step "10-Node Cluster Communication Stability (${stab_duration}s)" \
    "'$REPO_ROOT/tests/run_e2e_stability_10nodes.sh' --duration $stab_duration --warmup 3"

  run_test_step "10-Node Dynamic Join Under Active Load" \
    "'$REPO_ROOT/tests/run_e2e_dynamic_join_10nodes.sh' --duration 10"

  crash_duration=30
  run_test_step "10-Node TSA Crash & Recovery (${crash_duration}s)" \
    "'$REPO_ROOT/tests/run_e2e_tsa_crash_10nodes.sh' --duration $crash_duration"

  scale_duration=10
  [[ $QUICK -eq 1 ]] && scale_duration=5
  run_test_step "20-Node High-Density Mesh Scaling (${scale_duration}s)" \
    "'$REPO_ROOT/tests/run_e2e_scale_20nodes.sh' --duration $scale_duration"

  # --- 7. Embedded Cross-Compile (Optional) ------------------------------------
  if command -v arm-none-eabi-gcc &>/dev/null; then
    run_test_step "Baremetal ARM Cortex-M33 (LPC55S16) Cross-Compile" \
      "'$REPO_ROOT/tests/run_cross_compile_lpc55s16.sh'"
  else
    skip_test_step "ARM LPC55S16 Cross-Compile" "arm-none-eabi-gcc not installed"
  fi
fi

# --- Summary Report -----------------------------------------------------------
END_ALL=$(date +%s)
TOTAL_TIME=$((END_ALL - START_ALL))

echo
echo -e "${BOLD}================================================================${RESET}"
echo -e "${BOLD}                       TEST SUITE SUMMARY                       ${RESET}"
echo -e "${BOLD}================================================================${RESET}"
printf "%-62s %-8s %-10s %s\n" "Test Suite" "Result" "Duration" "Details"
echo "------------------------------------------------------------------------------------------------"

for i in "${!TEST_NAMES[@]}"; do
  name="${TEST_NAMES[$i]}"
  result="${TEST_RESULTS[$i]}"
  dur="${TEST_DURATIONS[$i]}"
  details="${TEST_DETAILS[$i]}"

  case "$result" in
    PASS)
      printf "%-62s ${GREEN}%-8s${RESET} %-10s %s\n" "$name" "$result" "$dur" "$details"
      ;;
    FAIL)
      printf "%-62s ${RED}%-8s${RESET} %-10s %s\n" "$name" "$result" "$dur" "$details"
      ;;
    SKIP)
      printf "%-62s ${YELLOW}%-8s${RESET} %-10s %s\n" "$name" "$result" "$dur" "$details"
      ;;
  esac
done

echo "------------------------------------------------------------------------------------------------"
echo -e "Total: ${BOLD}$TOTAL_TESTS${RESET} suites | Passed: ${GREEN}${BOLD}$PASSED_TESTS${RESET} | Failed: ${RED}${BOLD}$FAILED_TESTS${RESET} | Skipped: ${YELLOW}${BOLD}$SKIPPED_TESTS${RESET} | Time: ${TOTAL_TIME}s"

if [[ $FAILED_TESTS -eq 0 ]]; then
  echo
  echo -e "${GREEN}${BOLD}✓ ALL TEST SUITES PASSED!${RESET}"
  exit 0
else
  echo
  echo -e "${RED}${BOLD}✗ SOME TEST SUITES FAILED — PLEASE REVIEW THE LOGS ABOVE.${RESET}"
  exit 1
fi
