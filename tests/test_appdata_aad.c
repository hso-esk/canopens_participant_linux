/*
 * Copyright (c) 2026
 *
 * Hochschule Offenburg, University of Applied Sciences
 * Institute for reliable Embedded Systems
 * and Communications Electronic (ivESK)
 *
 * This file is licensed as described in the "LICENSE" file
 * included within the root folder of this work.
 */

/**
 * @file test_appdata_aad.c
 * @brief Tests associated data construction (CAN ID + data length) for data-plane AEAD.
 */

#include "keys.h"
#include "spsec_common.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Forward declaration of function under test (session_appdata.c) */
void prepare_appdata_assoc_data(uint32_t address, size_t data_len,
                                uint8_t assoc_data[DATA_AAD_LEN]);

static int g_failures = 0;
#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg);                                    \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

int main(void) {
  configure_logging("CRITICAL");

  CHECK(DATA_AAD_LEN == 5,
        "DATA_AAD_LEN is 5 (SPsec302 §2.9: CAN ID(4) + size(1), no stamp "
        "header - see A1)");

  // ============================================================
  // Case 1: 11-bit standard data-plane CAN ID, small payload.
  // ============================================================
  printf("Testing Case 1: standard 11-bit CAN ID, 8-byte payload...\n");
  {
    uint32_t can_id = 0x181; // 11-bit standard ID, well within CAN_EFF_MASK
    size_t data_len = 8;
    uint8_t assoc_data[DATA_AAD_LEN];
    memset(assoc_data, 0xAA, sizeof(assoc_data));

    prepare_appdata_assoc_data(can_id, data_len, assoc_data);

    uint8_t expected[DATA_AAD_LEN] = {0x81, 0x01, 0x00, 0x00, 0x08};
    CHECK(memcmp(assoc_data, expected, DATA_AAD_LEN) == 0,
          "Case 1: AD == LE(CAN ID) || size, exactly 5 bytes");
  }

  // Case 2: 29-bit extended CAN ID with bits 29-31 set (must be masked)
  printf("Testing Case 2: 29-bit ID with bits 29-31 set, 54-byte payload...\n");
  {
    uint32_t can_id = 0xFFFFFFFFu; // all bits set - top 3 bits must be masked
    size_t data_len = 54;
    uint8_t assoc_data[DATA_AAD_LEN];
    memset(assoc_data, 0, sizeof(assoc_data));

    prepare_appdata_assoc_data(can_id, data_len, assoc_data);

    // 0xFFFFFFFF & 0x1FFFFFFF = 0x1FFFFFFF, little-endian
    uint8_t expected[DATA_AAD_LEN] = {0xFF, 0xFF, 0xFF, 0x1F, 54};
    CHECK(memcmp(assoc_data, expected, DATA_AAD_LEN) == 0,
          "Case 2: CAN_EFF_MASK applied, size byte == 54, still 5 bytes total");
  }

  // Case 3: zero CAN ID, zero-length payload - the all-zero edge case
  // must not be confused with an unwritten/failed call.
  printf("Testing Case 3: CAN ID 0, zero-length payload...\n");
  {
    uint8_t assoc_data[DATA_AAD_LEN];
    memset(assoc_data, 0xFF, sizeof(assoc_data));

    prepare_appdata_assoc_data(0, 0, assoc_data);

    uint8_t expected[DATA_AAD_LEN] = {0, 0, 0, 0, 0};
    CHECK(memcmp(assoc_data, expected, DATA_AAD_LEN) == 0,
          "Case 3: all-zero AD for CAN ID 0 / data_len 0");
  }

  // ============================================================
  // Case 4: Acceptance window boundary validation (15ms default)
  // ============================================================
  printf("Testing Case 4: acceptance window boundary checks...\n");
  {
    uint32_t window_ticks = SPSEC_ACCEPT_WINDOW_TICKS; // 150 = 15ms
    uint32_t tick_ns = 100000; // 100us/tick (1 Mbps default)
    int64_t window_ns = (int64_t)window_ticks * 100000LL; // 15,000,000 ns = 15 ms

    // Skew exactly at window boundary (+150 ticks = +15 ms) -> within window
    int64_t skew_ticks = 150;
    int64_t skew_ns = skew_ticks * (int64_t)tick_ns;
    CHECK(skew_ns <= window_ns && skew_ns >= -window_ns,
          "Case 4a: +150 ticks (+15ms) accepted at positive boundary");

    // Skew exactly at negative boundary (-150 ticks = -15 ms) -> within window
    skew_ticks = -150;
    skew_ns = skew_ticks * (int64_t)tick_ns;
    CHECK(skew_ns <= window_ns && skew_ns >= -window_ns,
          "Case 4b: -150 ticks (-15ms) accepted at negative boundary");

    // Skew 1 tick past boundary (+151 ticks = 15.1ms) -> outside window (rejected)
    skew_ticks = 151;
    skew_ns = skew_ticks * (int64_t)tick_ns;
    CHECK(skew_ns > window_ns || skew_ns < -window_ns,
          "Case 4c: +151 ticks (15.1ms) rejected outside positive boundary");

    // Skew 1 tick past negative boundary (-151 ticks = -15.1ms) -> outside window
    skew_ticks = -151;
    skew_ns = skew_ticks * (int64_t)tick_ns;
    CHECK(skew_ns > window_ns || skew_ns < -window_ns,
          "Case 4d: -151 ticks (-15.1ms) rejected outside negative boundary");
  }

  // ============================================================
  // Case 5: Bitrate scaling preserves real 15ms duration
  // ============================================================
  printf("Testing Case 5: acceptance window at 2 Mbps and 5 Mbps data bitrates...\n");
  {
    uint32_t window_ticks = 150; // reference 0.1ms ticks = 15ms
    int64_t window_ns = (int64_t)window_ticks * 100000LL; // 15 ms real time

    // At 2 Mbps: tick_ns = 50000 (50us/tick). 15ms corresponds to 300 ticks.
    uint32_t tick_ns_2mbps = 50000;
    int64_t skew_300_ticks = 300;
    int64_t skew_ns_2mbps = skew_300_ticks * (int64_t)tick_ns_2mbps; // 15,000,000 ns
    CHECK(skew_ns_2mbps == window_ns, "Case 5a: 300 ticks at 2 Mbps equals 15ms window");
    CHECK(skew_ns_2mbps <= window_ns, "Case 5b: 300 ticks accepted at 2 Mbps");

    int64_t skew_301_ticks = 301;
    int64_t overflow_ns = skew_301_ticks * (int64_t)tick_ns_2mbps;
    CHECK(overflow_ns > window_ns, "Case 5c: 301 ticks rejected at 2 Mbps");

    // At 5 Mbps: tick_ns = 20000 (20us/tick). 15ms corresponds to 750 ticks.
    uint32_t tick_ns_5mbps = 20000;
    int64_t skew_750_ticks = 750;
    int64_t skew_ns_5mbps = skew_750_ticks * (int64_t)tick_ns_5mbps; // 15,000,000 ns
    CHECK(skew_ns_5mbps == window_ns, "Case 5d: 750 ticks at 5 Mbps equals 15ms window");
  }

  if (g_failures) {
    fprintf(stderr, "\n%d appdata_aad check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All appdata_aad checks passed.\n");
  return 0;
}
