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
 * @file test_participant_keys_ts.c
 * @brief Unit tests for get_required_ts_parts() in participant_keys.c
 */

#include "spsec_common.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Forward declaration of function under test */
unsigned char get_required_ts_parts(const uint8_t timestamp_le8[8],
                                    uint8_t even_ts_part[5],
                                    uint8_t odd_ts_part[5], bool *use_odd_now);

static int g_failures = 0;
#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg);                                    \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

/**
 * @brief Convert a 64-bit value to 8-byte little-endian array.
 */
static void ts_to_le8(uint64_t v, uint8_t out_ptr[8]) {
  for (int i = 0; i < 8; ++i)
    out_ptr[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}

int main(void) {
  configure_logging("CRITICAL");

  // ============================================================
  // Case 1: T=0 (before first transition) - early return
  // ============================================================
  printf("Testing Case 1: T=0 (before first transition)...\n");
  {
    uint8_t timestamp[8] = {0};
    uint8_t even_ts_part[5] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    uint8_t odd_ts_part[5] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    bool use_odd_now = false;

    unsigned char rc = get_required_ts_parts(timestamp, even_ts_part, odd_ts_part, &use_odd_now);

    CHECK(rc == 255, "Case 1: return value is 255 (unsigned char)-1");
    CHECK(memcmp(even_ts_part, (uint8_t[5]){0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, 5) == 0,
          "Case 1: even_ts_part unchanged (0xAA sentinel)");
    CHECK(memcmp(odd_ts_part, (uint8_t[5]){0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, 5) == 0,
          "Case 1: odd_ts_part unchanged (0xAA sentinel)");
    CHECK(use_odd_now == false, "Case 1: use_odd_now remains false");
  }

  // ============================================================
  // Case 2: T = 0x800000 (BIT23, even/last transition boundary)
  // ============================================================
  printf("Testing Case 2: T=0x800000 (BIT23 boundary)...\n");
  {
    uint8_t timestamp[8];
    ts_to_le8(0x800000ULL, timestamp);  // {0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00}
    uint8_t even_ts_part[5] = {0};
    uint8_t odd_ts_part[5] = {0};
    bool use_odd_now = false;

    unsigned char rc = get_required_ts_parts(timestamp, even_ts_part, odd_ts_part, &use_odd_now);

    CHECK(rc == 0, "Case 2: return value is 0");

    uint8_t expected_even[5] = {0x00, 0x00, 0x80, 0x00, 0x00};
    uint8_t expected_odd[5] = {0x00, 0x00, 0x80, 0x01, 0x00};

    CHECK(memcmp(even_ts_part, expected_even, 5) == 0,
          "Case 2: even_ts_part matches {0x00, 0x00, 0x80, 0x00, 0x00}");
    CHECK(memcmp(odd_ts_part, expected_odd, 5) == 0,
          "Case 2: odd_ts_part matches {0x00, 0x00, 0x80, 0x01, 0x00}");
    CHECK(use_odd_now == false, "Case 2: use_odd_now is false");
  }

  // ============================================================
  // Case 3: T = 0x1800000 (next window, odd branch)
  // ============================================================
  printf("Testing Case 3: T=0x1800000 (next window, odd branch)...\n");
  {
    uint8_t timestamp[8];
    ts_to_le8(0x1800000ULL, timestamp);  // {0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00}
    uint8_t even_ts_part[5] = {0};
    uint8_t odd_ts_part[5] = {0};
    bool use_odd_now = false;

    unsigned char rc = get_required_ts_parts(timestamp, even_ts_part, odd_ts_part, &use_odd_now);

    CHECK(rc == 0, "Case 3: return value is 0");

    uint8_t expected_even[5] = {0x00, 0x00, 0x80, 0x02, 0x00};
    uint8_t expected_odd[5] = {0x00, 0x00, 0x80, 0x01, 0x00};

    CHECK(memcmp(even_ts_part, expected_even, 5) == 0,
          "Case 3: even_ts_part matches {0x00, 0x00, 0x80, 0x02, 0x00}");
    CHECK(memcmp(odd_ts_part, expected_odd, 5) == 0,
          "Case 3: odd_ts_part matches {0x00, 0x00, 0x80, 0x01, 0x00}");
    CHECK(use_odd_now == true, "Case 3: use_odd_now is true");
  }

  if (g_failures) {
    fprintf(stderr, "\n%d participant_keys_ts check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All participant_keys_ts checks passed.\n");
  return 0;
}
