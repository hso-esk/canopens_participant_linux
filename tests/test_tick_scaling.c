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
 * @file test_tick_scaling.c
 * @brief Unit tests for bitrate-dependent timer tick scaling and resolution configuration.
 */

#include "config.h"
#include "keys.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include "timer.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;
#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg);                                    \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

static void u64_to_le(uint64_t v, uint8_t out_ptr[8]) {
  for (int i = 0; i < 8; i++)
    out_ptr[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}

static uint64_t le_to_u64(const uint8_t in_ptr[8]) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++)
    v |= ((uint64_t)in_ptr[i]) << (i * 8);
  return v;
}

int main(void) {
  configure_logging("CRITICAL");

  // Test spsec_tick_ns_for_data_bitrate() resolution mapping
  printf("Testing spsec_tick_ns_for_data_bitrate() table...\n");
  CHECK(spsec_tick_ns_for_data_bitrate(SPSEC_CAN_DATA_1MBPS) == 100000,
        "1 Mbps -> 100000 ns (100 us)");
  CHECK(spsec_tick_ns_for_data_bitrate(SPSEC_CAN_DATA_2MBPS) == 50000,
        "2 Mbps -> 50000 ns (50 us)");
  CHECK(spsec_tick_ns_for_data_bitrate(SPSEC_CAN_DATA_4MBPS) == 25000,
        "4 Mbps -> 25000 ns (25 us)");
  CHECK(spsec_tick_ns_for_data_bitrate(SPSEC_CAN_DATA_5MBPS) == 20000,
        "5 Mbps -> 20000 ns (20 us)");
  CHECK(spsec_tick_ns_for_data_bitrate(SPSEC_CAN_DATA_8MBPS) == 12500,
        "8 Mbps -> 12500 ns (12.5 us, exact - the non-integer-us case)");
  CHECK(spsec_tick_ns_for_data_bitrate(SPSEC_CAN_DATA_10MBPS) == 10000,
        "10 Mbps -> 10000 ns (10 us, closed-form, not paper-tabulated)");
  CHECK(spsec_tick_ns_for_data_bitrate(0x50) == 100000,
        "unrecognized enum (reserved, not manufacturer-specific) -> "
        "spec-default 100000 ns");
  // Derive tick duration for manufacturer-specific bitrates from bps.
  CHECK(spsec_tick_ns_for_data_bitrate(0xA0) == 625,
        "manufacturer-specific rate is scaled via Eq. eq:tick, not a fixed "
        "100us fallback");

  // Verify tick strictly decreases as bitrate increases
  uint32_t rates[] = {SPSEC_CAN_DATA_1MBPS,  SPSEC_CAN_DATA_2MBPS,
                      SPSEC_CAN_DATA_4MBPS,  SPSEC_CAN_DATA_5MBPS,
                      SPSEC_CAN_DATA_8MBPS,  SPSEC_CAN_DATA_10MBPS};
  int monotonic = 1;
  for (size_t i = 1; i < sizeof(rates) / sizeof(rates[0]); i++) {
    if (spsec_tick_ns_for_data_bitrate((uint8_t)rates[i]) >=
        spsec_tick_ns_for_data_bitrate((uint8_t)rates[i - 1])) {
      monotonic = 0;
    }
  }
  CHECK(monotonic, "tick_ns strictly decreases as data-phase rate increases");

  // Maximum acceptance window clamp bound for timer tick resolution.
  printf("Testing spsec_max_accept_window_ticks()...\n");
  // 2048 reference ticks * 0.1ms = 204.8ms, matching the paper's +/-204.8ms
  // reconstruction bound at 1 Mbps (SS622) exactly.
  CHECK(spsec_max_accept_window_ticks(100000) == 2048,
        "1 Mbps: 2048*100000/100000 = 2048 reference ticks (204.8 ms)");
  // 256 reference ticks * 0.1ms = 25.6ms, matching the paper's +/-25.6ms
  // bound at 8 Mbps exactly.
  CHECK(spsec_max_accept_window_ticks(12500) == 256,
        "8 Mbps: 2048*12500/100000 = 256 reference ticks (25.6 ms)");
  CHECK(spsec_max_accept_window_ticks(0) == 0,
        "tick_ns=0 is guarded, not propagated as an unlimited window");
  CHECK(SPSEC_ACCEPT_WINDOW_TICKS <= spsec_max_accept_window_ticks(100000),
        "the 15ms default itself must never be clamped at any supported rate");
  CHECK(SPSEC_ACCEPT_WINDOW_TICKS <= spsec_max_accept_window_ticks(12500),
        "the 15ms default fits even at the fastest supported tick (8 Mbps)");

  // FreeRunningTimer: default tick_ns, and set/get round-trip.
  printf("Testing FreeRunningTimer tick_ns default and set/get...\n");
  {
    FreeRunningTimer t;
    memset(&t, 0, sizeof(t));
    CHECK(timer_init(&t, 8) == 0, "timer_init succeeds");
    CHECK(timer_get_tick_ns(&t) == 100000,
          "timer_init() defaults tick_ns to 100000 (100us, SPsec302 2.11)");

    timer_set_tick_ns(&t, spsec_tick_ns_for_data_bitrate(SPSEC_CAN_DATA_5MBPS));
    CHECK(timer_get_tick_ns(&t) == 20000,
          "timer_set_tick_ns() takes effect (5 Mbps -> 20000 ns)");

    // Zero is rejected (would divide by zero in the tick/time conversions)
    // rather than silently corrupting the timer.
    timer_set_tick_ns(&t, 0);
    CHECK(timer_get_tick_ns(&t) == 20000,
          "timer_set_tick_ns(0) is a no-op (guards div-by-zero)");

    timer_destroy(&t);
  }

  // Verify backward-jump guard bounds a fixed 1-second duration across resolutions
  printf("Testing backward-jump guard bounds a fixed real duration...\n");
  {
    const uint32_t resolutions[] = {100000, 20000, 12500}; // 1, 5, 8 Mbps
    for (size_t i = 0; i < sizeof(resolutions) / sizeof(resolutions[0]); i++) {
      const uint32_t tick_ns = resolutions[i];
      // Ticks per second at this resolution.
      const uint64_t per_sec = 1000000000ULL / tick_ns;

      FreeRunningTimer t;
      memset(&t, 0, sizeof(t));
      if (timer_init(&t, 8) != 0) {
        CHECK(0, "timer_init succeeds");
        continue;
      }
      timer_set_tick_ns(&t, tick_ns);

      // Establish a synced baseline far enough from zero that the backward
      // jumps below stay positive. First set is always accepted.
      const uint64_t base = per_sec * 1000ULL; // 1000 s in
      uint8_t ts[8];
      u64_to_le(base, ts);
      CHECK(timer_set_timestamp(&t, ts) == 0,
            "first sync accepted (establishes baseline)");

      // 0.5 s backward: inside the 1 s bound -> must be ACCEPTED.
      u64_to_le(base - per_sec / 2ULL, ts);
      CHECK(timer_set_timestamp(&t, ts) == 0,
            "0.5 s backward jump accepted (inside the 1 s bound)");

      // 2 s backward from the new baseline: outside the bound -> REJECTED.
      uint8_t cur[8];
      timer_get_timestamp(&t, cur);
      u64_to_le(le_to_u64(cur) - per_sec * 2ULL, ts);
      CHECK(timer_set_timestamp(&t, ts) == -1,
            "2 s backward jump rejected (outside the 1 s bound)");

      timer_destroy(&t);
      printf("  tick_ns=%u (%llu ticks/s): bound holds at 1 s real time\n",
             tick_ns, (unsigned long long)per_sec);
    }
  }

  if (g_failures) {
    fprintf(stderr, "\n%d tick_scaling check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All tick_scaling checks passed.\n");
  return 0;
}
