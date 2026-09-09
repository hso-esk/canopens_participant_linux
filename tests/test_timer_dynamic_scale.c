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
 * @file test_timer_dynamic_scale.c
 * @brief Tests timer monotonicity and continuity when dynamically changing tick resolution.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include "spsec_common.h"
#include "timer.h"
#include "utils_bytes.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__);                \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

static uint64_t read_ticks(FreeRunningTimer *t_ptr) {
  uint8_t ts[8];
  timer_get_timestamp(t_ptr, ts);
  return bytes_to_u64_le(ts);
}

static void test_rescale_monotonicity(void) {
  printf("Testing timer dynamic tick-ns rescaling monotonicity...\n");
  FreeRunningTimer t;
  CHECK(timer_init(&t, 8) == 0, "timer_init succeeds");
  CHECK(timer_get_tick_ns(&t) == 100000, "default tick_ns is 100000 ns (100us)");

  /* Run at default 100us */
  usleep(60000);
  uint64_t ts1 = read_ticks(&t);

  /* Rescale to 50us (faster rate) */
  timer_set_tick_ns(&t, 50000);
  CHECK(timer_get_tick_ns(&t) == 50000, "tick_ns updated to 50000 ns");

  uint64_t ts2 = read_ticks(&t);
  CHECK(ts2 >= ts1, "timestamp after rescale to faster tick rate must be >= previous");
  /* Rescaling should not produce large discontinuous jumps */
  CHECK((ts2 - ts1) <= 100, "instantaneous tick jump after rescale is bounded");

  /* Run at 50us */
  usleep(60000);
  uint64_t ts3 = read_ticks(&t);
  uint64_t delta_50us = ts3 - ts2;
  CHECK(ts3 > ts2, "timer continues to advance under 50us tick rate");

  /* Rescale back to 100us */
  timer_set_tick_ns(&t, 100000);
  CHECK(timer_get_tick_ns(&t) == 100000, "tick_ns restored to 100000 ns");

  uint64_t ts4 = read_ticks(&t);
  CHECK(ts4 >= ts3, "timestamp after rescale to slower tick rate must NOT jump backward");
  CHECK((ts4 - ts3) <= 50, "instantaneous tick jump after slowing down is bounded");

  /* Run at 100us */
  usleep(60000);
  uint64_t ts5 = read_ticks(&t);
  uint64_t delta_100us = ts5 - ts4;
  CHECK(ts5 > ts4, "timer advances under restored 100us tick rate");

  /* 50us rate should accumulate ticks faster than 100us */
  printf("  60ms @ 50us: %" PRIu64 " ticks, 60ms @ 100us: %" PRIu64 " ticks\n",
         delta_50us, delta_100us);
  CHECK(delta_50us > delta_100us, "50us tick accumulation rate exceeds 100us rate");

  timer_destroy(&t);
}

int main(void) {
  test_rescale_monotonicity();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d timer_dynamic_scale check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All timer_dynamic_scale checks passed.\n");
  return 0;
}
