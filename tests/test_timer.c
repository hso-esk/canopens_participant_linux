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

// Regression tests for the timer backward-jump guard. The clock starts
// seeded from getrandom() (~2^63), so the FIRST time-sync must be accepted
// even though it jumps far "backward" to the authority's real timestamp;
// only later backward jumps count as rollback attempts.

#include "spsec_common.h"
#include "timer.h"

#include <assert.h>
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

  FreeRunningTimer t;
  if (timer_init(&t, 8) != 0) {
    fprintf(stderr, "timer_init failed\n");
    return 1;
  }

  uint8_t initial[8];
  timer_get_timestamp(&t, initial);
  printf("initial (random) timestamp = %llu\n",
         (unsigned long long)le_to_u64(initial));

  // First authoritative set: a small real timestamp. Even though it is far
  // below the random init, it MUST be accepted (this is the bug the guard
  // must not reintroduce).
  uint8_t first[8];
  u64_to_le(1000000ULL, first); // 100 s at 0.1 ms ticks
  CHECK(timer_set_timestamp(&t, first) == 0, "first sync accepted");

  uint8_t after_first[8];
  timer_get_timestamp(&t, after_first);
  CHECK(le_to_u64(after_first) < 2000000ULL,
        "clock actually adopted the small authority time");

  // A large backward jump after syncing = rollback attempt -> reject.
  uint8_t backward[8];
  u64_to_le(100ULL, backward);
  CHECK(timer_set_timestamp(&t, backward) == -1, "large backward jump rejected");

  // Forward jump = normal sync progression -> accept.
  uint8_t forward[8];
  u64_to_le(5000000ULL, forward);
  CHECK(timer_set_timestamp(&t, forward) == 0, "forward jump accepted");

  timer_destroy(&t);

  if (g_failures) {
    fprintf(stderr, "\n%d timer check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All timer checks passed.\n");
  return 0;
}
