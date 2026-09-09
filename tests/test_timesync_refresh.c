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
 * @file test_timesync_refresh.c
 * @brief Unit tests for participant_check_timesync_refresh() function.
 */

#include "spsec_common.h"
#include "participant.h"
#include "timer.h"
#include "spsec_registers.h"

#include <stdint.h>
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

// Set up a minimal Participant for testing.
static int init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  if (timer_init(&p_ptr->timer, 8) != 0) {
    fprintf(stderr, "timer_init failed\n");
    return 1;
  }
  return 0;
}

// Tear down a test Participant.
static void destroy_test_participant(Participant *p_ptr) {
  timer_destroy(&p_ptr->timer);
}

int main(void) {
  configure_logging("CRITICAL");

  Participant p;
  if (init_test_participant(&p) != 0) {
    return 1;
  }

  // Capture current time once for all deterministic timing tests
  uint64_t t0 = timer_get_current_time_us(&p.timer);

  // Case 1: NULL participant returns 0
  {
    signed char ret = participant_check_timesync_refresh(NULL);
    CHECK(ret == 0, "Case 1: NULL participant returns 0");
  }

  // Case 2: Unsynchronized node returns 0
  p.timesync.is_synchronized = false;
  p.timesync.refresh_interval_us = 100000;
  p.timesync.last_successful = t0;
  p.state_info.last_event = 0x1234;
  {
    signed char ret = participant_check_timesync_refresh(&p);
    CHECK(ret == 0, "Case 2: is_synchronized=false returns 0");
    CHECK(p.timesync.is_synchronized == false,
          "Case 2: is_synchronized stays false");
    CHECK(p.state_info.last_event == 0x1234,
          "Case 2: last_event unchanged (0x1234)");
  }

  // Case 3: Refresh interval disabled (0)
  p.timesync.is_synchronized = true;
  p.timesync.refresh_interval_us = 0;
  p.timesync.last_successful = t0;
  p.state_info.last_event = 0x5678;
  {
    signed char ret = participant_check_timesync_refresh(&p);
    CHECK(ret == 0, "Case 3: refresh_interval_us=0 returns 0 (disabled)");
    CHECK(p.timesync.is_synchronized == true,
          "Case 3: is_synchronized stays true");
    CHECK(p.state_info.last_event == 0x5678,
          "Case 3: last_event unchanged (0x5678)");
  }

  // Case 4: Refresh interval exceeded triggers timeout
  p.timesync.is_synchronized = true;
  p.timesync.last_successful = 0;
  p.timesync.refresh_interval_us = 1;
  p.state_info.last_event = 0x0000;
  {
    signed char ret = participant_check_timesync_refresh(&p);
    CHECK(ret == 1, "Case 4: timeout exceeded returns 1");
    CHECK(p.state_info.last_event == SPSEC_SYNC_REFR_TIMEOUT,
          "Case 4: last_event == SPSEC_SYNC_REFR_TIMEOUT (0xFE0F)");
    CHECK(p.timesync.is_synchronized == false,
          "Case 4: is_synchronized becomes false");
  }

  // Case 5: Refresh interval not exceeded
  p.timesync.is_synchronized = true;
  p.timesync.last_successful = t0;
  p.timesync.refresh_interval_us = UINT64_MAX / 2;
  p.state_info.last_event = 0xABCD;
  {
    signed char ret = participant_check_timesync_refresh(&p);
    CHECK(ret == 0, "Case 5: timeout not exceeded returns 0");
    CHECK(p.timesync.is_synchronized == true,
          "Case 5: is_synchronized stays true");
    CHECK(p.state_info.last_event == 0xABCD,
          "Case 5: last_event unchanged (0xABCD)");
  }

  destroy_test_participant(&p);

  if (g_failures) {
    fprintf(stderr, "\n%d timesync_refresh check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All timesync_refresh checks passed.\n");
  return 0;
}
