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
 * @file test_warning_hold_time.c
 * @brief Unit tests for participant_check_warning_state_hold_time() function.
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

  // Case 1: Non-WARNING state returns 0 without changing state
  p.state_info.state = SPSEC_STATE_SECURE;
  p.warning_state.event_occurred = true;
  p.warning_state.entry_time = 0;
  p.warning_state.hold_time_us = 1;
  {
    signed char ret = participant_check_warning_state_hold_time(&p);
    CHECK(ret == 0, "Case 1: non-WARNING state returns 0");
    CHECK(p.state_info.state == SPSEC_STATE_SECURE,
          "Case 1: state_info.state stays SECURE");
    CHECK(p.warning_state.event_occurred == true,
          "Case 1: warning_state.event_occurred unchanged (still true)");
  }

  // Case 2: Hold time not yet elapsed, remain in WARNING
  p.state_info.state = SPSEC_STATE_WARNING;
  p.warning_state.entry_time = t0;
  p.warning_state.hold_time_us = UINT64_MAX / 2;
  p.warning_state.event_occurred = false;
  p.state_info.alert_flag = true; // Set to prove it's not cleared on no-transition
  {
    signed char ret = participant_check_warning_state_hold_time(&p);
    CHECK(ret == 0, "Case 2: hold time not elapsed returns 0");
    CHECK(p.state_info.state == SPSEC_STATE_WARNING,
          "Case 2: state_info.state stays WARNING (no transition)");
  }

  // Case 3: Hold time elapsed with no new events, recover to SECURE
  p.state_info.state = SPSEC_STATE_WARNING;
  p.warning_state.entry_time = 0;
  p.warning_state.hold_time_us = 1;
  p.warning_state.event_occurred = false;
  p.state_info.alert_flag = true; // Should be cleared on transition
  {
    signed char ret = participant_check_warning_state_hold_time(&p);
    CHECK(ret == 1, "Case 3: hold time elapsed + no event returns 1");
    CHECK(p.state_info.state == SPSEC_STATE_SECURE,
          "Case 3: state_info.state becomes SECURE");
    CHECK(p.state_info.alert_flag == false,
          "Case 3: state_info.alert_flag becomes false");
  }

  // Case 4: Hold time elapsed but event_occurred is set, remain in WARNING
  p.state_info.state = SPSEC_STATE_WARNING;
  p.warning_state.entry_time = 0;
  p.warning_state.hold_time_us = 1;
  p.warning_state.event_occurred = true; // Blocks the transition
  p.state_info.alert_flag = true;
  {
    signed char ret = participant_check_warning_state_hold_time(&p);
    CHECK(ret == 0, "Case 4: hold time elapsed but event_occurred=true returns 0");
    CHECK(p.state_info.state == SPSEC_STATE_WARNING,
          "Case 4: state_info.state stays WARNING (event_occurred blocks)");
    CHECK(p.state_info.alert_flag == true,
          "Case 4: state_info.alert_flag stays true (no transition)");
  }

  // Case 5: New security event during WARNING resets entry time
  printf("Testing Case 5: Security event during WARNING refreshes hold window...\n");
  {
    p.state_info.state = SPSEC_STATE_WARNING;
    p.warning_state.entry_time = 100ULL; /* old entry time */
    p.warning_state.event_occurred = true;

    /* A new security event occurs */
    bool transitioned = participant_state_transition(&p, SPSEC_EVENT_SECURITY_EVENT);
    CHECK(transitioned == false, "Case 5: remaining in WARNING state returns false from transition");
    CHECK(p.state_info.state == SPSEC_STATE_WARNING, "Case 5: state remains WARNING");
    CHECK(p.warning_state.entry_time > 100ULL, "Case 5: entry_time is refreshed to current time");
    CHECK(p.warning_state.event_occurred == false, "Case 5: event_occurred is reset to false for new window");
  }

  destroy_test_participant(&p);

  if (g_failures) {
    fprintf(stderr, "\n%d warning_hold_time check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All warning_hold_time checks passed.\n");
  return 0;
}
