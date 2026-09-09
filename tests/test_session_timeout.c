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
 * @file test_session_timeout.c
 * @brief Unit tests for check_session_timeout() function.
 */

#include "spsec_common.h"
#include "participant.h"
#include "timer.h"
#include "spsec_errors.h"
#include "spsec_registers.h"
#include "register_operations.h"

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

  // Capture current time once for all deterministic timeout tests
  uint64_t t0 = timer_get_current_time_us(&p.timer);

  // Case 1: Inactive session returns success immediately
  p.session.active = false;
  p.state_info.state = SPSEC_STATE_CONFIGURATION;
  {
    spsec_ret_t ret = check_session_timeout(&p);
    CHECK(ret == SPSEC_SUCCESS,
          "Case 1: inactive session returns SPSEC_SUCCESS");
    CHECK(p.state_info.state == SPSEC_STATE_CONFIGURATION,
          "Case 1: state unchanged (CONFIGURATION)");
  }

  // Case 2: Overall timeout in WAITING resets session
  p.session.active = true;
  p.session.start_time = t0;
  p.session.timeout_us = 0; // guarantees time_since_start >= 0 >= timeout_us
  p.session.last_activity = t0;
  p.session.response_timeout_us = 100000; // 100ms
  p.state_info.state = SPSEC_STATE_WAITING;
  p.state_info.last_event = 0;
  {
    spsec_ret_t ret = check_session_timeout(&p);
    CHECK(ret == SPSEC_ERROR_SESSION_TIMEOUT,
          "Case 2: overall timeout returns SPSEC_ERROR_SESSION_TIMEOUT");
    CHECK(p.session.active == false,
          "Case 2: session.active becomes false");
    CHECK(p.state_info.last_event == SPSEC_SESS_TIMEOUT,
          "Case 2: last_event is SPSEC_SESS_TIMEOUT (0x5E04)");
    CHECK(p.state_info.state == SPSEC_STATE_WAITING,
          "Case 2: state stays WAITING (no SECURITY_ABORT for WAITING)");
  }

  // Case 3: Overall timeout in CONFIGURATION transitions to WAITING
  p.session.active = true;
  p.session.start_time = t0;
  p.session.timeout_us = 0;
  p.session.last_activity = t0;
  p.session.response_timeout_us = 100000;
  p.state_info.state = SPSEC_STATE_CONFIGURATION;
  p.timesync.is_synchronized = false;
  p.state_info.last_event = 0;
  {
    spsec_ret_t ret = check_session_timeout(&p);
    CHECK(ret == SPSEC_ERROR_SESSION_TIMEOUT,
          "Case 3: overall timeout returns SPSEC_ERROR_SESSION_TIMEOUT");
    CHECK(p.session.active == false,
          "Case 3: session.active becomes false");
    CHECK(p.state_info.last_event == SPSEC_SESS_TIMEOUT,
          "Case 3: last_event is SPSEC_SESS_TIMEOUT (0x5E04)");
    CHECK(p.state_info.state == SPSEC_STATE_WAITING,
          "Case 3: state transitions to WAITING (EXIT_CONFIG due to unsynced)");
  }

  // Case 4: Response timeout in WAITING resets session
  p.session.active = true;
  p.session.start_time = t0;
  p.session.timeout_us = UINT64_MAX / 2; // large, won't trigger
  p.session.last_activity = t0;
  p.session.response_timeout_us = 0; // guarantees time_since_activity >= 0
  p.state_info.state = SPSEC_STATE_WAITING;
  p.state_info.last_event = 0;
  {
    spsec_ret_t ret = check_session_timeout(&p);
    CHECK(ret == SPSEC_ERROR_SESSION_TIMEOUT,
          "Case 4: response timeout returns SPSEC_ERROR_SESSION_TIMEOUT");
    CHECK(p.session.active == false,
          "Case 4: session.active becomes false");
    CHECK(p.state_info.last_event == SPSEC_SESS_RESPONSE_TIMEOUT,
          "Case 4: last_event is SPSEC_SESS_RESPONSE_TIMEOUT (0x5E03)");
  }

  // Case 5: Session within limits remains active
  p.session.active = true;
  p.session.start_time = t0;
  p.session.timeout_us = UINT64_MAX / 2;
  p.session.last_activity = t0;
  p.session.response_timeout_us = UINT64_MAX / 2;
  p.state_info.state = SPSEC_STATE_SECURE;
  p.state_info.last_event = 0;
  {
    spsec_ret_t ret = check_session_timeout(&p);
    CHECK(ret == SPSEC_SUCCESS,
          "Case 5: no timeout returns SPSEC_SUCCESS");
    CHECK(p.session.active == true,
          "Case 5: session.active stays true");
    CHECK(p.state_info.state == SPSEC_STATE_SECURE,
          "Case 5: state unchanged (SECURE)");
  }

  destroy_test_participant(&p);

  if (g_failures) {
    fprintf(stderr, "\n%d session_timeout check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All session_timeout checks passed.\n");
  return 0;
}
