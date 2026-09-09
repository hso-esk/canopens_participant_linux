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
 * @file test_participant_state.c
 * @brief Unit tests for the participant state machine transitions.
 */

#include "spsec_common.h"
#include "participant.h"
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

  // Case 1: STARTUP from NOT_SET -> WAITING
  p.state_info.state = SPSEC_STATE_NOT_SET;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_STARTUP);
    CHECK(ret == true, "Case 1: STARTUP from NOT_SET returns true");
    CHECK(p.state_info.state == SPSEC_STATE_WAITING,
          "Case 1: state transitions to WAITING");
  }

  // Case 2: SECURITY_ESTABLISHED from WAITING -> SECURE
  p.state_info.state = SPSEC_STATE_WAITING;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_SECURITY_ESTABLISHED);
    CHECK(ret == true, "Case 2: SECURITY_ESTABLISHED from WAITING returns true");
    CHECK(p.state_info.state == SPSEC_STATE_SECURE,
          "Case 2: state transitions to SECURE");
    CHECK(p.state_info.alert_flag == false,
          "Case 2: alert_flag is false in SECURE");
  }

  // Case 3: ENTER_CONFIG from WAITING -> CONFIGURATION
  p.state_info.state = SPSEC_STATE_WAITING;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_ENTER_CONFIG);
    CHECK(ret == true, "Case 3: ENTER_CONFIG from WAITING returns true");
    CHECK(p.state_info.state == SPSEC_STATE_CONFIGURATION,
          "Case 3: state transitions to CONFIGURATION");
  }

  // Case 4: SECURITY_EVENT from SECURE -> WARNING
  p.state_info.state = SPSEC_STATE_SECURE;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_SECURITY_EVENT);
    CHECK(ret == true, "Case 4: SECURITY_EVENT from SECURE returns true");
    CHECK(p.state_info.state == SPSEC_STATE_WARNING,
          "Case 4: state transitions to WARNING");
    CHECK(p.state_info.alert_flag == true,
          "Case 4: alert_flag is true in WARNING");
    CHECK(p.warning_state.event_occurred == false,
          "Case 4: warning_state.event_occurred is false immediately after transition");
  }

  // Case 5: Repeated SECURITY_EVENT in WARNING stays in WARNING
  // State is already WARNING from Case 4
  {
    p.warning_state.event_occurred = true;
    bool ret = participant_state_transition(&p, SPSEC_EVENT_SECURITY_EVENT);
    CHECK(ret == false, "Case 5: second SECURITY_EVENT in WARNING returns false (no state change)");
    CHECK(p.state_info.state == SPSEC_STATE_WARNING,
          "Case 5: state remains WARNING");
    CHECK(p.warning_state.event_occurred == false,
          "Case 5: warning_state.event_occurred is false (not latched true) - REGRESSION TEST");
  }

  // Case 6: EVENTS_CLEAR from WARNING -> SECURE
  p.state_info.state = SPSEC_STATE_WARNING;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_EVENTS_CLEAR);
    CHECK(ret == true, "Case 6: EVENTS_CLEAR from WARNING returns true");
    CHECK(p.state_info.state == SPSEC_STATE_SECURE,
          "Case 6: state transitions to SECURE");
    CHECK(p.state_info.alert_flag == false,
          "Case 6: alert_flag is false in SECURE");
  }

  // Case 7: SECURITY_ABORT from SECURE -> WAITING
  p.state_info.state = SPSEC_STATE_SECURE;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_SECURITY_ABORT);
    CHECK(ret == true, "Case 7: SECURITY_ABORT from SECURE returns true");
    CHECK(p.state_info.state == SPSEC_STATE_WAITING,
          "Case 7: state transitions to WAITING");
  }

  // Case 8: SHUTDOWN from SECURE -> SHUTDOWN
  p.state_info.state = SPSEC_STATE_WAITING;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_SECURITY_ESTABLISHED);
    CHECK(ret == true, "Case 8 setup: SECURITY_ESTABLISHED from WAITING returns true");
    CHECK(p.state_info.state == SPSEC_STATE_SECURE,
          "Case 8 setup: state transitions to SECURE");
  }
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_SHUTDOWN);
    CHECK(ret == true, "Case 8: SHUTDOWN from SECURE returns true");
    CHECK(p.state_info.state == SPSEC_STATE_SHUTDOWN,
          "Case 8: state transitions to SHUTDOWN");
  }

  // Case 9: STARTUP from SHUTDOWN -> WAITING
  p.state_info.state = SPSEC_STATE_SHUTDOWN;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_STARTUP);
    CHECK(ret == true, "Case 9: STARTUP from SHUTDOWN returns true");
    CHECK(p.state_info.state == SPSEC_STATE_WAITING,
          "Case 9: state transitions to WAITING");
  }

  // Case 10: SECURITY_EVENT in WAITING is a no-op
  p.state_info.state = SPSEC_STATE_WAITING;
  {
    bool ret = participant_state_transition(&p, SPSEC_EVENT_SECURITY_EVENT);
    CHECK(ret == false, "Case 10: SECURITY_EVENT from WAITING returns false (no-op)");
    CHECK(p.state_info.state == SPSEC_STATE_WAITING,
          "Case 10: state remains WAITING (unchanged)");
  }

  // Case 11: participant_get_status_register() with NULL participant
  {
    uint8_t status = participant_get_status_register(NULL);
    CHECK(status == 0, "Case 11: NULL participant returns status 0");
  }

  // Case 12: Status register in SECURE without alert
  p.state_info.state = SPSEC_STATE_SECURE;
  p.state_info.alert_flag = false;
  {
    uint8_t status = participant_get_status_register(&p);
    CHECK((status & 0x0F) == SPSEC_STATE_SECURE,
          "Case 12: status bits 0-3 match SPSEC_STATE_SECURE");
    CHECK((status & 0x80) == 0, "Case 12: alert bit 7 is clear (no alert)");
  }

  // Case 13: Status register in SECURE with alert
  p.state_info.state = SPSEC_STATE_SECURE;
  p.state_info.alert_flag = true;
  {
    uint8_t status = participant_get_status_register(&p);
    CHECK((status & 0x0F) == SPSEC_STATE_SECURE,
          "Case 13: status bits 0-3 match SPSEC_STATE_SECURE");
    CHECK((status & 0x80) == 0x80, "Case 13: alert bit 7 is set");
  }

  // Case 14: participant_set_alert_flag() with NULL participant
  {
    participant_set_alert_flag(NULL, true);
    CHECK(true, "Case 14: NULL participant_ptr is safe no-op");
  }

  // Case 15: Setting alert flag sets status bit 7
  p.state_info.state = SPSEC_STATE_SECURE;
  p.state_info.alert_flag = false;
  p.state_info.status = 0x00;
  {
    participant_set_alert_flag(&p, true);
    CHECK(p.state_info.alert_flag == true, "Case 15: alert_flag set to true");
    CHECK((p.state_info.status & 0x80) == 0x80,
          "Case 15: status register bit 7 set (0x80)");
  }

  // Case 16: Clearing alert flag clears status bit 7 while preserving state
  p.state_info.state = SPSEC_STATE_SECURE;
  p.state_info.status = 0x0F;
  p.state_info.alert_flag = true;
  {
    participant_set_alert_flag(&p, false);
    CHECK(p.state_info.alert_flag == false, "Case 16: alert_flag cleared to false");
    CHECK((p.state_info.status & 0x80) == 0,
          "Case 16: status register bit 7 cleared");
    CHECK((p.state_info.status & 0x0F) == 0x0F,
          "Case 16: status bits 0-3 preserved at 0x0F");
  }

  // Case 17: participant_handle_security_event() with NULL participant
  {
    participant_handle_security_event(NULL, 0x1234);
    CHECK(true, "Case 17: NULL participant_ptr is safe no-op");
  }

  // Case 18: Security event in SECURE transitions to WARNING
  p.state_info.state = SPSEC_STATE_SECURE;
  p.state_info.alert_flag = false;
  p.state_info.last_event = 0x0000;
  {
    participant_handle_security_event(&p, 0x1234);
    CHECK(p.state_info.last_event == 0x1234,
          "Case 18: last_event set to 0x1234");
    CHECK(p.state_info.state == SPSEC_STATE_WARNING,
          "Case 18: state transitioned to WARNING");
    CHECK(p.state_info.alert_flag == true,
          "Case 18: alert_flag set to true on security event");
  }

  destroy_test_participant(&p);

  if (g_failures) {
    fprintf(stderr, "\n%d participant_state check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All participant_state checks passed.\n");
  return 0;
}
