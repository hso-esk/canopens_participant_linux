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
 * @file test_event_loops.c
 * @brief Unit tests for SPsec event loop dispatchers and state transitions.
 */

/* Must precede any include so unistd.h exposes usleep() under -std=c11. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "messages.h"
#include "participant.h"
#include "register_operations.h"
#include "spsec_common.h"
#include "spsec_errors.h"
#include "spsec_protocol_can.h"
#include "../spsec_can_protocol/spsec_protocol_internal.h"
#include "spsec_registers.h"
#include "timer.h"
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, msg_ptr)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s (line %d)\n", msg_ptr, __LINE__);                \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

#define TEST_PID 77

static uint32_t build_arb_id(uint8_t prefix, uint8_t pid, uint8_t cpmt,
                             uint8_t counter_lsb) {
  (void)counter_lsb;
  /* CAN ID = prefix(8) | 0xFF(8) | cpmt(8) | (pid)(8) */
  return ((uint32_t)prefix << 24) | ((uint32_t)0xFF << 16) |
         ((uint32_t)cpmt << 8) | (uint32_t)(pid & 0x7F);
}

static void test_parse_client_hello(void) {
  printf("Testing can_protocol_parse_received_frame: ClientHello...\n");
  CanFrame frame = {0};
  frame.can_id = build_arb_id(0x1E, TEST_PID, CPMT_SESS_HELLO, 0);
  frame.len = 4 + RANDOM_SIZE;
  frame.data[0] = KEY_SELECTOR_PROVISIONING;
  /* 3 bytes padding */
  for (int i = 0; i < RANDOM_SIZE; i++)
    frame.data[4 + i] = (uint8_t)(0xA0 + i);

  uint8_t arb[4] = {
      (uint8_t)(TEST_PID | 0x80), CPMT_SESS_HELLO, 0xFF, 0x1E,
  };
  SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
  CHECK(msg_ptr != NULL, "ClientHello parses to non-NULL");
  if (msg_ptr) {
    CHECK(msg_ptr->msg_type == MSGTYPE_CLIENT_HELLO, "ClientHello message type");
    spsecmessage_dispose(msg_ptr);
  }
}

static void test_parse_client_hello_truncated(void) {
  printf("Testing ClientHello: truncated frame is rejected...\n");
  CanFrame frame = {0};
  frame.can_id = build_arb_id(0x1E, TEST_PID, CPMT_SESS_HELLO, 0);
  frame.len = 4; /* missing RANDOM_SIZE */

  uint8_t arb[4] = {
      (uint8_t)(TEST_PID | 0x80), CPMT_SESS_HELLO, 0xFF, 0x1E,
  };
  SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
  CHECK(msg_ptr == NULL, "truncated ClientHello is rejected");
}

static void test_parse_client_finished(void) {
  printf("Testing ClientFinished: tag is captured...\n");
  CanFrame frame = {0};
  frame.can_id = build_arb_id(0x1E, TEST_PID, CPMT_SESS_FINISH, 7);
  frame.len = AUTH_TAG_SIZE;
  for (int i = 0; i < AUTH_TAG_SIZE; i++)
    frame.data[i] = (uint8_t)(0xC0 + i);

  uint8_t arb[4] = {
      (uint8_t)(TEST_PID | 0x80), CPMT_SESS_FINISH, 7, 0x1E,
  };
  SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
  CHECK(msg_ptr != NULL, "ClientFinished parses");
  if (msg_ptr) {
    CHECK(msg_ptr->msg_type == MSGTYPE_CLIENT_FINISHED, "ClientFinished type");
    SPsecClientFinishedMessage *cf_ptr =
        (SPsecClientFinishedMessage *)msg_ptr->msg_content_ptr;
    CHECK(cf_ptr != NULL, "ClientFinished body allocated");
    if (cf_ptr) {
      CHECK(cf_ptr->auth_tag[0] == 0xC0, "first auth tag byte captured");
      CHECK(cf_ptr->cnt == 7, "counter LSB captured");
    }
    spsecmessage_dispose(msg_ptr);
  }
}

static void test_parse_session_terminate(void) {
  printf("Testing SessionTerminate: tag is captured...\n");
  CanFrame frame = {0};
  frame.can_id = build_arb_id(0x1E, TEST_PID, CPMT_SESS_TERMINATE, 11);
  frame.len = AUTH_TAG_SIZE;
  for (int i = 0; i < AUTH_TAG_SIZE; i++)
    frame.data[i] = (uint8_t)(0xE0 + i);

  uint8_t arb[4] = {
      (uint8_t)(TEST_PID | 0x80), CPMT_SESS_TERMINATE, 11, 0x1E,
  };
  SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
  CHECK(msg_ptr != NULL, "SessionTerminate parses");
  if (msg_ptr) {
    CHECK(msg_ptr->msg_type == MSGTYPE_CLIENT_TERMINATE, "SessionTerminate type");
    spsecmessage_dispose(msg_ptr);
  }
}

static void test_parse_read_initiate(void) {
  printf("Testing ReadInitiate: short auth-tag frame is rejected...\n");
  CanFrame frame = {0};
  frame.can_id = build_arb_id(0x1E, TEST_PID, CPMT_SESS_RDINIT, 3);
  frame.len = 2; /* too short */
  frame.data[0] = 0xAA;
  frame.data[1] = 0xBB;

  uint8_t arb[4] = {
      (uint8_t)(TEST_PID | 0x80), CPMT_SESS_RDINIT, 3, 0x1E,
  };
  SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
  CHECK(msg_ptr == NULL, "truncated ReadInitiate rejected");
}

static void test_parse_unrecognised_prefix(void) {
  printf("Testing parse_received_frame: too-short fallback returns NULL...\n");
  CanFrame frame = {0};
  frame.can_id = build_arb_id(0xAA, TEST_PID, CPMT_SESS_HELLO, 0);
  /* Frame is too short (0 bytes) for default app data path, so returns NULL. */
  frame.len = 0;

  uint8_t arb[4] = {
      (uint8_t)(TEST_PID | 0x80), CPMT_SESS_HELLO, 0xFF, 0xAA,
  };
  SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
  CHECK(msg_ptr == NULL, "truly malformed unrecognised prefix returns NULL");
}

static void test_parse_server_role_filter(void) {
  printf("Testing parse_received_frame: ServerHello (no client bit) is filtered...\n");
  CanFrame frame = {0};
  frame.can_id = build_arb_id(0x1E, TEST_PID, CPMT_SESS_HELLO, 0);
  frame.len = 4 + RANDOM_SIZE;

  uint8_t arb[4] = {
      (uint8_t)(TEST_PID & 0x7F), /* client bit clear */
      CPMT_SESS_HELLO, 0xFF, 0x1E,
  };
  SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
  CHECK(msg_ptr == NULL, "ServerHello frame is filtered (client-only receives)");
}

static void test_session_timeout_inactive(void) {
  printf("Testing check_session_timeout: inactive session is no-op...\n");
  Participant p;
  memset(&p, 0, sizeof(p));
  timer_init(&p.timer, 8);

  /* No active session -> check_session_timeout returns SUCCESS without
   * touching state. */
  p.session.active = false;
  spsec_ret_t ret = check_session_timeout(&p);
  CHECK(ret == SPSEC_SUCCESS, "inactive session does not time out");
  CHECK(p.state_info.state == 0, "state remains unchanged");

  timer_destroy(&p.timer);
}

static void test_session_overall_timeout(void) {
  printf("Testing check_session_timeout: overall session timeout fires...\n");
  Participant p;
  memset(&p, 0, sizeof(p));
  timer_init(&p.timer, 8);
  p.participant_id = TEST_PID;
  p.state_info.state = SPSEC_STATE_CONFIGURATION;
  p.state_info.status = 0x04;
  communication_keys_init(&p.comm_keys);
  p.session.active = true;
  p.session.start_time = 0;
  p.session.last_activity = 0;
  p.session.timeout_us = 100; /* 100us total session */
  p.session.response_timeout_us = 50;

  /* Wait longer than timeout. */
  usleep(2000);

  spsec_ret_t ret = check_session_timeout(&p);
  CHECK(ret < 0, "overall timeout returns negative");
  CHECK(p.session.active == false, "session deactivated on timeout");
  CHECK(p.state_info.last_event == SPSEC_SESS_TIMEOUT,
        "security event is SPSEC_SESS_TIMEOUT");

  communication_keys_destroy(&p.comm_keys);
  timer_destroy(&p.timer);
}

static void test_session_response_timeout(void) {
  printf("Testing check_session_timeout: response timeout fires...\n");
  Participant p;
  memset(&p, 0, sizeof(p));
  timer_init(&p.timer, 8);
  p.participant_id = TEST_PID;
  p.state_info.state = SPSEC_STATE_CONFIGURATION;
  p.state_info.status = 0x04;
  communication_keys_init(&p.comm_keys);
  p.session.active = true;
  p.session.start_time = timer_get_current_time_us(&p.timer);
  p.session.last_activity = p.session.start_time;
  p.session.timeout_us = 10000000; /* 10s overall */
  p.session.response_timeout_us = 50; /* 50us per-response (500us threshold) */

  /* Sleep beyond response timeout but well within overall timeout. */
  usleep(10000);

  spsec_ret_t ret = check_session_timeout(&p);
  CHECK(ret < 0, "response timeout returns negative");
  CHECK(p.state_info.last_event == SPSEC_SESS_RESPONSE_TIMEOUT,
        "security event is SPSEC_SESS_RESPONSE_TIMEOUT");

  communication_keys_destroy(&p.comm_keys);
  timer_destroy(&p.timer);
}

static void test_state_transition_happy_path(void) {
  printf("Testing participant_state_transition: NOT_SET -> WAITING...\n");
  Participant p;
  memset(&p, 0, sizeof(p));
  p.participant_id = TEST_PID;
  p.state_info.state = SPSEC_STATE_NOT_SET;
  p.state_info.status = 0x00;

  CHECK(participant_state_transition(&p, SPSEC_EVENT_STARTUP) == true,
        "STARTUP moves NOT_SET to WAITING");
  CHECK(p.state_info.state == SPSEC_STATE_WAITING,
        "NOT_SET -> WAITING on STARTUP");

  CHECK(participant_state_transition(&p, SPSEC_EVENT_ENTER_CONFIG) == true,
        "ENTER_CONFIG moves WAITING to CONFIGURATION");
  CHECK(p.state_info.state == SPSEC_STATE_CONFIGURATION,
        "WAITING -> CONFIGURATION on ENTER_CONFIG");

  CHECK(participant_state_transition(&p, SPSEC_EVENT_EXIT_CONFIG) == true,
        "EXIT_CONFIG moves CONFIGURATION to WAITING (no timesync)");
  CHECK(p.state_info.state == SPSEC_STATE_WAITING,
        "CONFIGURATION -> WAITING on EXIT_CONFIG (no timesync)");
}

int main(void) {
  configure_logging("CRITICAL");

  test_parse_client_hello();
  test_parse_client_hello_truncated();
  test_parse_client_finished();
  test_parse_session_terminate();
  test_parse_read_initiate();
  test_parse_unrecognised_prefix();
  test_parse_server_role_filter();

  test_session_timeout_inactive();
  test_session_overall_timeout();
  test_session_response_timeout();

  test_state_transition_happy_path();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d event_loops check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All event_loops checks passed.\n");
  return 0;
}
