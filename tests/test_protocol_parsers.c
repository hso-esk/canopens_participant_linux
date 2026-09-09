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
 * @file test_protocol_parsers.c
 * @brief Regression tests for CAN-frame-length floor checks in protocol parsers.
 */

#include "messages.h"
#include "spsec_common.h"
#include "../spsec_can_protocol/spsec_protocol_internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;
#define CHECK(cond, msg_ptr)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg_ptr);                                    \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

/* Common arbitration ID bytes: byte0 has bit7 clear so & 0x7F is a no-op. */
static const uint8_t arb_id_bytes[4] = {0x05, 0x00, 0x07, 0x00};

/* Helper to create a zeroed CanFrame with fixed can_id and given len. */
static CanFrame make_frame(uint8_t len) {
  CanFrame frame;
  memset(&frame, 0, sizeof(frame));
  frame.can_id = 0x12345678;
  frame.len = len;
  return frame;
}

/* ---- protocol_handshake.c ---- */

static void test_parse_client_hello_frame(void) {
  /* floor = 4 + RANDOM_SIZE = 20 */
  CanFrame frame = make_frame(19);
  SPsecMessage *msg_ptr = parse_client_hello_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_client_hello_frame: len=19 (floor-1) rejects");

  frame = make_frame(20);
  msg_ptr = parse_client_hello_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_client_hello_frame: len=20 (floor) accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

static void test_parse_client_finished_frame(void) {
  /* floor = AUTH_TAG_SIZE = 8 */
  CanFrame frame = make_frame(7);
  SPsecMessage *msg_ptr = parse_client_finished_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_client_finished_frame: len=7 (floor-1) rejects");

  frame = make_frame(8);
  msg_ptr = parse_client_finished_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_client_finished_frame: len=8 (floor) accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

static void test_parse_terminate_request_frame(void) {
  /* floor = AUTH_TAG_SIZE = 8 */
  CanFrame frame = make_frame(7);
  SPsecMessage *msg_ptr = parse_terminate_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_terminate_request_frame: len=7 (floor-1) rejects");

  frame = make_frame(8);
  msg_ptr = parse_terminate_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_terminate_request_frame: len=8 (floor) accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

/* ---- protocol_register.c ---- */

static void test_parse_read_initiate_request_frame(void) {
  /* floor = 8 + AUTH_TAG_SIZE = 16 */
  CanFrame frame = make_frame(15);
  SPsecMessage *msg_ptr = parse_read_initiate_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_read_initiate_request_frame: len=15 (floor-1) rejects");

  frame = make_frame(16);
  msg_ptr = parse_read_initiate_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_read_initiate_request_frame: len=16 (floor) accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

static void test_parse_read_segment_request_frame(void) {
  /* floor = AUTH_TAG_SIZE = 8 */
  CanFrame frame = make_frame(7);
  SPsecMessage *msg_ptr = parse_read_segment_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_read_segment_request_frame: len=7 (floor-1) rejects");

  frame = make_frame(8);
  msg_ptr = parse_read_segment_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_read_segment_request_frame: len=8 (floor) accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

static void test_parse_write_initiate_request_frame(void) {
  /* floor = 8 + AUTH_TAG_SIZE = 16 */
  CanFrame frame = make_frame(15);
  SPsecMessage *msg_ptr = parse_write_initiate_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_write_initiate_request_frame: len=15 (floor-1) rejects");

  frame = make_frame(16);
  msg_ptr = parse_write_initiate_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_write_initiate_request_frame: len=16 (floor) accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

/* Test parse_write_segment_request_frame length validation */
static void test_parse_write_segment_request_frame(void) {
  /* Test A: floor rejected (payload_without_tag == 0) */
  CanFrame frame = make_frame(8);
  SPsecMessage *msg_ptr = parse_write_segment_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_write_segment_request_frame: len=8 (payload_no_tag=0) rejects");

  /* Test B: floor accepted, smallest table entry (payload_without_tag = 1) */
  frame = make_frame(9);
  msg_ptr = parse_write_segment_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_write_segment_request_frame: len=9 (payload_no_tag=1) accepts");
  if (msg_ptr) {
    SPsecClientWriteSegmentRequest *content_ptr =
        (SPsecClientWriteSegmentRequest *)msg_ptr->msg_content_ptr;
    CHECK(content_ptr->data_len == 1,
          "parse_write_segment_request_frame: len=9 -> data_len=1 (smallest table entry)");
    spsecmessage_dispose(msg_ptr);
  }

  /* Test C: between-entries length (payload_without_tag = 3, between 2 and 4) */
  /* The parser truncates rather than rejects for between-table-entry lengths;
   * true rejection only happens when payload_without_tag == 0. */
  frame = make_frame(11);
  msg_ptr = parse_write_segment_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_write_segment_request_frame: len=11 (payload_no_tag=3) accepts (truncates to 2)");
  if (msg_ptr) {
    SPsecClientWriteSegmentRequest *content_ptr =
        (SPsecClientWriteSegmentRequest *)msg_ptr->msg_content_ptr;
    CHECK(content_ptr->data_len == 2,
          "parse_write_segment_request_frame: len=11 -> data_len=2 (greatest-lower-bound truncation)");
    spsecmessage_dispose(msg_ptr);
  }
}

/* ---- protocol_session.c ---- */

static void test_parse_timesync_request_frame(void) {
  /* floor = RANDOM_SIZE = 16 */
  CanFrame frame = make_frame(15);
  SPsecMessage *msg_ptr = parse_timesync_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_timesync_request_frame: len=15 (floor-1) rejects");

  frame = make_frame(16);
  msg_ptr = parse_timesync_request_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_timesync_request_frame: len=16 (floor) accepts");
  /* Note: msg_type is CPMT_AUTH_TIME (8), not MSGTYPE_TIME_SYNC_REQUEST (15).
   * This mismatch exists in the source and is out of scope for this test. */
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

static void test_parse_timesync_response_frame(void) {
  /* floor = TIMESTAMP_SIZE + 4 + AUTH_TAG_SIZE = 20 */
  CanFrame frame = make_frame(19);
  SPsecMessage *msg_ptr = parse_timesync_response_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr == NULL, "parse_timesync_response_frame: len=19 (floor-1) rejects");

  frame = make_frame(20);
  msg_ptr = parse_timesync_response_frame((uint8_t *)arb_id_bytes, &frame);
  CHECK(msg_ptr != NULL, "parse_timesync_response_frame: len=20 (floor) accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

/* Test parse_default_app_data length handling */
static void test_parse_default_app_data(void) {
  CanFrame frame = make_frame(11);
  int secure_data_len = 1;  /* satisfies caller's floor: len - 10 = 1 >= 0.
                               * Avoid len=10/secure_data_len=0 edge which
                               * triggers malloc(0) inside spsecappdata_new. */
  SPsecMessage *msg_ptr = parse_default_app_data(0x12345678, &frame, secure_data_len);
  CHECK(msg_ptr != NULL, "parse_default_app_data: len=11, secure_data_len=1 accepts");
  if (msg_ptr) spsecmessage_dispose(msg_ptr);
}

static void test_fuzzed_can_frames(void) {
  printf("Testing fuzzed and malformed CAN frames robustness...\n");
  /* Test every length 0..64 across multiple arbitration IDs */
  for (uint8_t cpmt = 0; cpmt <= 15; cpmt++) {
    for (uint8_t len = 0; len <= 64; len++) {
      CanFrame frame;
      memset(&frame, 0xCD, sizeof(frame));
      frame.can_id = 0x1E000000 | ((uint32_t)cpmt << 8) | 120;
      frame.len = len;

      uint8_t arb[4];
      arb[0] = (uint8_t)(frame.can_id & 0xFF);
      arb[1] = (uint8_t)((frame.can_id >> 8) & 0xFF);
      arb[2] = (uint8_t)((frame.can_id >> 16) & 0xFF);
      arb[3] = (uint8_t)((frame.can_id >> 24) & 0xFF);

      SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
      if (msg_ptr) {
        spsecmessage_dispose(msg_ptr);
      }
    }
  }

  /* Test all-zero and all-one arbitration IDs with various lengths */
  uint32_t test_ids[] = {0x00000000, 0x1FFFFFFF, 0x02210000, 0x06230000, 0x0AFF0000, 0x12000000};
  for (size_t i = 0; i < sizeof(test_ids) / sizeof(test_ids[0]); i++) {
    for (uint8_t len = 0; len <= 64; len++) {
      CanFrame frame;
      memset(&frame, 0xAA, sizeof(frame));
      frame.can_id = test_ids[i];
      frame.len = len;

      uint8_t arb[4];
      arb[0] = (uint8_t)(frame.can_id & 0xFF);
      arb[1] = (uint8_t)((frame.can_id >> 8) & 0xFF);
      arb[2] = (uint8_t)((frame.can_id >> 16) & 0xFF);
      arb[3] = (uint8_t)((frame.can_id >> 24) & 0xFF);

      SPsecMessage *msg_ptr = can_protocol_parse_received_frame(frame.can_id, arb, &frame);
      if (msg_ptr) {
        spsecmessage_dispose(msg_ptr);
      }
    }
  }
}

int main(void) {
  configure_logging("CRITICAL");

  /* Handshake parsers */
  test_parse_client_hello_frame();
  test_parse_client_finished_frame();
  test_parse_terminate_request_frame();

  /* Register parsers */
  test_parse_read_initiate_request_frame();
  test_parse_read_segment_request_frame();
  test_parse_write_initiate_request_frame();
  test_parse_write_segment_request_frame();

  /* Session parsers */
  test_parse_timesync_request_frame();
  test_parse_timesync_response_frame();
  test_parse_default_app_data();

  /* Fuzz testing robustness */
  test_fuzzed_can_frames();

  if (g_failures) {
    fprintf(stderr, "\n%d protocol parser check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All protocol parser checks passed.\n");
  return 0;
}
