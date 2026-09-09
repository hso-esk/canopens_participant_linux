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
 * @file test_heartbeat_timeouts.c
 * @brief Unit tests for participant_check_heartbeat_timing() and
 *        participant_check_heartbeat_timeouts() functions.
 */

#include "spsec_common.h"
#include "participant.h"
#include "timer.h"
#include "spsec_registers.h"
#include "register_write.h"
#include "messages.h"

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

  // PART A: Early-return guards for heartbeat timing

  // A1: Disabled timing returns immediately
  p.heartbeat.timing = SPSEC_HEARTBEAT_DISABLED;
  {
    signed char ret = participant_check_heartbeat_timing(&p);
    CHECK(ret == 0, "A1: SPSEC_HEARTBEAT_DISABLED returns 0 immediately");
  }

  // A2: Active cycle not yet elapsed returns 0
  p.heartbeat.timing = SPSEC_HEARTBEAT_8S;
  p.heartbeat.last_sent = timer_get_current_time_us(&p.timer);
  {
    signed char ret = participant_check_heartbeat_timing(&p);
    CHECK(ret == 0, "A2: SPSEC_HEARTBEAT_8S cycle not elapsed returns 0");
  }

  // A3: Cycle position before slot offset waits for assigned slot
  p.heartbeat.timing = SPSEC_HEARTBEAT_1S; // 1,000,000 us cycle
  p.participant_id = 50;                  // 50ms slot = 50,000 us
  {
    // Set timestamp to 10000 ticks (100us each = 1,000,000us), so cycle_position ~ 0us (< 50,000us)
    uint8_t ts[8] = {0};
    uint64_t ticks = 10000ULL;
    for (int i = 0; i < 8; i++)
      ts[i] = (uint8_t)((ticks >> (i * 8)) & 0xFF);
    timer_set_timestamp(&p.timer, ts);
    p.heartbeat.last_sent = 0; // time_since_last >= cycle_us

    signed char ret = participant_send_heartbeat(&p);
    CHECK(ret == 0, "A3: cycle_position < slot_offset returns 0 (waits for slot)");
  }

  // PART B: Heartbeat timeout detection and monitoring

  // B1: Disabled timing skips monitor processing
  destroy_test_participant(&p);
  init_test_participant(&p);
  p.heartbeat.timing = SPSEC_HEARTBEAT_DISABLED;
  p.heartbeat.last_received[0] = 111;
  p.heartbeat.last_received[1] = 222;
  p.heartbeat.last_received[2] = 333;
  p.heartbeat.last_received[3] = 444;
  {
    signed char ret = participant_check_heartbeat_timeouts(&p);
    CHECK(ret == 0, "B1: SPSEC_HEARTBEAT_DISABLED returns 0");
    CHECK(p.heartbeat.last_received[0] == 111, "B1: last_received[0] unchanged (111)");
    CHECK(p.heartbeat.last_received[1] == 222, "B1: last_received[1] unchanged (222)");
    CHECK(p.heartbeat.last_received[2] == 333, "B1: last_received[2] unchanged (333)");
    CHECK(p.heartbeat.last_received[3] == 444, "B1: last_received[3] unchanged (444)");
  }

  // B2: Empty monitor list returns 0 with no slots processed
  destroy_test_participant(&p);
  init_test_participant(&p);
  p.heartbeat.timing = SPSEC_HEARTBEAT_1S;
  {
    signed char ret = participant_check_heartbeat_timeouts(&p);
    CHECK(ret == 0, "B2: all monitor slots unused returns 0");
    CHECK(p.heartbeat.last_received[0] == 0, "B2: last_received[0] stays 0");
    CHECK(p.heartbeat.last_received[1] == 0, "B2: last_received[1] stays 0");
    CHECK(p.heartbeat.last_received[2] == 0, "B2: last_received[2] stays 0");
    CHECK(p.heartbeat.last_received[3] == 0, "B2: last_received[3] stays 0");
  }

  // B3: First check for unrecorded node arms timeout window without firing an event
  destroy_test_participant(&p);
  init_test_participant(&p);
  p.heartbeat.timing = SPSEC_HEARTBEAT_1S;
  p.heartbeat.monitor.participant_ids[0] = 5;
  p.heartbeat.last_received[0] = 0;
  p.state_info.last_event = 0x1111;
  {
    signed char ret = participant_check_heartbeat_timeouts(&p);
    CHECK(ret == 0, "B3: first-ever check arms timeout returns 0");
    CHECK(p.heartbeat.last_received[0] != 0, "B3: last_received[0] armed to current_time (nonzero)");
    CHECK(p.state_info.last_event == 0x1111, "B3: last_event unchanged (0x1111, no event fired)");
  }

  // B4: Timeout detection and window re-arm
  destroy_test_participant(&p);
  init_test_participant(&p);
  p.heartbeat.timing = SPSEC_HEARTBEAT_250MS;  // cycle_ms=250, timeout_us=625000
  p.heartbeat.monitor.participant_ids[0] = 5;
  p.heartbeat.last_received[0] = 0;
  uint64_t timeout_us = 250ULL * 2500ULL;  // 625,000us = 2.5 * 250ms

  // First call: arms last_received[0] to current_time
  participant_check_heartbeat_timeouts(&p);

  // Capture the armed value
  uint64_t armed = p.heartbeat.last_received[0];
  CHECK(armed > 0, "B4-setup: armed value is nonzero");

  // Roll it back to simulate elapsed time > timeout_us
  if (armed > timeout_us + 1000) {
    p.heartbeat.last_received[0] = armed - (timeout_us + 1000);
  } else {
    p.heartbeat.last_received[0] = 1;
  }
  uint64_t rolled_back = p.heartbeat.last_received[0];
  CHECK(rolled_back > 0, "B4-setup: rolled-back value is nonzero");

  // Set sentinel not 0xEF05
  p.state_info.last_event = 0x2222;

  // Second call: should detect timeout
  {
    signed char ret = participant_check_heartbeat_timeouts(&p);
    CHECK(ret == 0, "B4: timeout detected returns 0");
    CHECK(p.state_info.last_event == (SPSEC_SDP_HB_LOSS_BASE + 5),
          "B4: last_event == SPSEC_SDP_HB_LOSS_BASE + 5 (0xEF05)");
    CHECK(p.heartbeat.last_received[0] > rolled_back,
          "B4: last_received[0] re-armed to current_time (> rolled-back value)");
    CHECK(p.heartbeat.last_received[0] != 0,
          "B4: last_received[0] is nonzero after re-arm");
  }

  // B5: Normal check within window does not re-trigger timeout
  {
    signed char ret = participant_check_heartbeat_timeouts(&p);
    CHECK(ret == 0, "B5: no timeout yet returns 0");
    CHECK(p.state_info.last_event == (SPSEC_SDP_HB_LOSS_BASE + 5),
          "B5: last_event unchanged (still 0xEF05, not overwritten)");
    CHECK(p.heartbeat.last_received[0] != 0,
          "B5: last_received[0] remains armed (nonzero)");
  }

  // B6: Dynamic monitor update (0x62 write) zeroes last_received to avoid false timeouts
  printf("Case B6: Dynamic monitor list update clears last_received...\n");
  {
    /* Node 5 is monitored and currently armed with an old timestamp */
    p.heartbeat.timing = SPSEC_HEARTBEAT_1S;
    p.heartbeat.monitor.participant_ids[0] = 5;
    p.heartbeat.last_received[0] = 1000ULL; /* very old timestamp */

    /* Update register 0x62 to monitor node 6 in slot 0 */
    p.state_info.prepared_write_register = SPSEC_REG_SECURE_HEARTBEAT_MONITOR;
    uint8_t new_monitor_payload[4] = {6, 0, 0, 0};
    uint8_t *heap_payload_ptr = malloc(4);
    memcpy(heap_payload_ptr, new_monitor_payload, 4);
    SPsecClientWriteSegmentRequest *req_ptr = spsecwritesegmentrequest_new(
        p.participant_id, 1, heap_payload_ptr, 4);
    free(heap_payload_ptr);

    spsec_ret_t apply_rc = register_apply_write_segment(&p, req_ptr);
    CHECK(apply_rc == SPSEC_SUCCESS, "B6: register_apply_write_segment for 62h succeeds");
    CHECK(p.heartbeat.monitor.participant_ids[0] == 6, "B6: slot 0 updated to node 6");
    CHECK(p.heartbeat.last_received[0] == 0, "B6: last_received[0] is zeroed on update");

    /* Calling timeout check immediately must NOT raise a false positive timeout for node 6! */
    p.state_info.last_event = 0;
    signed char hb_rc = participant_check_heartbeat_timeouts(&p);
    CHECK(hb_rc == 0, "B6: check_heartbeat_timeouts returns 0");
    CHECK(p.state_info.last_event == 0, "B6: NO false-positive timeout raised for node 6");
    CHECK(p.heartbeat.last_received[0] != 0, "B6: slot 0 self-armed to current time");

    spsecwritesegmentrequest_free(req_ptr);
  }

  destroy_test_participant(&p);

  if (g_failures) {
    fprintf(stderr, "\n%d heartbeat_timeouts check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All heartbeat_timeouts checks passed.\n");
  return 0;
}
