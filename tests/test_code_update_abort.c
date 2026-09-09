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
 * @file test_code_update_abort.c
 * @brief Tests aborting segmented code updates and resetting the write accumulator.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "messages.h"
#include "nvol_storage.h"
#include "participant.h"
#include "platform_nvol_storage.h"
#include "register_operations.h"
#include "register_write.h"
#include "spsec_common.h"
#include "spsec_errors.h"
#include "spsec_mapping.h"
#include "spsec_registers.h"
#include "timer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__);                \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

#define TEST_STORAGE_DIR "/tmp/test_code_update_abort_storage"

static void init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = 77;
  p_ptr->state_info.state = SPSEC_STATE_CONFIGURATION;
  p_ptr->state_info.status = 0x04;
  timer_init(&p_ptr->timer, 8);
  platform_nvol_storage_init(TEST_STORAGE_DIR, true);

  p_ptr->session.auth_tag_data_ptr = authtagparticipantdata_new();
  if (p_ptr->session.auth_tag_data_ptr) {
    p_ptr->session.auth_tag_data_ptr->key_selector[0] = KEY_SELECTOR_PROVISIONING;
  }

  p_ptr->state_info.prepared_write_register = SPSEC_REG_CODE_UPDATE_FILE;
  p_ptr->write_accum.expected = 1024;
  p_ptr->write_accum.active = true;
  p_ptr->write_accum.len = 0;
}

static void teardown_test_participant(Participant *p_ptr) {
  if (p_ptr->session.auth_tag_data_ptr) {
    authtagparticipantdata_free(p_ptr->session.auth_tag_data_ptr);
    p_ptr->session.auth_tag_data_ptr = NULL;
  }
  timer_destroy(&p_ptr->timer);
  int rc = system("rm -rf " TEST_STORAGE_DIR);
  (void)rc;
}

static SPsecClientWriteSegmentRequest *make_seg(uint8_t pid, uint32_t cnt,
                                                const uint8_t *data_ptr, uint8_t len) {
  uint8_t *buf_ptr = (uint8_t *)malloc(len);
  memcpy(buf_ptr, data_ptr, len);
  SPsecClientWriteSegmentRequest *req_ptr =
      spsecwritesegmentrequest_new(pid, cnt, buf_ptr, len);
  free(buf_ptr);
  return req_ptr;
}

static void test_partial_upload_and_abort(void) {
  printf("Testing partial segmented upload and explicit abort...\n");
  Participant p;
  init_test_participant(&p);

  uint8_t chunk[32];
  memset(chunk, 0xAA, sizeof(chunk));

  /* Feed 3 segments of 32 bytes = 96 bytes */
  for (int i = 0; i < 3; i++) {
    SPsecClientWriteSegmentRequest *seg_ptr = make_seg(p.participant_id, i + 1, chunk, 32);
    spsec_ret_t ret = register_apply_write_segment(&p, seg_ptr);
    CHECK(ret == SPSEC_SUCCESS, "segment applied");
    spsecwritesegmentrequest_free(seg_ptr);
  }

  CHECK(p.write_accum.len == 96, "accumulator has 96 bytes");
  CHECK(p.write_accum.active == true, "accumulator is active");

  /* Abort transfer via write_accum_reset() */
  write_accum_reset(&p.write_accum);
  CHECK(p.write_accum.len == 0, "accumulator len reset to 0");
  CHECK(p.write_accum.expected == 0, "accumulator expected reset to 0");
  CHECK(p.write_accum.active == false, "accumulator active reset to false");

  /* Storage must be empty (nothing committed) */
  uint8_t *stored_ptr = NULL;
  size_t stored_len = 0;
  CHECK(nvol_storage_read_varlen_alloc("code_update/update_file", &stored_ptr, &stored_len) != 0,
        "no file committed to storage on aborted transfer");

  teardown_test_participant(&p);
}

static void test_reinitiate_discards_stale_data(void) {
  printf("Testing re-initiate discards stale accumulation...\n");
  Participant p;
  init_test_participant(&p);

  uint8_t chunk[32];
  memset(chunk, 0xBB, sizeof(chunk));

  /* Upload 2 segments */
  for (int i = 0; i < 2; i++) {
    SPsecClientWriteSegmentRequest *seg_ptr = make_seg(p.participant_id, i + 1, chunk, 32);
    register_apply_write_segment(&p, seg_ptr);
    spsecwritesegmentrequest_free(seg_ptr);
  }
  CHECK(p.write_accum.len == 64, "accumulator has 64 bytes");

  /* Re-initiating write status on 92h resets accumulator */
  spsec_ret_t ret = register_check_write_status(
      &p, SPSEC_REG_CODE_UPDATE_FILE, SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN);
  CHECK(ret == SPSEC_SUCCESS, "write status check on 92h succeeds");
  CHECK(p.write_accum.len == 0, "stale buffer discarded on re-initiate");
  CHECK(p.write_accum.expected == SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN,
        "expected length updated to new request");
  CHECK(p.write_accum.active == true, "accumulator active for new transfer");

  teardown_test_participant(&p);
}

static void test_overflow_segment_resets_accum(void) {
  printf("Testing segment overflow rejection and accumulator clear...\n");
  Participant p;
  init_test_participant(&p);

  p.write_accum.expected = 64; /* Only expecting 64 bytes total */

  uint8_t chunk[32];
  memset(chunk, 0xCC, sizeof(chunk));

  /* Segment 1: 32 bytes -> fits */
  SPsecClientWriteSegmentRequest *seg1_ptr = make_seg(p.participant_id, 1, chunk, 32);
  CHECK(register_apply_write_segment(&p, seg1_ptr) == SPSEC_SUCCESS, "first segment accepted");
  spsecwritesegmentrequest_free(seg1_ptr);
  CHECK(p.write_accum.len == 32, "accum has 32 bytes");

  /* Simulate only 24 bytes remaining before 64, then send 32-byte chunk */
  p.write_accum.len = 40;

  SPsecClientWriteSegmentRequest *seg_overflow_ptr = make_seg(p.participant_id, 2, chunk, 32);
  spsec_ret_t ret = register_apply_write_segment(&p, seg_overflow_ptr);
  CHECK(ret < 0, "overflow segment rejected with negative error");
  spsecwritesegmentrequest_free(seg_overflow_ptr);

  CHECK(p.write_accum.len == 0, "accumulator cleared on overflow");
  CHECK(p.write_accum.active == false, "accumulator deactivated on overflow");

  teardown_test_participant(&p);
}

int main(void) {
  test_partial_upload_and_abort();
  test_reinitiate_discards_stale_data();
  test_overflow_segment_resets_accum();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d code_update_abort check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All code_update_abort checks passed.\n");
  return 0;
}
