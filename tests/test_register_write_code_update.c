/*
 * Copyright (c) 2026
 *
 * Hochschule Offenburg, University of Applied Sciences
 * Institute for reliable Embedded Systems
 * and Communications Electronic (ivESK)
 *
 * This file is licensed as described in the "LICENSE" file
 * included within this root folder of this work.
 */

/**
 * @file test_register_write_code_update.c
 * @brief Unit tests for multi-segment code update file writes (register 0x92).
 */

// POSIX feature test for setenv()/unsetenv(); must come before any include.
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "spsec_common.h"
#include "participant.h"
#include "register_write.h"
#include "spsec_errors.h"
#include "spsec_registers.h"
#include "spsec_mapping.h"
#include "messages.h"
#include "nvol_storage.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DATA_DIR "./test_register_write_code_update_data"
#define TEST_KEY_FILE  "./test_register_write_code_update_key.txt"
#define TEST_KEY_HEX   "00000000000000000000000000000000000000000000000000000000000000aa"

static int g_failures = 0;
#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg);                                    \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

// Set up a Participant with a fresh 92h prep state - exercises the apply
// path directly, skipping the non-Zero-session access check.
static int init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  if (timer_init(&p_ptr->timer, 8) != 0) {
    fprintf(stderr, "timer_init failed\n");
    return 1;
  }
  p_ptr->state_info.prepared_write_register = SPSEC_REG_CODE_UPDATE_FILE;
  p_ptr->write_accum.expected = SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN;
  p_ptr->write_accum.active = true;
  return 0;
}

static void destroy_test_participant(Participant *p_ptr) {
  timer_destroy(&p_ptr->timer);
}

/**
 * @brief Build an SPsecClientWriteSegmentRequest of any size (1..32).
 */
static SPsecClientWriteSegmentRequest *make_segment(uint8_t pid,
                                                    uint32_t cnt,
                                                    const uint8_t *data_ptr,
                                                    uint8_t len) {
  if (len == 0 || len > 32) {
    fprintf(stderr, "make_segment: len must be 1..32 (got %u)\n", len);
    return NULL;
  }
  uint8_t *scratch_ptr = malloc(len);
  if (!scratch_ptr)
    return NULL;
  memcpy(scratch_ptr, data_ptr, len);
  SPsecClientWriteSegmentRequest *r_ptr =
      spsecwritesegmentrequest_new(pid, cnt, scratch_ptr, len);
  free(scratch_ptr);
  return r_ptr;
}

// 4096-byte image where byte i == i, so tests can assert each segment
// landed in the right slot.
static void build_image(uint8_t *image_ptr, size_t len) {
  for (size_t i = 0; i < len; i++) {
    image_ptr[i] = (uint8_t)(i & 0xFF);
  }
}

/**
 * @brief Read the 92h storage file back and compare to expected.
 */
static int storage_matches(const uint8_t *expected_ptr, size_t expected_len) {
  uint8_t *got_ptr = NULL;
  size_t got_len = 0;
  if (nvol_storage_read_varlen_alloc("code_update/update_file", &got_ptr,
                                     &got_len) != 0) {
    return 0;
  }
  if (got_len != expected_len) {
    free(got_ptr);
    fprintf(stderr, "  expected %zu bytes, got %zu\n", expected_len, got_len);
    return 0;
  }
  int ok = (memcmp(got_ptr, expected_ptr, expected_len) == 0);
  free(got_ptr);
  return ok;
}

/* ============================================================
 * Case 1: 128 x 32-byte segments commit exactly once, full 4096 bytes
 * ============================================================ */
static void test_full_4096_accumulation(void) {
  printf("Case 1: 128 x 32-byte segments commit full 4096 bytes...\n");
  Participant p;
  if (init_test_participant(&p) != 0) {
    g_failures++;
    return;
  }

  uint8_t image[SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN];
  build_image(image, sizeof(image));

  // Feed 128 segments; the first 127 must NOT touch storage.
  for (int seg = 0; seg < 127; seg++) {
    SPsecClientWriteSegmentRequest *r_ptr =
        make_segment(120, (uint32_t)seg, image + seg * 32, 32);
    if (!r_ptr) {
      fprintf(stderr, "  segment %d: allocation failed\n", seg);
      g_failures++;
      destroy_test_participant(&p);
      return;
    }
    spsec_ret_t ret = register_apply_write_segment(&p, r_ptr);
    spsecwritesegmentrequest_free(r_ptr);
    if (ret != 0) {
      fprintf(stderr, "  segment %d unexpectedly returned %d\n", seg, (int)ret);
      g_failures++;
      destroy_test_participant(&p);
      return;
    }
    if (nvol_storage_exists("code_update/update_file")) {
      fprintf(stderr, "  segment %d wrote to storage prematurely\n", seg);
      g_failures++;
      destroy_test_participant(&p);
      return;
    }
  }

  // Final segment: must commit the full image exactly once.
  SPsecClientWriteSegmentRequest *last_ptr =
      make_segment(120, 127, image + 127 * 32, 32);
  if (!last_ptr) {
    fprintf(stderr, "  final segment: allocation failed\n");
    g_failures++;
    destroy_test_participant(&p);
    return;
  }
  spsec_ret_t ret = register_apply_write_segment(&p, last_ptr);
  spsecwritesegmentrequest_free(last_ptr);
  if (ret != 0) {
    fprintf(stderr, "  final segment returned %d\n", (int)ret);
    g_failures++;
    destroy_test_participant(&p);
    return;
  }
  CHECK(nvol_storage_exists("code_update/update_file"),
        "Case 1: final segment creates the storage file");
  CHECK(storage_matches(image, sizeof(image)),
        "Case 1: storage holds the full 4096-byte image in order");
  CHECK(p.write_accum.active == false,
        "Case 1: accumulator reset after commit");
  destroy_test_participant(&p);
}

/*
 * Case 2: Inactive accumulator rejects incoming segments.
 */
static void test_segment_without_active_accum_is_rejected(void) {
  printf("Case 2: segment without an active accumulator is rejected...\n");
  Participant p;
  if (init_test_participant(&p) != 0) {
    g_failures++;
    return;
  }

  // Simulate a finished/aborted upload: accum is no longer active.
  p.write_accum.active = false;
  p.write_accum.len = 0;
  p.write_accum.expected = 0;

  uint8_t data[32] = {0};
  SPsecClientWriteSegmentRequest *r_ptr = make_segment(120, 0, data, 32);
  if (!r_ptr) {
    g_failures++;
    destroy_test_participant(&p);
    return;
  }
  spsec_ret_t ret = register_apply_write_segment(&p, r_ptr);
  spsecwritesegmentrequest_free(r_ptr);
  CHECK(ret != 0, "Case 2: segment with inactive accum is rejected");
  CHECK(!nvol_storage_exists("code_update/update_file"),
        "Case 2: no storage write on inactive-accum segment");
  destroy_test_participant(&p);
}

/*
 * Case 3: Missing public authentication key rejects commit.
 */
static void test_fail_closed_without_public_auth_key(void) {
  printf("Case 3: missing public auth key closes the 92h write...\n");
  // Ensure no env var is set.
  unsetenv("SPSEC_PUBLIC_AUTH_KEY");
  unsetenv("SPSEC_PUBLIC_AUTH_KEY_FILE");

  Participant p;
  if (init_test_participant(&p) != 0) {
    g_failures++;
    return;
  }

  uint8_t image[SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN];
  build_image(image, sizeof(image));

  // 127 partial segments are accepted regardless of the public key (the
  // accumulator stores, no signature check runs).
  for (int seg = 0; seg < 127; seg++) {
    SPsecClientWriteSegmentRequest *r_ptr =
        make_segment(120, (uint32_t)seg, image + seg * 32, 32);
    if (!r_ptr) {
      g_failures++;
      destroy_test_participant(&p);
      return;
    }
    spsec_ret_t ret = register_apply_write_segment(&p, r_ptr);
    spsecwritesegmentrequest_free(r_ptr);
    if (ret != 0) {
      fprintf(stderr, "  partial segment %d rejected: %d\n", seg, (int)ret);
      g_failures++;
      destroy_test_participant(&p);
      return;
    }
  }

  // Final segment triggers the fail-closed gate.
  SPsecClientWriteSegmentRequest *last_ptr =
      make_segment(120, 127, image + 127 * 32, 32);
  if (!last_ptr) {
    g_failures++;
    destroy_test_participant(&p);
    return;
  }
  spsec_ret_t ret = register_apply_write_segment(&p, last_ptr);
  spsecwritesegmentrequest_free(last_ptr);
  CHECK(ret != 0,
        "Case 3: final segment is rejected without a public auth key");
  CHECK(!nvol_storage_exists("code_update/update_file"),
        "Case 3: storage untouched on fail-closed");
  CHECK(p.write_accum.active == false,
        "Case 3: accumulator cleared on fail-closed");
  destroy_test_participant(&p);
}

/* ============================================================
 * Case 4: re-initiating 92h on a participant discards a stale buffer
 * ============================================================ */
static void test_reinitiate_resets_accum(void) {
  printf("Case 4: re-initiating 92h discards any prior accumulation...\n");
  Participant p;
  if (init_test_participant(&p) != 0) {
    g_failures++;
    return;
  }

  // Push some garbage into the accumulator to simulate a partial upload
  // from a prior session, then re-arm as the next WRINIT would.
  for (int i = 0; i < 100; i++) {
    p.write_accum.buf[i] = 0xCC;
  }
  p.write_accum.len = 100;

  // Simulate the WRINIT reset path.
  memset(&p.write_accum, 0, sizeof(p.write_accum));
  p.write_accum.expected = SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN;
  p.write_accum.active = true;
  CHECK(p.write_accum.len == 0,
        "Case 4: re-initiate zeroes the prior accum length");
  CHECK(p.write_accum.expected == SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN,
        "Case 4: re-initiate re-records the negotiated total");
  destroy_test_participant(&p);
}

int main(void) {
  configure_logging("CRITICAL");

  if (nvol_storage_init(TEST_DATA_DIR, true) < 0) {  // bin: 1 byte = 1 byte
    fprintf(stderr, "nvol_storage_init failed\n");
    return 1;
  }

  // Set up a 64-char hex public key file for cases 1, 2 and 4. Case 3
  // unsets the env vars to exercise the fail-closed path.
  FILE *f_ptr = fopen(TEST_KEY_FILE, "w");
  if (!f_ptr) {
    fprintf(stderr, "Failed to write test key file\n");
    nvol_storage_cleanup();
    return 1;
  }
  fwrite(TEST_KEY_HEX, 1, strlen(TEST_KEY_HEX), f_ptr);
  fclose(f_ptr);
  setenv("SPSEC_PUBLIC_AUTH_KEY_FILE", TEST_KEY_FILE, 1);

  // Each case writes the same storage path. Delete it between cases so
  // prior bytes do not pollute the next case's assertions.
  test_full_4096_accumulation();
  nvol_storage_delete("code_update/update_file");
  test_segment_without_active_accum_is_rejected();
  nvol_storage_delete("code_update/update_file");
  test_fail_closed_without_public_auth_key();
  nvol_storage_delete("code_update/update_file");
  test_reinitiate_resets_accum();

  nvol_storage_cleanup();
  {
    int rc = system("rm -rf " TEST_DATA_DIR " " TEST_KEY_FILE);
    (void)rc;
  }

  if (g_failures) {
    fprintf(stderr, "\n%d register_write_code_update check(s) FAILED\n",
            g_failures);
    return 1;
  }
  printf("All register_write_code_update checks passed.\n");
  return 0;
}
