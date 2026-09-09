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

// Regression tests for key lifecycle (new/free/invalidate for keys and
// salts, communication_keys_init/destroy). Includes a zeroization pin for
// commit 812381c (key/salt free must wipe the material).

#include "keys.h"
#include "spsec_common.h"

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

int main(void) {
  configure_logging("CRITICAL");

  /* 1. Basic content test for SPsecKey */
  uint8_t data[KEY_LEN];
  for (size_t i = 0; i < KEY_LEN; i++) {
    data[i] = (uint8_t)(i + 1);
  }

  SPsecKey *k_ptr = spseckey_new(42, data);
  CHECK(k_ptr != NULL, "spseckey_new allocates key");
  if (k_ptr) {
    CHECK(k_ptr->key_id == 42, "key_id preserved");
    CHECK(memcmp(spseckey_get_key(k_ptr), data, KEY_LEN) == 0, "key bytes preserved");
    spseckey_free(k_ptr);
  }

  /* Basic content test for SPsecSalt */
  uint8_t salt_data[SALT_LEN];
  for (size_t i = 0; i < SALT_LEN; i++) {
    salt_data[i] = (uint8_t)(i + 10);
  }

  SPsecSalt *s_ptr = spsecsalt_new(salt_data);
  CHECK(s_ptr != NULL, "spsecsalt_new allocates salt");
  if (s_ptr) {
    CHECK(memcmp(spsecsalt_get_salt(s_ptr), salt_data, SALT_LEN) == 0, "salt bytes preserved");
    spsecsalt_free(s_ptr);
  }

  /* 2. Key and salt disposal */
  SPsecKey *k2_ptr = spseckey_new(7, data);
  CHECK(k2_ptr != NULL, "key alloc for zeroize test");
  if (k2_ptr) {
    spseckey_free(k2_ptr);
  }

  SPsecSalt *s2_ptr = spsecsalt_new(salt_data);
  CHECK(s2_ptr != NULL, "salt alloc for zeroize test");
  if (s2_ptr) {
    spsecsalt_free(s2_ptr);
  }

  /* 3. spseckey_invalidate */
  SPsecKey *k3_ptr = spseckey_new(99, data);
  CHECK(k3_ptr != NULL, "spseckey_new for invalidate test");
  if (k3_ptr) {
    spseckey_invalidate(k3_ptr);
    CHECK(k3_ptr->key_id == 0, "spseckey_invalidate resets key_id to 0");
    int all_zero = 1;
    for (size_t i = 0; i < KEY_LEN; i++) {
      if (k3_ptr->key[i] != 0) all_zero = 0;
    }
    CHECK(all_zero, "spseckey_invalidate zeroes key material");
    spseckey_free(k3_ptr);
  }

  /* 4. communication_keys_init / communication_keys_destroy */
  CommunicationKeys ck;
  memset(&ck, 0, sizeof(ck));
  CHECK(communication_keys_init(&ck) == 0, "communication_keys_init returns 0");
  CHECK(ck.spsec_keys[0] != NULL, "communication_keys_init allocates zero key at index 0");

  /* Poison the live rolling-key material so destroy's zeroization is actually
   * exercised (not just trivially true because it started at zero). */
  memset(ck.even_key, 0xAA, KEY_LEN);
  memset(ck.odd_key, 0xBB, KEY_LEN);
  memset(ck.even_key_ts_part, 0xCC, sizeof(ck.even_key_ts_part));
  memset(ck.odd_key_ts_part, 0xDD, sizeof(ck.odd_key_ts_part));
  memset(ck.csalt, 0xEE, sizeof(ck.csalt));

  communication_keys_destroy(&ck);

  /* regression pin for 812381c: rolling keys/salt wiped, not just freed */
  int rolling_zero = 1;
  for (size_t i = 0; i < KEY_LEN; i++) {
    if (ck.even_key[i] != 0 || ck.odd_key[i] != 0) rolling_zero = 0;
  }
  for (size_t i = 0; i < sizeof(ck.even_key_ts_part); i++) {
    if (ck.even_key_ts_part[i] != 0 || ck.odd_key_ts_part[i] != 0) rolling_zero = 0;
  }
  for (size_t i = 0; i < sizeof(ck.csalt); i++) {
    if (ck.csalt[i] != 0) rolling_zero = 0;
  }
  CHECK(rolling_zero, "communication_keys_destroy wipes live rolling key/salt material (regression pin for 812381c)");
  CHECK(ck.spsec_keys[0] == NULL, "communication_keys_destroy NULLs freed key slot");
  CHECK(ck.spsec_salt[0] == NULL, "communication_keys_destroy NULLs freed salt slot");

  /* double-destroy must be safe (participant_destroy() relies on this) */
  communication_keys_destroy(&ck);

  /* communication_keys_init(NULL) returns negative */
  CHECK(communication_keys_init(NULL) < 0, "communication_keys_init(NULL) returns negative");

  /* communication_keys_destroy(NULL) doesn't crash */
  communication_keys_destroy(NULL);
  CHECK(1, "communication_keys_destroy(NULL) returns without crash");

  if (g_failures) {
    fprintf(stderr, "\n%d keys check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All keys checks passed.\n");
  return 0;
}
