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
 * @file test_register_write_apply.c
 * @brief Unit tests for apply_key(), apply_salt(), apply_key_id() functions.
 */

#include "spsec_common.h"
#include "participant.h"
#include "timer.h"
#include "spsec_errors.h"
#include "spsec_registers.h"
#include "keys.h"
#include "nvol_storage.h"
#include "../spsec_participant/register_write_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;
#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg);                                    \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

// Remove the test's scratch data directory.
static void cleanup_data_dir(const char *cmd_ptr) {
  int rc = system(cmd_ptr);
  (void)rc;
}

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

/**
 * @brief Encode a 32-bit key_id into a little-endian byte array.
 */
static void encode_key_id_le(uint32_t key_id, uint8_t data_ptr[4]) {
  data_ptr[0] = (uint8_t)(key_id & 0xFF);
  data_ptr[1] = (uint8_t)((key_id >> 8) & 0xFF);
  data_ptr[2] = (uint8_t)((key_id >> 16) & 0xFF);
  data_ptr[3] = (uint8_t)((key_id >> 24) & 0xFF);
}

/**
 * @brief Helper to clean up all allocated keys and salts in the participant.
 */
static void cleanup_participant_keys(Participant *p_ptr) {
  for (int i = 0; i < 4; i++) {
    if (p_ptr->comm_keys.spsec_keys[i] != NULL) {
      spseckey_free(p_ptr->comm_keys.spsec_keys[i]);
      p_ptr->comm_keys.spsec_keys[i] = NULL;
    }
    if (p_ptr->comm_keys.spsec_salt[i] != NULL) {
      spsecsalt_free(p_ptr->comm_keys.spsec_salt[i]);
      p_ptr->comm_keys.spsec_salt[i] = NULL;
    }
  }
}

int main(void) {
  configure_logging("CRITICAL");

  // Initialize nvol_storage at top of main()
  if (nvol_storage_init("./test_register_write_apply_data", false) < 0) {
    fprintf(stderr, "Failed to initialize nvol_storage\n");
    return 1;
  }

  Participant p;
  if (init_test_participant(&p) != 0) {
    nvol_storage_cleanup();
    cleanup_data_dir("rm -rf ./test_register_write_apply_data");
    return 1;
  }

  // Initialize communication keys (zero key and zero salt)
  if (communication_keys_init(&p.comm_keys) != 0) {
    fprintf(stderr, "communication_keys_init failed\n");
    destroy_test_participant(&p);
    nvol_storage_cleanup();
    cleanup_data_dir("rm -rf ./test_register_write_apply_data");
    return 1;
  }

  uint8_t test_key[KEY_LEN];
  uint8_t test_salt[SALT_LEN];

  // ============================================================
  // A. apply_key() tests
  // ============================================================

  // Case 1: Fresh slot (index 3, seed, no write-once) -> SPSEC_SUCCESS,
  // slot non-NULL, key_id is 0
  printf("Testing apply_key() Case 1: Fresh slot (index 3, seed)...\n");
  memset(test_key, 0xAA, KEY_LEN);
  {
    spsec_ret_t ret = apply_key(&p, 3, test_key);
    CHECK(ret == SPSEC_SUCCESS, "Case 1: apply_key returns SPSEC_SUCCESS");
    CHECK(p.comm_keys.spsec_keys[3] != NULL, "Case 1: slot is non-NULL");
    CHECK(p.comm_keys.spsec_keys[3]->key_id == 0, "Case 1: key_id is 0 (default)");
    // Verify key material was stored
    CHECK(memcmp(spseckey_get_key(p.comm_keys.spsec_keys[3]), test_key, KEY_LEN) == 0,
          "Case 1: key material matches");
  }
  // Clean up seed key for next test
  spseckey_free(p.comm_keys.spsec_keys[3]);
  p.comm_keys.spsec_keys[3] = NULL;

  // Case 2: Index 1 (provisioning) disallowed via protocol -> SPSEC_ERROR_REGISTER_ACCESS_DENIED
  printf("Testing apply_key() Case 2: Index 1 (provisioning) disallowed via protocol...\n");
  memset(test_key, 0xBB, KEY_LEN);
  {
    spsec_ret_t ret = apply_key(&p, 1, test_key);
    CHECK(ret == SPSEC_ERROR_REGISTER_ACCESS_DENIED, "Case 2: returns SPSEC_ERROR_REGISTER_ACCESS_DENIED");
    CHECK(p.comm_keys.spsec_keys[1] == NULL, "Case 2: slot remains NULL");
  }

  // Case 3: Index 2 (integrator), same already-set pattern -> SPSEC_ERROR_KEY_ALREADY_SET.
  printf("Testing apply_key() Case 3: Index 2 (integrator) write-once...\n");
  memset(test_key, 0xDD, KEY_LEN);
  {
    // First write
    spsec_ret_t ret = apply_key(&p, 2, test_key);
    CHECK(ret == SPSEC_SUCCESS, "Case 3a: first write returns SPSEC_SUCCESS");
    CHECK(p.comm_keys.spsec_keys[2] != NULL, "Case 3a: slot is non-NULL");

    // Arm write-once by setting a non-INVALID, non-RESERVED key_id
    p.comm_keys.spsec_keys[2]->key_id = 0xDEADBEEF;

    // Second write should fail when Prov Key is not installed
    memset(test_key, 0xEE, KEY_LEN);
    ret = apply_key(&p, 2, test_key);
    CHECK(ret == SPSEC_ERROR_KEY_ALREADY_SET, "Case 3b: second write returns SPSEC_ERROR_KEY_ALREADY_SET");
  }

  // Case 3c: Index 2 (integrator) when Provisioning Key IS installed -> rewrite allowed (Rule 4)
  printf("Testing apply_key() Case 3c: Index 2 with Provisioning Key installed allows rewrite...\n");
  {
    uint8_t prov_key[KEY_LEN];
    memset(prov_key, 0x11, KEY_LEN);
    p.comm_keys.spsec_keys[1] = spseckey_new(0x11111111u, prov_key);

    // With Prov Key installed, writing Integrator Key succeeds even if already set
    memset(test_key, 0x99, KEY_LEN);
    spsec_ret_t ret = apply_key(&p, 2, test_key);
    CHECK(ret == SPSEC_SUCCESS, "Case 3c: rewrite succeeds when Prov Key is installed");
    CHECK(memcmp(spseckey_get_key(p.comm_keys.spsec_keys[2]), test_key, KEY_LEN) == 0,
          "Case 3c: new key material stored");

    // Clean up prov key
    spseckey_free(p.comm_keys.spsec_keys[1]);
    p.comm_keys.spsec_keys[1] = NULL;
  }
  // Clean up
  spseckey_free(p.comm_keys.spsec_keys[2]);
  p.comm_keys.spsec_keys[2] = NULL;

  // ============================================================
  // B. apply_salt() tests
  // ============================================================

  // Case 4: Fresh slot -> SPSEC_SUCCESS, slot non-NULL.
  // Overwrite same slot -> SPSEC_SUCCESS, verify new bytes via spsecsalt_get_salt()
  printf("Testing apply_salt() Case 4: Fresh slot and overwrite...\n");
  memset(test_salt, 0x11, SALT_LEN);
  {
    // Fresh slot
    spsec_ret_t ret = apply_salt(&p, 3, test_salt);
    CHECK(ret == SPSEC_SUCCESS, "Case 4a: fresh slot returns SPSEC_SUCCESS");
    CHECK(p.comm_keys.spsec_salt[3] != NULL, "Case 4a: slot is non-NULL");
    CHECK(memcmp(spsecsalt_get_salt(p.comm_keys.spsec_salt[3]), test_salt, SALT_LEN) == 0,
          "Case 4a: salt material matches");

    // Overwrite same slot
    memset(test_salt, 0x22, SALT_LEN);
    ret = apply_salt(&p, 3, test_salt);
    CHECK(ret == SPSEC_SUCCESS, "Case 4b: overwrite returns SPSEC_SUCCESS");
    CHECK(memcmp(spsecsalt_get_salt(p.comm_keys.spsec_salt[3]), test_salt, SALT_LEN) == 0,
          "Case 4b: new salt material verified via spsecsalt_get_salt()");
  }
  // Clean up
  spsecsalt_free(p.comm_keys.spsec_salt[3]);
  p.comm_keys.spsec_salt[3] = NULL;

  // ============================================================
  // C. apply_key_id() tests
  // ============================================================

  // Case 5: Wrong data_len (3 instead of 4) -> SPSEC_ERROR_INVALID_ARGUMENT, no mutation
  printf("Testing apply_key_id() Case 5: Wrong data_len...\n");
  {
    uint8_t data[3] = {0x78, 0x56, 0x34}; // truncated
    spsec_ret_t ret = apply_key_id(&p, 3, data, 3);
    CHECK(ret == SPSEC_ERROR_INVALID_ARGUMENT, "Case 5: returns SPSEC_ERROR_INVALID_ARGUMENT");
    CHECK(p.comm_keys.spsec_keys[3] == NULL, "Case 5: no mutation (slot still NULL)");
  }

  // Case 6: key_id all zeros (SPSEC_KEY_ID_INVALID) -> SPSEC_ERROR_KEY_INVALID_ID
  printf("Testing apply_key_id() Case 6: key_id all zeros (INVALID)...\n");
  {
    uint8_t data[4];
    encode_key_id_le(SPSEC_KEY_ID_INVALID, data); // 0x00000000
    spsec_ret_t ret = apply_key_id(&p, 3, data, 4);
    CHECK(ret == SPSEC_ERROR_KEY_INVALID_ID, "Case 6: returns SPSEC_ERROR_KEY_INVALID_ID");
    CHECK(p.comm_keys.spsec_keys[3] == NULL, "Case 6: no mutation (slot still NULL)");
  }

  // Case 7: Valid key_id (0x12345678, little-endian encode) on fresh slot (index 3)
  // -> SPSEC_SUCCESS, slot's key_id becomes 0x12345678
  printf("Testing apply_key_id() Case 7: Valid key_id on fresh slot...\n");
  {
    uint8_t data[4];
    encode_key_id_le(0x12345678, data);
    spsec_ret_t ret = apply_key_id(&p, 3, data, 4);
    CHECK(ret == SPSEC_SUCCESS, "Case 7: returns SPSEC_SUCCESS");
    CHECK(p.comm_keys.spsec_keys[3] != NULL, "Case 7: slot is non-NULL");
    CHECK(p.comm_keys.spsec_keys[3]->key_id == 0x12345678,
          "Case 7: slot's key_id becomes 0x12345678");
    // Key material should be zero (initialized with zero_key)
    uint8_t zero_key[KEY_LEN] = {0};
    CHECK(memcmp(spseckey_get_key(p.comm_keys.spsec_keys[3]), zero_key, KEY_LEN) == 0,
          "Case 7: key material is zero-initialized");
  }
  // Clean up
  spseckey_free(p.comm_keys.spsec_keys[3]);
  p.comm_keys.spsec_keys[3] = NULL;

  // Case 8: Index 1 key ID disallowed via protocol -> SPSEC_ERROR_REGISTER_ACCESS_DENIED
  printf("Testing apply_key_id() Case 8: Index 1 disallowed via protocol...\n");
  {
    uint8_t data[4];
    encode_key_id_le(0x87654321, data);
    spsec_ret_t ret = apply_key_id(&p, 1, data, 4);
    CHECK(ret == SPSEC_ERROR_REGISTER_ACCESS_DENIED, "Case 8: returns SPSEC_ERROR_REGISTER_ACCESS_DENIED");
  }

  // ============================================================
  // Final cleanup
  // ============================================================
  cleanup_participant_keys(&p);
  communication_keys_destroy(&p.comm_keys);
  destroy_test_participant(&p);
  nvol_storage_cleanup();
  cleanup_data_dir("rm -rf ./test_register_write_apply_data");

  if (g_failures) {
    fprintf(stderr, "\n%d register_write_apply check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All register_write_apply checks passed.\n");
  return 0;
}
