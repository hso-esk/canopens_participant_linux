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
 * @file test_participant_storage.c
 * @brief Unit tests for participant_storage_load_all() and participant_storage_delete_key().
 */

#include "spsec_common.h"
#include "participant.h"
#include "timer.h"
#include "spsec_errors.h"
#include "spsec_registers.h"
#include "keys.h"
#include "nvol_storage.h"
#include "participant_storage.h"
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
  if (nvol_storage_init("./test_participant_storage_data", false) < 0) {
    fprintf(stderr, "Failed to initialize nvol_storage\n");
    return 1;
  }

  Participant p;
  if (init_test_participant(&p) != 0) {
    nvol_storage_cleanup();
    cleanup_data_dir("rm -rf ./test_participant_storage_data");
    return 1;
  }

  // Initialize communication keys (zero key and zero salt)
  if (communication_keys_init(&p.comm_keys) != 0) {
    fprintf(stderr, "communication_keys_init failed\n");
    destroy_test_participant(&p);
    nvol_storage_cleanup();
    cleanup_data_dir("rm -rf ./test_participant_storage_data");
    return 1;
  }

  uint8_t key_buf_a[KEY_LEN];
  uint8_t key_buf_b[KEY_LEN];

  // ============================================================
  // Case 1: Fresh/empty storage
  // ============================================================
  printf("Case 1: Fresh/empty storage...\n");
  {
    signed char ret = participant_storage_load_all(&p);
    CHECK(ret == 0, "Case 1: participant_storage_load_all returns 0");
    CHECK(p.participant_id == 0, "Case 1: participant_id remains 0");
    CHECK(p.heartbeat.timing == 0, "Case 1: heartbeat.timing remains 0");
  }

  // ============================================================
  // Case 2: Key round-trip (Provisioning key saved by manufacturer and reloaded)
  // ============================================================
  printf("Case 2: Key round-trip...\n");
  {
    memset(key_buf_a, 0xAB, KEY_LEN);
    p.comm_keys.spsec_keys[1] = spseckey_new(1, key_buf_a);
    CHECK(p.comm_keys.spsec_keys[1] != NULL, "Case 2: key allocated");
    spsec_ret_t sret = participant_storage_save_key(&p, 1);
    CHECK(sret == SPSEC_SUCCESS, "Case 2: participant_storage_save_key returns SPSEC_SUCCESS");
    CHECK(memcmp(spseckey_get_key(p.comm_keys.spsec_keys[1]), key_buf_a, KEY_LEN) == 0,
          "Case 2: key material matches original buffer");

    // Simulate fresh process: free in-memory key
    spseckey_free(p.comm_keys.spsec_keys[1]);
    p.comm_keys.spsec_keys[1] = NULL;

    // Load from storage
    signed char ret = participant_storage_load_all(&p);
    CHECK(ret == 0, "Case 2: participant_storage_load_all returns 0 after reload");
    CHECK(p.comm_keys.spsec_keys[1] != NULL, "Case 2: slot 1 reloaded from storage");
    CHECK(memcmp(spseckey_get_key(p.comm_keys.spsec_keys[1]), key_buf_a, KEY_LEN) == 0,
          "Case 2: key material matches after reload");

    // Clean up
    spseckey_free(p.comm_keys.spsec_keys[1]);
    p.comm_keys.spsec_keys[1] = NULL;
  }

  // ============================================================
  // Case 3: Valid participant_id from storage
  // ============================================================
  printf("Case 3: Valid participant_id from storage...\n");
  {
    nvol_storage_write_u8("config/participant_id", 42);
    signed char ret = participant_storage_load_all(&p);
    CHECK(ret == 0, "Case 3: participant_storage_load_all returns 0");
    CHECK(p.participant_id == 42, "Case 3: participant_id loaded as 42");
  }

  // ============================================================
  // Case 4: Invalid participant_id rejected
  // ============================================================
  printf("Case 4: Invalid participant_id rejected...\n");
  {
    p.participant_id = 99; // Set to a known value first
    nvol_storage_write_u8("config/participant_id", 0); // 0 is out of valid 1-127 range
    signed char ret = participant_storage_load_all(&p);
    CHECK(ret == 0, "Case 4: participant_storage_load_all returns 0");
    CHECK(p.participant_id == 99, "Case 4: participant_id unchanged (invalid 0 rejected)");
  }

  // ============================================================
  // Case 5: Manufacturer reset flag
  // ============================================================
  printf("Case 5: Manufacturer reset flag...\n");
  {
    // Write two distinct keys (indices 2 and 3)
    memset(key_buf_a, 0xCD, KEY_LEN);
    memset(key_buf_b, 0xEF, KEY_LEN);

    spsec_ret_t ret = apply_key(&p, 2, key_buf_a);
    CHECK(ret == SPSEC_SUCCESS, "Case 5: apply_key index 2 succeeds");
    ret = apply_key(&p, 3, key_buf_b);
    CHECK(ret == SPSEC_SUCCESS, "Case 5: apply_key index 3 succeeds");

    // Free in-memory slots to simulate fresh process
    spseckey_free(p.comm_keys.spsec_keys[2]);
    p.comm_keys.spsec_keys[2] = NULL;
    spseckey_free(p.comm_keys.spsec_keys[3]);
    p.comm_keys.spsec_keys[3] = NULL;

    // Set manufacturer reset flag
    nvol_storage_write_u8("config/manufacturer_reset", 1);

    // Call load_all - this will reload keys 2&3 first, then process reset flag
    ret = participant_storage_load_all(&p);
    CHECK(ret == 0, "Case 5: participant_storage_load_all returns 0");

    // (a) Flag should be cleared
    uint8_t reset_val = 0xFF;
    nvol_storage_read_u8("config/manufacturer_reset", &reset_val);
    CHECK(reset_val == 0, "Case 5a: manufacturer_reset flag cleared to 0");

    // (b) Key files should be deleted
    CHECK(nvol_storage_exists("keys/integrator_key") == false,
          "Case 5b: integrator_key deleted from storage");
    CHECK(nvol_storage_exists("keys/seed_key") == false,
          "Case 5b: seed_key deleted from storage");

    // Cleanup: free any reloaded keys (load_all reloads keys 2&3 before reset runs)
    if (p.comm_keys.spsec_keys[2] != NULL) {
      spseckey_free(p.comm_keys.spsec_keys[2]);
      p.comm_keys.spsec_keys[2] = NULL;
    }
    if (p.comm_keys.spsec_keys[3] != NULL) {
      spseckey_free(p.comm_keys.spsec_keys[3]);
      p.comm_keys.spsec_keys[3] = NULL;
    }
  }

  // ============================================================
  // Case 6: participant_storage_delete_key() direct test
  // ============================================================
  printf("Case 6: participant_storage_delete_key() direct test...\n");
  {
    memset(key_buf_a, 0x12, KEY_LEN);
    spsec_ret_t ret = apply_key(&p, 3, key_buf_a);
    CHECK(ret == SPSEC_SUCCESS, "Case 6: apply_key index 3 succeeds");

    CHECK(nvol_storage_exists("keys/seed_key") == true,
          "Case 6: seed_key exists before delete");

    signed char del_ret = participant_storage_delete_key(&p, 3);
    CHECK(del_ret == 0, "Case 6: participant_storage_delete_key returns 0");

    CHECK(nvol_storage_exists("keys/seed_key") == false,
          "Case 6: seed_key deleted from storage");

    // participant_storage_delete_key does NOT free in-memory slot
    if (p.comm_keys.spsec_keys[3] != NULL) {
      spseckey_free(p.comm_keys.spsec_keys[3]);
      p.comm_keys.spsec_keys[3] = NULL;
    }
  }

  // ============================================================
  // Case 7: participant_storage_delete_key() edge cases
  // ============================================================
  printf("Case 7: participant_storage_delete_key() edge cases...\n");
  {
    CHECK(participant_storage_delete_key(NULL, 1) == -1,
          "Case 7: NULL participant returns -1");
    CHECK(participant_storage_delete_key(&p, 0) == -1,
          "Case 7: key_index 0 returns -1");
    CHECK(participant_storage_delete_key(&p, 4) == -1,
          "Case 7: key_index 4 returns -1");
  }

  // ============================================================
  // Final cleanup
  // ============================================================
  cleanup_participant_keys(&p);
  communication_keys_destroy(&p.comm_keys);
  destroy_test_participant(&p);
  nvol_storage_cleanup();
  cleanup_data_dir("rm -rf ./test_participant_storage_data");

  if (g_failures) {
    fprintf(stderr, "\n%d participant_storage check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All participant_storage checks passed.\n");
  return 0;
}
