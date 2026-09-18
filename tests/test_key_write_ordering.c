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
 * @file test_key_write_ordering.c
 * @brief Tests key write ordering, write-once enforcement, and seed rotation.
 */

#include "keys.h"
#include "nvol_storage.h"
#include "participant.h"
#include "platform_nvol_storage.h"
#include "register_validation.h"
#include "spsec_common.h"
#include "spsec_errors.h"
#include "spsec_registers.h"
#include "timer.h"
#include "../spsec_participant/register_write_internal.h"

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

static void u32_to_le(uint32_t v, uint8_t out_ptr[4]) {
  out_ptr[0] = (uint8_t)(v & 0xFF);
  out_ptr[1] = (uint8_t)((v >> 8) & 0xFF);
  out_ptr[2] = (uint8_t)((v >> 16) & 0xFF);
  out_ptr[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = 42;
  p_ptr->state_info.state = SPSEC_STATE_CONFIGURATION;
  p_ptr->state_info.status = 0x04;
  timer_init(&p_ptr->timer, 8);
  communication_keys_init(&p_ptr->comm_keys);

  /* Clean up storage directory for isolation */
  platform_nvol_storage_init("/tmp/test_key_order", true);
}

static void teardown_test_participant(Participant *p_ptr) {
  communication_keys_destroy(&p_ptr->comm_keys);
  timer_destroy(&p_ptr->timer);
  int rc = system("rm -rf /tmp/test_key_order");
  (void)rc;
}

static void test_provisioning_key_id_first(void) {
  printf("Testing Provisioning Key write disallowed via protocol...\n");
  Participant p;
  init_test_participant(&p);

  uint8_t id_data[4];
  u32_to_le(0xA1B2C3D4, id_data);

  /* Provisioning Key ID and Key material writes must be rejected (manufacturer only) */
  spsec_ret_t ret = apply_key_id(&p, 1, id_data, 4);
  CHECK(ret == SPSEC_ERROR_REGISTER_ACCESS_DENIED, "apply_key_id for index 1 rejected with ACCESS_DENIED");

  uint8_t key_data[KEY_LEN];
  memset(key_data, 0x55, KEY_LEN);
  ret = apply_key(&p, 1, key_data);
  CHECK(ret == SPSEC_ERROR_REGISTER_ACCESS_DENIED, "apply_key for index 1 rejected with ACCESS_DENIED");

  teardown_test_participant(&p);
}

static void test_integrator_key_id_first(void) {
  printf("Testing Integrator Key ID-first write ordering...\n");
  Participant p;
  init_test_participant(&p);

  uint8_t id_data[4];
  u32_to_le(0xB2C3D4E5, id_data);

  /* Write Key ID (Register 0x42 / index 2) first */
  spsec_ret_t ret = apply_key_id(&p, 2, id_data, 4);
  CHECK(ret == SPSEC_SUCCESS, "apply_key_id for index 2 succeeds");

  /* Write Key Material (Register 0x22 / index 2) */
  uint8_t key_data[KEY_LEN];
  memset(key_data, 0x77, KEY_LEN);
  ret = apply_key(&p, 2, key_data);
  CHECK(ret == SPSEC_SUCCESS, "apply_key succeeds for index 2 after ID set");
  CHECK(register_is_key_material_set(&p, 2), "key material is set for index 2");

  /* Attempt overwrite -> rejected */
  ret = apply_key(&p, 2, key_data);
  CHECK(ret == SPSEC_ERROR_KEY_ALREADY_SET, "overwrite of Integrator key rejected");

  teardown_test_participant(&p);
}

static void test_seed_key_rotation_allowed(void) {
  printf("Testing Seed Key rotation (multiple writes permitted)...\n");
  Participant p;
  init_test_participant(&p);

  uint8_t id_data[4];
  u32_to_le(0x10000001, id_data);
  CHECK(apply_key_id(&p, 3, id_data, 4) == SPSEC_SUCCESS, "seed key id 1 set");

  uint8_t key1[KEY_LEN];
  memset(key1, 0x11, KEY_LEN);
  CHECK(apply_key(&p, 3, key1) == SPSEC_SUCCESS, "seed key material 1 set");

  /* Rotation: write new Seed key ID and material */
  u32_to_le(0x10000002, id_data);
  CHECK(apply_key_id(&p, 3, id_data, 4) == SPSEC_SUCCESS, "seed key id rotation succeeds");

  uint8_t key2[KEY_LEN];
  memset(key2, 0x22, KEY_LEN);
  CHECK(apply_key(&p, 3, key2) == SPSEC_SUCCESS, "seed key material rotation succeeds");
  CHECK(memcmp(p.comm_keys.spsec_keys[3]->key, key2, KEY_LEN) == 0,
        "seed key reflects newly rotated material");

  teardown_test_participant(&p);
}

int main(void) {
  test_provisioning_key_id_first();
  test_integrator_key_id_first();
  test_seed_key_rotation_allowed();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d key_write_ordering check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All key_write_ordering checks passed.\n");
  return 0;
}
