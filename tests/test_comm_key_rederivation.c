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
 * @file test_comm_key_rederivation.c
 * @brief Verifies that writing a new Seed key immediately re-derives communication keys.
 */

#include "spsec_common.h"
#include "participant.h"
#include "participant_keys.h"
#include "timer.h"
#include "spsec_errors.h"
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

/** @brief Convert a 64-bit value to an 8-byte little-endian array. */
static void ts_to_le8(uint64_t v, uint8_t out_ptr[8]) {
  for (int i = 0; i < 8; ++i)
    out_ptr[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}

static int is_all_zero(const uint8_t *buf_ptr, size_t len) {
  for (size_t i = 0; i < len; ++i)
    if (buf_ptr[i] != 0)
      return 0;
  return 1;
}

static void cleanup_data_dir(const char *cmd_ptr) {
  int rc = system(cmd_ptr);
  (void)rc;
}

int main(void) {
  configure_logging("CRITICAL");

  if (nvol_storage_init("./test_comm_key_rederivation_data", false) < 0) {
    fprintf(stderr, "Failed to initialize nvol_storage\n");
    return 1;
  }

  Participant p;
  memset(&p, 0, sizeof(p));
  if (timer_init(&p.timer, 8) != 0) {
    fprintf(stderr, "timer_init failed\n");
    nvol_storage_cleanup();
    cleanup_data_dir("rm -rf ./test_comm_key_rederivation_data");
    return 1;
  }
  if (communication_keys_init(&p.comm_keys) != 0) {
    fprintf(stderr, "communication_keys_init failed\n");
    timer_destroy(&p.timer);
    nvol_storage_cleanup();
    cleanup_data_dir("rm -rf ./test_comm_key_rederivation_data");
    return 1;
  }

  /* A timestamp comfortably past the first bit-23 transition, so both the even
   * and odd transition points are well defined. Held CONSTANT for the whole
   * test: that is what isolates "the seed changed" from "the epoch rolled". */
  uint8_t ts[8];
  ts_to_le8((uint64_t)0x05000000ULL, ts);

  uint8_t seed_a[KEY_LEN], seed_b[KEY_LEN], salt[SALT_LEN];
  memset(seed_a, 0xA1, KEY_LEN);
  memset(seed_b, 0xB2, KEY_LEN);
  memset(salt, 0x5A, SALT_LEN);
  memset(p.comm_keys.csalt, 0x7C, sizeof(p.comm_keys.csalt));

  uint8_t even_a[KEY_LEN], odd_a[KEY_LEN];

  /* ---------------------------------------------------------------
   * Case 1: install Seed A, derive the communication keys.
   * --------------------------------------------------------------- */
  printf("Case 1: derive communication keys from Seed A...\n");
  CHECK(apply_key(&p, 3, seed_a) == SPSEC_SUCCESS, "Case 1: Seed A installed");
  CHECK(apply_salt(&p, 3, salt) == SPSEC_SUCCESS, "Case 1: Seed salt installed");

  CHECK(communication_keys_update(&p.comm_keys, ts) == 0,
        "Case 1: communication_keys_update() succeeds");
  CHECK(!is_all_zero(p.comm_keys.even_key, KEY_LEN),
        "Case 1: even key was actually derived");
  CHECK(!is_all_zero(p.comm_keys.odd_key, KEY_LEN),
        "Case 1: odd key was actually derived");
  CHECK(memcmp(p.comm_keys.even_key, p.comm_keys.odd_key, KEY_LEN) != 0,
        "Case 1: even and odd keys differ from each other");
  memcpy(even_a, p.comm_keys.even_key, KEY_LEN);
  memcpy(odd_a, p.comm_keys.odd_key, KEY_LEN);

  // Case 2: a new Seed key must invalidate the derived-key cache - without
  // this fix the ts_parts survive and mask the new seed.
  printf("Case 2: Seed key write invalidates the derived-key cache...\n");
  CHECK(apply_key(&p, 3, seed_b) == SPSEC_SUCCESS, "Case 2: Seed B installed");
  CHECK(is_all_zero(p.comm_keys.even_key_ts_part,
                    sizeof(p.comm_keys.even_key_ts_part)),
        "Case 2: even_key_ts_part cleared by the Seed write");
  CHECK(is_all_zero(p.comm_keys.odd_key_ts_part,
                    sizeof(p.comm_keys.odd_key_ts_part)),
        "Case 2: odd_key_ts_part cleared by the Seed write");
  CHECK(is_all_zero(p.comm_keys.even_key, KEY_LEN),
        "Case 2: stale even key does not linger in RAM");
  CHECK(is_all_zero(p.comm_keys.odd_key, KEY_LEN),
        "Case 2: stale odd key does not linger in RAM");

  // Case 3: same timestamp + new seed must yield new keys - the cache bug
  // would leave Seed A's keys in place.
  printf("Case 3: same timestamp + new Seed key -> different keys...\n");
  CHECK(communication_keys_update(&p.comm_keys, ts) == 0,
        "Case 3: communication_keys_update() succeeds after the rotation");
  CHECK(!is_all_zero(p.comm_keys.even_key, KEY_LEN),
        "Case 3: even key re-derived (not left zeroed)");
  CHECK(!is_all_zero(p.comm_keys.odd_key, KEY_LEN),
        "Case 3: odd key re-derived (not left zeroed)");
  CHECK(memcmp(p.comm_keys.even_key, even_a, KEY_LEN) != 0,
        "Case 3: even key changed with the new Seed key");
  CHECK(memcmp(p.comm_keys.odd_key, odd_a, KEY_LEN) != 0,
        "Case 3: odd key changed with the new Seed key");

  // Case 4: rewriting the same seed is still a rotation - must re-derive,
  // landing back on Seed A's keys.
  printf("Case 4: rotating back to Seed A restores Seed A's keys...\n");
  CHECK(apply_key(&p, 3, seed_a) == SPSEC_SUCCESS, "Case 4: Seed A reinstalled");
  CHECK(communication_keys_update(&p.comm_keys, ts) == 0,
        "Case 4: communication_keys_update() succeeds");
  CHECK(memcmp(p.comm_keys.even_key, even_a, KEY_LEN) == 0,
        "Case 4: even key matches Seed A again (derivation is deterministic)");
  CHECK(memcmp(p.comm_keys.odd_key, odd_a, KEY_LEN) == 0,
        "Case 4: odd key matches Seed A again");

  // Case 5: unchanged seed + timestamp must not re-derive needlessly.
  printf("Case 5: cache still suppresses redundant derivation...\n");
  {
    uint8_t even_before[KEY_LEN], odd_before[KEY_LEN];
    memcpy(even_before, p.comm_keys.even_key, KEY_LEN);
    memcpy(odd_before, p.comm_keys.odd_key, KEY_LEN);
    CHECK(communication_keys_update(&p.comm_keys, ts) == 0,
          "Case 5: communication_keys_update() succeeds");
    CHECK(memcmp(p.comm_keys.even_key, even_before, KEY_LEN) == 0,
          "Case 5: even key unchanged when nothing changed");
    CHECK(memcmp(p.comm_keys.odd_key, odd_before, KEY_LEN) == 0,
          "Case 5: odd key unchanged when nothing changed");
  }

  communication_keys_destroy(&p.comm_keys);
  timer_destroy(&p.timer);
  nvol_storage_cleanup();
  cleanup_data_dir("rm -rf ./test_comm_key_rederivation_data");

  if (g_failures == 0) {
    printf("All communication-key re-derivation tests passed.\n");
    return 0;
  }
  fprintf(stderr, "%d check(s) failed.\n", g_failures);
  return 1;
}
