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
 * @file test_csalt_rederivation.c
 * @brief Verifies a csalt change always invalidates the derived communication keys,
 *        even when the even/odd key cache tag aliases between epochs.
 */

#include "spsec_common.h"
#include "participant.h"
#include "participant_keys.h"
#include "timer.h"
#include "keys.h"

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

int main(void) {
  configure_logging("CRITICAL");

  CommunicationKeys ck;
  memset(&ck, 0, sizeof(ck));
  if (communication_keys_init(&ck) != 0) {
    fprintf(stderr, "communication_keys_init failed\n");
    return 1;
  }

  uint8_t seed[KEY_LEN];
  memset(seed, 0x42, KEY_LEN);
  ck.spsec_keys[3] = spseckey_new(1, seed);
  if (!ck.spsec_keys[3]) {
    fprintf(stderr, "spseckey_new failed\n");
    communication_keys_destroy(&ck);
    return 1;
  }

  // m1 and m2 share their low 16 bits, so the cache tag aliases between them.
  const uint64_t PERIOD = 1ULL << 24;
  uint64_t m1 = 5, m2 = 5 + 0x10000ULL;
  uint8_t ts1[8], ts2[8];
  ts_to_le8(m1 * PERIOD + (1ULL << 23) + 100, ts1); // mid-epoch, well inside
  ts_to_le8(m2 * PERIOD + (1ULL << 23) + 100, ts2);

  uint8_t csalt_a[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  uint8_t csalt_b[4] = {0xBB, 0xBB, 0xBB, 0xBB};

  printf("Case 1: derive keys under csalt A at epoch m1...\n");
  communication_keys_set_csalt(&ck, csalt_a);
  CHECK(communication_keys_update(&ck, ts1) == 0, "Case 1: update succeeds");
  CHECK(!is_all_zero(ck.even_key, KEY_LEN), "Case 1: even key derived");
  CHECK(!is_all_zero(ck.odd_key, KEY_LEN), "Case 1: odd key derived");
  uint8_t even_a[KEY_LEN], odd_a[KEY_LEN];
  memcpy(even_a, ck.even_key, KEY_LEN);
  memcpy(odd_a, ck.odd_key, KEY_LEN);

  printf("Case 2: new csalt B at an aliasing epoch (m2, same low 16 bits "
        "as m1) must still re-derive...\n");
  communication_keys_set_csalt(&ck, csalt_b);
  CHECK(is_all_zero(ck.even_key_ts_part, sizeof(ck.even_key_ts_part)),
        "Case 2: even_key_ts_part cleared by the csalt change");
  CHECK(is_all_zero(ck.odd_key_ts_part, sizeof(ck.odd_key_ts_part)),
        "Case 2: odd_key_ts_part cleared by the csalt change");

  CHECK(communication_keys_update(&ck, ts2) == 0,
        "Case 2: update succeeds after the csalt change");
  CHECK(!is_all_zero(ck.even_key, KEY_LEN),
        "Case 2: even key re-derived (not stale)");
  CHECK(!is_all_zero(ck.odd_key, KEY_LEN),
        "Case 2: odd key re-derived (not stale)");
  CHECK(memcmp(ck.even_key, even_a, KEY_LEN) != 0,
        "Case 2: even key differs from the stale csalt-A key");
  CHECK(memcmp(ck.odd_key, odd_a, KEY_LEN) != 0,
        "Case 2: odd key differs from the stale csalt-A key");

  printf("Case 3: same csalt, same epoch -> cache still suppresses "
        "redundant derivation...\n");
  {
    uint8_t even_before[KEY_LEN], odd_before[KEY_LEN];
    memcpy(even_before, ck.even_key, KEY_LEN);
    memcpy(odd_before, ck.odd_key, KEY_LEN);
    communication_keys_set_csalt(&ck, csalt_b); // unchanged
    CHECK(!is_all_zero(ck.even_key_ts_part, sizeof(ck.even_key_ts_part)),
          "Case 3: cache tag NOT cleared when csalt is unchanged");
    CHECK(communication_keys_update(&ck, ts2) == 0, "Case 3: update succeeds");
    CHECK(memcmp(ck.even_key, even_before, KEY_LEN) == 0,
          "Case 3: even key unchanged when nothing changed");
    CHECK(memcmp(ck.odd_key, odd_before, KEY_LEN) == 0,
          "Case 3: odd key unchanged when nothing changed");
  }

  communication_keys_destroy(&ck);

  if (g_failures == 0) {
    printf("All csalt re-derivation tests passed.\n");
    return 0;
  }
  fprintf(stderr, "%d check(s) failed.\n", g_failures);
  return 1;
}
