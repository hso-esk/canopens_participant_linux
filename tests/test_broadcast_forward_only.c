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

/* Pins forward-only broadcast adoption to prevent replay of older timestamps. */

#include "../spsec_participant/session_loops_internal.h"
#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_keys.h"
#include "spsec_common.h"
#include "spsec_errors.h"
#include "utils_bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;
#define CHECK(cond, msg_ptr)                                                   \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s (line %d)\n", msg_ptr, __LINE__);            \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

#define TEST_PID 7
#define SYNC_BROADCAST_ADDR (0x02210000u | ((uint32_t)CPMT_SYNC << 8))

static void init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = TEST_PID;
  p_ptr->crypto_algorithm = CRYPTO_ALGO_AES_GCM;
  crypto_handler_init(&p_ptr->crypto_handler);
  crypto_handler_select_algorithm(&p_ptr->crypto_handler,
                                  p_ptr->crypto_algorithm);
  communication_keys_init(&p_ptr->comm_keys);
  timer_init(&p_ptr->timer, 8);

  uint8_t seed[KEY_LEN];
  for (int i = 0; i < KEY_LEN; i++)
    seed[i] = (uint8_t)(0x30 + i);
  p_ptr->comm_keys.spsec_keys[3] = spseckey_new(0x44444444, seed);

  uint8_t salt[SALT_LEN] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7};
  p_ptr->comm_keys.spsec_salt[3] = (SPsecSalt *)malloc(sizeof(SPsecSalt));
  spsecsalt_init(p_ptr->comm_keys.spsec_salt[3], salt);

  uint8_t csalt[4] = {0x11, 0x22, 0x33, 0x44};
  communication_keys_set_csalt(&p_ptr->comm_keys, csalt);
}

static void teardown_test_participant(Participant *p_ptr) {
  communication_keys_destroy(&p_ptr->comm_keys);
  crypto_handler_destroy(&p_ptr->crypto_handler);
  timer_destroy(&p_ptr->timer);
}

/* Build encrypted Sync Time Broadcast with given timestamp and wire nonce. */
static SPsecSyncTimeBroadcastMessage *
make_broadcast(Participant *p_ptr, uint64_t nonce_ts, uint64_t content_ts,
               uint8_t *key_ptr) {
  uint8_t nonce_ts_le[8], content_ts_le[8];
  u64_to_bytes_le(nonce_ts, nonce_ts_le);
  u64_to_bytes_le(content_ts, content_ts_le);

  uint8_t nonce[REQUIRED_NONCE_LEN] = {0};
  memcpy(nonce, nonce_ts_le, 8);
  nonce[8] = (uint8_t)(SYNC_BROADCAST_ADDR & 0xFF);
  nonce[9] = (uint8_t)((SYNC_BROADCAST_ADDR >> 8) & 0xFF);
  memcpy(nonce + 10, p_ptr->comm_keys.spsec_salt[3]->salt, 6);

  uint8_t aad[DATA_AAD_LEN];
  aad[0] = (uint8_t)(SYNC_BROADCAST_ADDR & 0xFF);
  aad[1] = (uint8_t)((SYNC_BROADCAST_ADDR >> 8) & 0xFF);
  aad[2] = (uint8_t)((SYNC_BROADCAST_ADDR >> 16) & 0xFF);
  aad[3] = (uint8_t)((SYNC_BROADCAST_ADDR >> 24) & 0xFF);
  aad[4] = TIMESTAMP_SIZE + 2;

  uint8_t plaintext[TIMESTAMP_SIZE + 2];
  memcpy(plaintext, content_ts_le, TIMESTAMP_SIZE);
  plaintext[8] = 0;
  plaintext[9] = 0;

  uint8_t ciphertext[TIMESTAMP_SIZE + 2];
  uint8_t tag[AUTH_TAG_SIZE];
  crypto_handler_set_context(&p_ptr->crypto_handler, key_ptr, nonce, 12,
                             AUTH_TAG_SIZE);
  crypto_handler_encrypt_with_assoc_data(&p_ptr->crypto_handler, plaintext,
                                         sizeof(plaintext), ciphertext, tag,
                                         aad, sizeof(aad));

  uint16_t lsb = (uint16_t)(nonce_ts_le[0] | ((nonce_ts_le[1] & 0x0F) << 8));
  uint16_t hdr = (uint16_t)(lsb & 0x0FFF);
  uint8_t trailer_ts[8] = {0};
  trailer_ts[0] = (uint8_t)(hdr & 0xFF);
  trailer_ts[1] = (uint8_t)((hdr >> 8) & 0xFF);

  SPsecAppData *sad_ptr = spsecappdata_new(SYNC_BROADCAST_ADDR, ciphertext,
                                           sizeof(ciphertext), 0, trailer_ts,
                                           tag, sizeof(tag));
  SPsecSyncTimeBroadcastMessage *tsb_ptr = spsecsynctimebroadcast_new(0);
  tsb_ptr->spsec_app_data_ptr = sad_ptr;
  return tsb_ptr;
}

int main(void) {
  configure_logging("CRITICAL");

  Participant p;
  init_test_participant(&p);

  /* Establish a local clock inside a stable epoch. */
  const uint64_t base_ts = 0x05800000ULL + 1000ULL;
  uint8_t base_le[8];
  u64_to_bytes_le(base_ts, base_le);
  timer_set_timestamp(&p.timer, base_le);
  communication_keys_update(&p.comm_keys, base_le);
  uint8_t *key_ptr = p.comm_keys.use_odd_key ? p.comm_keys.odd_key
                                              : p.comm_keys.even_key;

  /* --- Case 1: first broadcast is accepted (watermark is 0) --- */
  uint64_t ts1 = base_ts + 100;
  SPsecSyncTimeBroadcastMessage *m1 = make_broadcast(&p, base_ts, ts1, key_ptr);
  CHECK(participant_handle_timesync_broadcast(&p, m1) == 0,
        "first broadcast accepted");
  uint8_t got[8];
  timer_get_timestamp(&p.timer, got);
  CHECK(bytes_to_u64_le(got) == ts1, "timer set to ts1");
  CHECK(p.timesync.broadcast_high_watermark == ts1,
        "watermark updated to ts1");
  spsecsynctimebroadcast_free(m1);

  /* --- Case 2: forward broadcast accepted, raises watermark --- */
  uint64_t ts2 = ts1 + 200;
  /* Nonce must match the receiver's current clock for tag verification.
     After Case 1 the timer is at ts1. */
  SPsecSyncTimeBroadcastMessage *m2 = make_broadcast(&p, ts1, ts2, key_ptr);
  CHECK(participant_handle_timesync_broadcast(&p, m2) == 0,
        "forward broadcast accepted");
  timer_get_timestamp(&p.timer, got);
  CHECK(bytes_to_u64_le(got) == ts2, "timer set to ts2");
  CHECK(p.timesync.broadcast_high_watermark == ts2,
        "watermark updated to ts2");
  spsecsynctimebroadcast_free(m2);

  /* --- Case 3: replay of ts1 (older) is DROPPED --- */
  /* Build a broadcast carrying ts1 again, with nonce at ts2 (current). */
  SPsecSyncTimeBroadcastMessage *m3 = make_broadcast(&p, ts2, ts1, key_ptr);
  /* The handler returns 0 (it decrypts fine, just doesn't apply). */
  participant_handle_timesync_broadcast(&p, m3);
  timer_get_timestamp(&p.timer, got);
  CHECK(bytes_to_u64_le(got) == ts2, "timer unchanged after replay (still ts2)");
  CHECK(p.timesync.broadcast_high_watermark == ts2,
        "watermark unchanged after replay");
  spsecsynctimebroadcast_free(m3);

  /* --- Case 4: replay of ts2 (equal) is also DROPPED --- */
  SPsecSyncTimeBroadcastMessage *m4 = make_broadcast(&p, ts2, ts2, key_ptr);
  participant_handle_timesync_broadcast(&p, m4);
  timer_get_timestamp(&p.timer, got);
  CHECK(bytes_to_u64_le(got) == ts2, "timer unchanged after equal-ts replay");
  spsecsynctimebroadcast_free(m4);

  /* --- Case 5: reset watermark (simulates Parameter Authentication) --- */
  p.timesync.broadcast_high_watermark = 0;
  /* Now ts1+50 (lower than old watermark) should be accepted. */
  uint64_t ts_after_reset = ts1 + 50;
  SPsecSyncTimeBroadcastMessage *m5 =
      make_broadcast(&p, ts2, ts_after_reset, key_ptr);
  CHECK(participant_handle_timesync_broadcast(&p, m5) == 0,
        "broadcast accepted after watermark reset");
  timer_get_timestamp(&p.timer, got);
  CHECK(bytes_to_u64_le(got) == ts_after_reset,
        "timer set to ts_after_reset");
  CHECK(p.timesync.broadcast_high_watermark == ts_after_reset,
        "watermark updated to ts_after_reset");
  spsecsynctimebroadcast_free(m5);

  teardown_test_participant(&p);

  if (g_failures == 0) {
    printf("All broadcast-forward-only checks passed.\n");
    return 0;
  }
  fprintf(stderr, "%d check(s) failed.\n", g_failures);
  return 1;
}
