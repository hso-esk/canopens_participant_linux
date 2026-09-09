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
 * @file test_sync_broadcast_no_window.c
 * @brief Verifies no acceptance-window check precedes the decrypt attempt in
 *        participant_handle_timesync_broadcast(), so a far-future but
 *        correctly-authenticated broadcast is still accepted and applied.
 */

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
// SPsec Sync Time Broadcast CAN ID: 0x02210000 | (CPMT_SYNC << 8)
#define SYNC_BROADCAST_ADDR (0x02210000u | ((uint32_t)CPMT_SYNC << 8))

static void init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = TEST_PID;
  p_ptr->crypto_algorithm = CRYPTO_ALGO_AES_GCM;
  crypto_handler_init(&p_ptr->crypto_handler);
  crypto_handler_select_algorithm(&p_ptr->crypto_handler, p_ptr->crypto_algorithm);
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

int main(void) {
  configure_logging("CRITICAL");

  Participant p;
  init_test_participant(&p);

  // Comfortably inside an epoch, so both rolling keys are well defined.
  const uint64_t local_ts = 0x05800000ULL + 1000ULL;
  uint8_t local_ts_le[8];
  u64_to_bytes_le(local_ts, local_ts_le);

  CHECK(timer_set_timestamp(&p.timer, local_ts_le) == 0,
        "receiver local clock established");

  // Derive keys for local_ts and pick whichever key the handler tries first
  CHECK(communication_keys_update(&p.comm_keys, local_ts_le) == 0,
        "communication keys derived for local_ts's epoch");
  uint8_t *first_key_ptr = p.comm_keys.use_odd_key ? p.comm_keys.odd_key
                                                   : p.comm_keys.even_key;

  // Encrypt with the sender's timestamp equal to local_ts, so the trailer
  // reconstructs exactly and the tag verifies on the first attempt.
  uint8_t nonce[REQUIRED_NONCE_LEN] = {0};
  memcpy(nonce, local_ts_le, 8);
  nonce[8] = (uint8_t)(SYNC_BROADCAST_ADDR & 0xFF);
  nonce[9] = (uint8_t)((SYNC_BROADCAST_ADDR >> 8) & 0xFF);
  memcpy(nonce + 10, p.comm_keys.spsec_salt[3]->salt, 6);

  uint8_t aad[DATA_AAD_LEN];
  aad[0] = (uint8_t)(SYNC_BROADCAST_ADDR & 0xFF);
  aad[1] = (uint8_t)((SYNC_BROADCAST_ADDR >> 8) & 0xFF);
  aad[2] = (uint8_t)((SYNC_BROADCAST_ADDR >> 16) & 0xFF);
  aad[3] = (uint8_t)((SYNC_BROADCAST_ADDR >> 24) & 0xFF);
  aad[4] = TIMESTAMP_SIZE + 2; // unpadded broadcast body length (10)

  // Plaintext content: far past any acceptance window
  const uint64_t far_future_ts = local_ts + 1000000000ULL;
  uint8_t plaintext[TIMESTAMP_SIZE + 2];
  u64_to_bytes_le(far_future_ts, plaintext);
  plaintext[8] = 0;
  plaintext[9] = 0;

  uint8_t ciphertext[TIMESTAMP_SIZE + 2];
  uint8_t tag[AUTH_TAG_SIZE];
  CHECK(crypto_handler_set_context(&p.crypto_handler, first_key_ptr, nonce, 12,
                                   AUTH_TAG_SIZE) == SPSEC_SUCCESS,
        "crypto context set");
  CHECK(crypto_handler_encrypt_with_assoc_data(
            &p.crypto_handler, plaintext, sizeof(plaintext), ciphertext, tag,
            aad, sizeof(aad)) == SPSEC_SUCCESS,
        "broadcast body encrypted");

  // Wire trailer: [padding:4 | ts_low12:12], padding_size = 0.
  uint8_t trailer_ts[8] = {0};
  uint16_t lsb = (uint16_t)(local_ts_le[0] | ((local_ts_le[1] & 0x0F) << 8));
  uint16_t hdr = (uint16_t)(lsb & 0x0FFF);
  trailer_ts[0] = (uint8_t)(hdr & 0xFF);
  trailer_ts[1] = (uint8_t)((hdr >> 8) & 0xFF);

  SPsecAppData *encrypted_appdata_ptr =
      spsecappdata_new(SYNC_BROADCAST_ADDR, ciphertext, sizeof(ciphertext), 0,
                       trailer_ts, tag, sizeof(tag));
  CHECK(encrypted_appdata_ptr != NULL, "encrypted broadcast message built");

  SPsecSyncTimeBroadcastMessage *tsb_msg_ptr = spsecsynctimebroadcast_new(0);
  CHECK(tsb_msg_ptr != NULL, "broadcast envelope allocated");
  tsb_msg_ptr->spsec_app_data_ptr = encrypted_appdata_ptr;

  printf("Delivering a well-authenticated broadcast whose content timestamp "
        "is 10^9 ticks ahead of the local clock...\n");
  signed char ret = participant_handle_timesync_broadcast(&p, tsb_msg_ptr);
  CHECK(ret == 0,
        "broadcast decrypts and is accepted despite the far-future content "
        "timestamp");

  uint8_t applied_ts_le[8];
  timer_get_timestamp(&p.timer, applied_ts_le);
  CHECK(bytes_to_u64_le(applied_ts_le) == far_future_ts,
        "the far-future content timestamp was actually applied to the "
        "local timer, unfiltered by any window check");

  spsecsynctimebroadcast_free(tsb_msg_ptr);
  teardown_test_participant(&p);

  if (g_failures == 0) {
    printf("All sync-broadcast-no-window checks passed.\n");
    return 0;
  }
  fprintf(stderr, "%d check(s) failed.\n", g_failures);
  return 1;
}
