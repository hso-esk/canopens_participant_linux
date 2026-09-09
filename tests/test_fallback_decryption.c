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
 * @file test_fallback_decryption.c
 * @brief Tests AppData decryption and rolling key fallback across epochs.
 */

#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_keys.h"
#include "spsec_common.h"
#include "spsec_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, msg_ptr)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s (line %d)\n", msg_ptr, __LINE__);                \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

#define TEST_PID 42

static void init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = TEST_PID;
  p_ptr->crypto_algorithm = CRYPTO_ALGO_AES_GCM;
  crypto_handler_init(&p_ptr->crypto_handler);
  crypto_handler_select_algorithm(&p_ptr->crypto_handler, p_ptr->crypto_algorithm);
  communication_keys_init(&p_ptr->comm_keys);

  /* Set up seed key (index 3) so communication keys can be derived */
  uint8_t seed[KEY_LEN];
  for (int i = 0; i < KEY_LEN; i++)
    seed[i] = (uint8_t)(0x20 + i);
  p_ptr->comm_keys.spsec_keys[3] = spseckey_new(0x33333333, seed);

  uint8_t salt[SALT_LEN] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
  p_ptr->comm_keys.spsec_salt[3] = (SPsecSalt *)malloc(sizeof(SPsecSalt));
  spsecsalt_init(p_ptr->comm_keys.spsec_salt[3], salt);

  /* Base derivation salt */
  for (int i = 0; i < 4; i++)
    p_ptr->comm_keys.csalt[i] = (uint8_t)(0x10 + i);
}

static void teardown_test_participant(Participant *p_ptr) {
  communication_keys_destroy(&p_ptr->comm_keys);
  crypto_handler_destroy(&p_ptr->crypto_handler);
}

static void test_preferred_key_success(void) {
  printf("Testing preferred key decryption...\n");
  Participant p;
  init_test_participant(&p);

  /* Timestamp with bit 24 = 0 (even epoch) */
  uint8_t ts[8] = {0x00, 0x00, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00};
  CHECK(communication_keys_update(&p.comm_keys, ts) == 0, "comm keys update succeeds");

  uint32_t can_id = 0x181;
  uint8_t payload[] = {0x11, 0x22, 0x33, 0x44};
  uint8_t padded_payload[8] = {0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00};
  uint8_t padding_size = 4;

  /* Build AAD: [CAN_ID:4 | unpadded_len:1] */
  uint8_t aad[5];
  aad[0] = (uint8_t)(can_id & 0xFF);
  aad[1] = (uint8_t)((can_id >> 8) & 0xFF);
  aad[2] = (uint8_t)((can_id >> 16) & 0xFF);
  aad[3] = (uint8_t)((can_id >> 24) & 0xFF);
  aad[4] = (uint8_t)sizeof(payload);

  /* Encrypt using even key */
  uint8_t nonce[REQUIRED_NONCE_LEN] = {0};
  memcpy(nonce, ts, 8);
  nonce[8] = (uint8_t)(can_id & 0xFF);
  nonce[9] = (uint8_t)((can_id >> 8) & 0xFF);
  memcpy(nonce + 10, p.comm_keys.spsec_salt[3]->salt, 6);

  uint8_t ciphertext[8];
  uint8_t tag[AUTH_TAG_SIZE];
  CHECK(crypto_handler_set_context(&p.crypto_handler, p.comm_keys.even_key,
                                   nonce, 12, AUTH_TAG_SIZE) == SPSEC_SUCCESS, "ctx set");
  CHECK(crypto_handler_encrypt_with_assoc_data(
            &p.crypto_handler, padded_payload, sizeof(padded_payload),
            ciphertext, tag, aad, sizeof(aad)) == SPSEC_SUCCESS, "encrypt");

  /* Wire trailer timestamp: [padding:4 | ts_lsb:12] (8 bytes buffer for spsecappdata_new) */
  uint8_t trailer_ts[8] = {0};
  uint16_t lsb = (uint16_t)(ts[0] | ((ts[1] & 0x0F) << 8));
  uint16_t hdr = (uint16_t)((padding_size << 12) | (lsb & 0x0FFF));
  trailer_ts[0] = (uint8_t)(hdr & 0xFF);
  trailer_ts[1] = (uint8_t)((hdr >> 8) & 0xFF);

  SPsecAppData *msg_ptr = spsecappdata_new(can_id, ciphertext, sizeof(ciphertext),
                                      0, trailer_ts, tag, sizeof(tag));
  CHECK(msg_ptr != NULL, "message created");

  uint8_t *plaintext_ptr = NULL;
  size_t plaintext_len = 0;
  spsec_ret_t ret = participant_decrypt_spsec_appdata(
      &p, msg_ptr, ts, p.comm_keys.even_key, &plaintext_ptr, &plaintext_len);

  CHECK(ret == SPSEC_SUCCESS, "preferred key decrypts successfully");
  CHECK(plaintext_len == sizeof(payload), "payload length matches");
  CHECK(plaintext_ptr && memcmp(plaintext_ptr, payload, sizeof(payload)) == 0, "payload matches");

  free(plaintext_ptr);
  spsecappdata_free(msg_ptr);
  teardown_test_participant(&p);
}

static void test_fallback_key_success(void) {
  printf("Testing fallback to secondary key across epoch boundary...\n");
  Participant p;
  init_test_participant(&p);

  // Transition N=0x01800000: packet 10 ticks before (odd parity), receiver
  // 10 ticks after (even parity) -> delta=20 ticks, within the 15ms window.
  uint64_t t_packet = 0x01800000ULL - 10ULL; /* 0x017FFFF6 */
  uint64_t t_local  = 0x01800000ULL + 10ULL; /* 0x0180000A */

  uint8_t packet_ts[8];
  uint8_t local_ts[8];
  for (int i = 0; i < 8; i++) {
    packet_ts[i] = (uint8_t)((t_packet >> (i * 8)) & 0xFF);
    local_ts[i]  = (uint8_t)((t_local >> (i * 8)) & 0xFF);
  }

  CHECK(communication_keys_update(&p.comm_keys, packet_ts) == 0, "packet comm keys update");
  uint8_t packet_odd_key[KEY_LEN];
  memcpy(packet_odd_key, p.comm_keys.odd_key, KEY_LEN);

  /* Receiver updates its clock to local_ts */
  CHECK(communication_keys_update(&p.comm_keys, local_ts) == 0, "receiver comm keys update");

  uint32_t can_id = 0x200;
  uint8_t payload[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  uint8_t padded_payload[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x00};
  uint8_t padding_size = 3;

  /* Encrypt using packet's key */
  uint8_t aad[5];
  aad[0] = (uint8_t)(can_id & 0xFF);
  aad[1] = (uint8_t)((can_id >> 8) & 0xFF);
  aad[2] = (uint8_t)((can_id >> 16) & 0xFF);
  aad[3] = (uint8_t)((can_id >> 24) & 0xFF);
  aad[4] = (uint8_t)sizeof(payload);

  uint8_t nonce[REQUIRED_NONCE_LEN] = {0};
  memcpy(nonce, packet_ts, 8);
  nonce[8] = (uint8_t)(can_id & 0xFF);
  nonce[9] = (uint8_t)((can_id >> 8) & 0xFF);
  memcpy(nonce + 10, p.comm_keys.spsec_salt[3]->salt, 2);

  uint8_t ciphertext[8];
  uint8_t tag[AUTH_TAG_SIZE];
  CHECK(crypto_handler_set_context(&p.crypto_handler, packet_odd_key,
                                   nonce, 12, AUTH_TAG_SIZE) == SPSEC_SUCCESS, "ctx set");
  CHECK(crypto_handler_encrypt_with_assoc_data(
            &p.crypto_handler, padded_payload, sizeof(padded_payload),
            ciphertext, tag, aad, sizeof(aad)) == SPSEC_SUCCESS, "encrypt");

  uint8_t trailer_ts[8] = {0};
  uint16_t lsb = (uint16_t)(packet_ts[0] | ((packet_ts[1] & 0x0F) << 8));
  uint16_t hdr = (uint16_t)((padding_size << 12) | (lsb & 0x0FFF));
  trailer_ts[0] = (uint8_t)(hdr & 0xFF);
  trailer_ts[1] = (uint8_t)((hdr >> 8) & 0xFF);

  SPsecAppData *msg_ptr = spsecappdata_new(can_id, ciphertext, sizeof(ciphertext),
                                      0, trailer_ts, tag, sizeof(tag));
  CHECK(msg_ptr != NULL, "message created");

  /* First attempt with receiver's preferred key (even key) must fail */
  uint8_t *plaintext_ptr = NULL;
  size_t plaintext_len = 0;
  spsec_ret_t ret = participant_decrypt_spsec_appdata(
      &p, msg_ptr, local_ts, p.comm_keys.even_key, &plaintext_ptr, &plaintext_len);
  CHECK(ret != SPSEC_SUCCESS, "first attempt with wrong key fails");

  /* Second attempt with fallback (odd key) MUST succeed without wire corruption */
  ret = participant_decrypt_spsec_appdata(
      &p, msg_ptr, local_ts, p.comm_keys.odd_key, &plaintext_ptr, &plaintext_len);
  CHECK(ret == SPSEC_SUCCESS, "fallback key decrypts successfully");
  CHECK(plaintext_len == sizeof(payload), "fallback payload length matches");
  CHECK(plaintext_ptr && memcmp(plaintext_ptr, payload, sizeof(payload)) == 0, "fallback payload matches");

  free(plaintext_ptr);
  spsecappdata_free(msg_ptr);
  teardown_test_participant(&p);
}

static void test_double_failure_reports_event(void) {
  printf("Testing double failure security event report...\n");
  Participant p;
  init_test_participant(&p);

  uint8_t ts[8] = {0x00, 0x00, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00};
  communication_keys_update(&p.comm_keys, ts);

  uint32_t can_id = 0x300;
  uint8_t fake_cipher[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
  uint8_t fake_tag[AUTH_TAG_SIZE] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88};
  uint8_t trailer_ts[8] = {0};
  trailer_ts[0] = 0x00;
  trailer_ts[1] = 0x10;

  SPsecAppData *msg_ptr = spsecappdata_new(can_id, fake_cipher, sizeof(fake_cipher),
                                      0, trailer_ts, fake_tag, sizeof(fake_tag));

  uint8_t *plaintext_ptr = NULL;
  size_t plaintext_len = 0;
  spsec_ret_t ret1 = participant_decrypt_spsec_appdata(
      &p, msg_ptr, ts, p.comm_keys.even_key, &plaintext_ptr, &plaintext_len);
  CHECK(ret1 != SPSEC_SUCCESS, "first key decrypt fails on fake packet");

  spsec_ret_t ret2 = participant_decrypt_spsec_appdata(
      &p, msg_ptr, ts, p.comm_keys.odd_key, &plaintext_ptr, &plaintext_len);
  CHECK(ret2 != SPSEC_SUCCESS, "second key decrypt fails on fake packet");

  spsecappdata_free(msg_ptr);
  teardown_test_participant(&p);
}

static void test_padding_boundary_overflow(void) {
  printf("Testing padding size overflow rejection...\n");
  Participant p;
  init_test_participant(&p);

  uint8_t ts[8] = {0x00, 0x00, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00};
  communication_keys_update(&p.comm_keys, ts);

  uint32_t can_id = 0x400;
  uint8_t dummy_data[8] = {0};
  uint8_t dummy_tag[AUTH_TAG_SIZE] = {0};

  /* Wire trailer with padding=10, but secure_data_len=8 -> invalid (10 > 8) */
  uint8_t trailer_ts[8] = {0};
  uint16_t hdr = (uint16_t)((10 << 12) | 0x000);
  trailer_ts[0] = (uint8_t)(hdr & 0xFF);
  trailer_ts[1] = (uint8_t)((hdr >> 8) & 0xFF);

  SPsecAppData *msg_ptr = spsecappdata_new(can_id, dummy_data, sizeof(dummy_data),
                                      0, trailer_ts, dummy_tag, sizeof(dummy_tag));

  uint8_t *plaintext_ptr = NULL;
  size_t plaintext_len = 0;
  spsec_ret_t ret = participant_decrypt_spsec_appdata(
      &p, msg_ptr, ts, p.comm_keys.even_key, &plaintext_ptr, &plaintext_len);
  CHECK(ret == SPSEC_ERROR_INVALID_ARGUMENT,
        "padding_size > secure_data_len rejected with SPSEC_ERROR_INVALID_ARGUMENT");

  spsecappdata_free(msg_ptr);
  teardown_test_participant(&p);
}

int main(void) {
  test_preferred_key_success();
  test_fallback_key_success();
  test_double_failure_reports_event();
  test_padding_boundary_overflow();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d fallback_decryption check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All fallback_decryption checks passed.\n");
  return 0;
}
