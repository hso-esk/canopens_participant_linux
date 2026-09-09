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
 * @file test_auth_only.c
 * @brief Authentication-only AEAD contract tests for every supported backend.
 */

#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_keys.h"
#include "spsec_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg);                                  \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

static spsec_ret_t set_context(CryptoHandler *handler_ptr, uint8_t *key_ptr,
                               uint8_t *nonce_ptr) {
  return crypto_handler_set_context(handler_ptr, key_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                                    AUTH_TAG_SIZE);
}

static void test_receive_path(CryptoAlgorithm algorithm, const char *name_ptr) {
  Participant participant;
  memset(&participant, 0, sizeof(participant));
  CHECK(crypto_handler_init(&participant.crypto_handler) == SPSEC_SUCCESS,
        "initialize receive-path crypto handler_ptr");
  if (crypto_handler_select_algorithm(&participant.crypto_handler, algorithm) !=
      SPSEC_SUCCESS) {
    crypto_handler_destroy(&participant.crypto_handler);
    return;
  }
  participant.crypto_algorithm = algorithm;
  participant.auth_only_mode = true;
  CHECK(communication_keys_init(&participant.comm_keys) == 0,
        "initialize receive-path communication keys");
  static const uint8_t zero_salt[SALT_LEN] = {0};
  static const uint8_t seed_key[KEY_LEN] = {
      0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B,
      0x5C, 0x6D, 0x7E, 0x8F, 0x90, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
      0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
  participant.comm_keys.spsec_salt[3] = spsecsalt_new(zero_salt);
  participant.comm_keys.spsec_keys[3] = spseckey_new(13, seed_key);
  if (!participant.comm_keys.spsec_keys[3] || !participant.comm_keys.spsec_salt[3]) {
    communication_keys_destroy(&participant.comm_keys);
    crypto_handler_destroy(&participant.crypto_handler);
    return;
  }

  uint8_t timestamp[8] = {0x00, 0x00, 0x80, 0x00, 0, 0, 0, 0};
  uint8_t trailer_timestamp[8] = {0x00, 0x40, 0, 0, 0, 0, 0, 0};
  uint8_t payload[] = {0x51, 0x52, 0x53, 0x54, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t base_aad[DATA_AAD_LEN] = {0x23, 0x01, 0x00, 0x00, 0x04};
  uint8_t extended_aad[DATA_AAD_LEN + 4];
  uint8_t tag[AUTH_TAG_SIZE];
  uint8_t nonce[REQUIRED_NONCE_LEN];
  uint8_t dummy_input = 0;
  uint8_t dummy_output = 0;
  uint8_t *plaintext_ptr = NULL;
  size_t plaintext_len = 0;

  memset(participant.comm_keys.csalt, 0x5A, sizeof(participant.comm_keys.csalt));
  CHECK(communication_keys_update(&participant.comm_keys, timestamp) == 0,
        "derive receive-path communication key");
  memcpy(extended_aad, base_aad, sizeof(base_aad));
  memcpy(extended_aad + sizeof(base_aad), payload, base_aad[4]);
  memcpy(nonce, timestamp, sizeof(timestamp));
  nonce[8] = base_aad[0];
  nonce[9] = base_aad[1];
  if (crypto_get_nonce_len(algorithm) > 10) {
    size_t salt_len = crypto_get_nonce_len(algorithm) - 10;
    if (salt_len > SALT_LEN)
      salt_len = SALT_LEN;
    memset(nonce + 10, 0, salt_len);
  }
  CHECK(crypto_handler_set_context(&participant.crypto_handler,
                                   participant.comm_keys.even_key, nonce,
                                   crypto_get_nonce_len(algorithm), AUTH_TAG_SIZE) ==
            SPSEC_SUCCESS,
        "set receive-path sender context");
  CHECK(crypto_handler_encrypt_with_assoc_data(
            &participant.crypto_handler, &dummy_input, 0, &dummy_output, tag,
            extended_aad, sizeof(extended_aad)) == SPSEC_SUCCESS,
        "generate receive-path auth-only tag");

  SPsecAppData *message_ptr =
      spsecappdata_new(0x123, payload, sizeof(payload), 0, trailer_timestamp,
                        tag, sizeof(tag));
  CHECK(message_ptr != NULL, "allocate receive-path app-data message");
  if (message_ptr) {
    CHECK(participant_decrypt_spsec_appdata(
              &participant, message_ptr, timestamp, participant.comm_keys.even_key,
              &plaintext_ptr, &plaintext_len) == SPSEC_SUCCESS,
          "receive path accepts valid auth-only frame");
    CHECK(plaintext_len == 4, "receive path removes auth-only transport padding");
    CHECK(plaintext_ptr && memcmp(plaintext_ptr, payload, plaintext_len) == 0,
          "receive path returns original auth-only payload");
    free(plaintext_ptr);
    spsecappdata_free(message_ptr);
  }

  communication_keys_destroy(&participant.comm_keys);
  crypto_handler_destroy(&participant.crypto_handler);
  printf("  receive path %s\n", name_ptr);
}

static void test_algorithm(CryptoHandler *handler_ptr, CryptoAlgorithm algorithm,
                           const char *name_ptr) {
  if (crypto_handler_select_algorithm(handler_ptr, algorithm) != SPSEC_SUCCESS) {
    printf("  skip %s (unsupported by this backend)\n", name_ptr);
    return;
  }
  printf("  algo %s\n", name_ptr);

  uint8_t key[KEY_LEN];
  uint8_t nonce[REQUIRED_NONCE_LEN];
  uint8_t wire_payload[] = {0x11, 0x22, 0x33, 0x44, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t expected_wire[sizeof(wire_payload)];
  uint8_t tag[AUTH_TAG_SIZE];
  uint8_t base_aad[DATA_AAD_LEN] = {0x23, 0x01, 0x00, 0x00, 0x04};
  uint8_t extended_aad[DATA_AAD_LEN + 4];
  uint8_t dummy_input = 0;
  uint8_t dummy_output = 0;

  for (size_t i = 0; i < sizeof(key); ++i)
    key[i] = (uint8_t)(0x10U + i);
  for (size_t i = 0; i < sizeof(nonce); ++i)
    nonce[i] = (uint8_t)(0xA0U + i);
  memcpy(expected_wire, wire_payload, sizeof(wire_payload));
  memcpy(extended_aad, base_aad, sizeof(base_aad));
  memcpy(extended_aad + sizeof(base_aad), wire_payload, base_aad[4]);

  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set auth-only encrypt context");
  CHECK(crypto_handler_encrypt_with_assoc_data(
            handler_ptr, &dummy_input, 0, &dummy_output, tag, extended_aad,
            sizeof(extended_aad)) == SPSEC_SUCCESS,
        "auth-only tag generation");
  CHECK(memcmp(wire_payload, expected_wire, sizeof(wire_payload)) == 0,
        "auth-only wire payload remains plaintext");

  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set auth-only decrypt context");
  CHECK(crypto_handler_decrypt_with_assoc_data(
            handler_ptr, &dummy_input, 0, tag, &dummy_output, extended_aad,
            sizeof(extended_aad)) == SPSEC_SUCCESS,
        "auth-only tag verification");

  uint8_t tampered_aad[sizeof(extended_aad)];
  memcpy(tampered_aad, extended_aad, sizeof(tampered_aad));
  tampered_aad[DATA_AAD_LEN] ^= 0x01;
  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set payload-tamper decrypt context");
  CHECK(crypto_handler_decrypt_with_assoc_data(
            handler_ptr, &dummy_input, 0, tag, &dummy_output, tampered_aad,
            sizeof(tampered_aad)) != SPSEC_SUCCESS,
        "tampered auth-only payload rejected");

  uint8_t bad_tag[AUTH_TAG_SIZE];
  memcpy(bad_tag, tag, sizeof(bad_tag));
  bad_tag[0] ^= 0x01;
  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set tag-tamper decrypt context");
  CHECK(crypto_handler_decrypt_with_assoc_data(
            handler_ptr, &dummy_input, 0, bad_tag, &dummy_output, extended_aad,
            sizeof(extended_aad)) != SPSEC_SUCCESS,
        "tampered auth-only tag rejected");

  uint8_t wrong_id_aad[sizeof(extended_aad)];
  memcpy(wrong_id_aad, extended_aad, sizeof(wrong_id_aad));
  wrong_id_aad[0] ^= 0x01;
  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set CAN-ID-tamper decrypt context");
  CHECK(crypto_handler_decrypt_with_assoc_data(
            handler_ptr, &dummy_input, 0, tag, &dummy_output, wrong_id_aad,
            sizeof(wrong_id_aad)) != SPSEC_SUCCESS,
        "tampered CAN ID rejected");

  uint8_t wrong_length_aad[sizeof(extended_aad)];
  memcpy(wrong_length_aad, extended_aad, sizeof(wrong_length_aad));
  wrong_length_aad[4] = 3;
  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set length-tamper decrypt context");
  CHECK(crypto_handler_decrypt_with_assoc_data(
            handler_ptr, &dummy_input, 0, tag, &dummy_output, wrong_length_aad,
            sizeof(wrong_length_aad)) != SPSEC_SUCCESS,
        "tampered payload length rejected");

  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set AEAD-mode decrypt context");
  CHECK(crypto_handler_decrypt_with_assoc_data(
            handler_ptr, wire_payload, sizeof(wire_payload), tag, expected_wire,
            base_aad, sizeof(base_aad)) != SPSEC_SUCCESS,
        "auth-only frame rejected by AEAD convention");

  uint8_t ciphertext[sizeof(wire_payload)];
  uint8_t ae_tag[AUTH_TAG_SIZE];
  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set AEAD encrypt context");
  CHECK(crypto_handler_encrypt_with_assoc_data(
            handler_ptr, wire_payload, sizeof(wire_payload), ciphertext, ae_tag,
            base_aad, sizeof(base_aad)) == SPSEC_SUCCESS,
        "AEAD tag generation");
  CHECK(set_context(handler_ptr, key, nonce) == SPSEC_SUCCESS,
        "set auth-only convention decrypt context");
  CHECK(crypto_handler_decrypt_with_assoc_data(
            handler_ptr, &dummy_input, 0, ae_tag, &dummy_output, extended_aad,
            sizeof(extended_aad)) != SPSEC_SUCCESS,
        "AEAD frame rejected by auth-only convention");
}

int main(void) {
  configure_logging("CRITICAL");

  CryptoHandler handler_ptr;
  if (crypto_handler_init(&handler_ptr) != SPSEC_SUCCESS) {
    fprintf(stderr, "crypto_handler_init failed\n");
    return 1;
  }

  const CryptoBackend *backend_ptr = crypto_handler_get_backend(&handler_ptr);
  printf("Authentication-only backend: %s\n",
         backend_ptr ? backend_ptr->name : "(unknown)");
  test_algorithm(&handler_ptr, CRYPTO_ALGO_AES_GCM, "AES-GCM");
  test_algorithm(&handler_ptr, CRYPTO_ALGO_CHACHA20_POLY1305,
                 "ChaCha20-Poly1305");
  test_algorithm(&handler_ptr, CRYPTO_ALGO_ASCON128, "Ascon-AEAD128");

  crypto_handler_destroy(&handler_ptr);
  test_receive_path(CRYPTO_ALGO_AES_GCM, "AES-GCM");
  test_receive_path(CRYPTO_ALGO_CHACHA20_POLY1305, "ChaCha20-Poly1305");
  test_receive_path(CRYPTO_ALGO_ASCON128, "Ascon-AEAD128");
  if (g_failures != 0) {
    fprintf(stderr, "\n%d authentication-only check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nAll authentication-only checks passed.\n");
  return 0;
}
