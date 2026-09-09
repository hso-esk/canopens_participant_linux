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

// Known-answer tests for whichever crypto backend the build selected
// (SPSEC_CRYPTO_BACKEND). Run once per backend so mbedTLS and wolfSSL can't
// silently diverge: AEAD round-trip, tag/ciphertext/AAD tamper rejection,
// plus the constant-time compare helper.

#include "crypto.h"
#include "keys.h"
#include "messages.h" /* AUTH_TAG_SIZE */
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

static void set_ctx(CryptoHandler *h_ptr, uint8_t *key_ptr, uint8_t *nonce_ptr) {
  spsec_ret_t r =
      crypto_handler_set_context(h_ptr, key_ptr, nonce_ptr, REQUIRED_NONCE_LEN, AUTH_TAG_SIZE);
  (void)r;
  assert(r == SPSEC_SUCCESS);
}

static void test_algorithm(CryptoHandler *h_ptr, CryptoAlgorithm algo,
                           const char *name_ptr) {
  if (crypto_handler_select_algorithm(h_ptr, algo) != SPSEC_SUCCESS) {
    printf("  skip %s (unsupported by this backend)\n", name_ptr);
    return;
  }
  printf("  algo %s\n", name_ptr);

  uint8_t key[KEY_LEN];
  uint8_t nonce[REQUIRED_NONCE_LEN];
  for (int i = 0; i < KEY_LEN; i++)
    key[i] = (uint8_t)(0x10 + i);
  for (int i = 0; i < REQUIRED_NONCE_LEN; i++)
    nonce[i] = (uint8_t)(0xA0 + i);

  uint8_t plaintext[32];
  for (int i = 0; i < (int)sizeof(plaintext); i++)
    plaintext[i] = (uint8_t)i;
  uint8_t aad[5] = {1, 2, 3, 4, 5};

  uint8_t ciphertext[32];
  uint8_t tag[AUTH_TAG_SIZE];
  uint8_t decrypted[32];

  /* round-trip */
  set_ctx(h_ptr, key, nonce);
  CHECK(crypto_handler_encrypt_with_assoc_data(h_ptr, plaintext, sizeof(plaintext),
                                               ciphertext, tag, aad,
                                               sizeof(aad)) == SPSEC_SUCCESS,
        "encrypt");
  set_ctx(h_ptr, key, nonce);
  memset(decrypted, 0, sizeof(decrypted));
  CHECK(crypto_handler_decrypt_with_assoc_data(
            h_ptr, ciphertext, sizeof(plaintext), tag, decrypted, aad,
            sizeof(aad)) == SPSEC_SUCCESS,
        "decrypt");
  CHECK(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0,
        "round-trip plaintext matches");
  CHECK(memcmp(ciphertext, plaintext, sizeof(plaintext)) != 0,
        "ciphertext differs from plaintext");

  /* tag tamper must be rejected */
  {
    uint8_t bad_tag[AUTH_TAG_SIZE];
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[0] ^= 0x01;
    set_ctx(h_ptr, key, nonce);
    memset(decrypted, 0, sizeof(decrypted));
    CHECK(crypto_handler_decrypt_with_assoc_data(
              h_ptr, ciphertext, sizeof(plaintext), bad_tag, decrypted, aad,
              sizeof(aad)) != SPSEC_SUCCESS,
          "tampered tag rejected");
  }

  /* ciphertext tamper must be rejected */
  {
    uint8_t bad_ct[32];
    memcpy(bad_ct, ciphertext, sizeof(bad_ct));
    bad_ct[0] ^= 0x01;
    set_ctx(h_ptr, key, nonce);
    CHECK(crypto_handler_decrypt_with_assoc_data(
              h_ptr, bad_ct, sizeof(plaintext), tag, decrypted, aad,
              sizeof(aad)) != SPSEC_SUCCESS,
          "tampered ciphertext rejected");
  }

  /* AAD mismatch must be rejected */
  {
    uint8_t bad_aad[5] = {9, 9, 9, 9, 9};
    set_ctx(h_ptr, key, nonce);
    CHECK(crypto_handler_decrypt_with_assoc_data(
              h_ptr, ciphertext, sizeof(plaintext), tag, decrypted, bad_aad,
              sizeof(bad_aad)) != SPSEC_SUCCESS,
          "wrong AAD rejected");
  }
}

static void test_ct_memcmp(void) {
  printf("  spsec_ct_memcmp\n");
  uint8_t a[16], b[16];
  for (int i = 0; i < 16; i++)
    a[i] = b[i] = (uint8_t)i;
  CHECK(spsec_ct_memcmp(a, b, sizeof(a)) == 0, "equal arrays compare equal");
  b[15] ^= 0x80;
  CHECK(spsec_ct_memcmp(a, b, sizeof(a)) != 0, "diff in last byte detected");
  b[15] = a[15];
  b[0] ^= 0x01;
  CHECK(spsec_ct_memcmp(a, b, sizeof(a)) != 0, "diff in first byte detected");
  CHECK(spsec_ct_memcmp(a, b, 0) == 0, "zero length compares equal");
}

int main(void) {
  /* Suppress expected error log noise from decrypt failure tests */
  configure_logging("CRITICAL");

  CryptoHandler handler;
  if (crypto_handler_init(&handler) != SPSEC_SUCCESS) {
    fprintf(stderr, "crypto_handler_init failed\n");
    return 1;
  }
  const CryptoBackend *backend_ptr = crypto_handler_get_backend(&handler);
  printf("Crypto backend: %s\n", backend_ptr ? backend_ptr->name : "(unknown)");

  test_algorithm(&handler, CRYPTO_ALGO_AES_GCM, "AES-GCM");
  test_algorithm(&handler, CRYPTO_ALGO_CHACHA20_POLY1305, "ChaCha20-Poly1305");
  test_algorithm(&handler, CRYPTO_ALGO_ASCON128, "Ascon-AEAD128");
  test_ct_memcmp();

  crypto_handler_destroy(&handler);

  if (g_failures) {
    fprintf(stderr, "\n%d check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nAll crypto checks passed.\n");
  return 0;
}
