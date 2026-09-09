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

// Regression tests for session-counter nonce construction + a cross-backend
// AEAD known-answer test. Pins down three real interop bugs from one
// debugging session: nonce layout diverging under non-default SALT_LEN,
// a session-counter-wrap nonce-reuse gap, and a hardcoded-backend bug.

#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "spsec_common.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                      \
  do {                                                                        \
    if (!(cond)) {                                                           \
      fprintf(stderr, "  FAIL: %s\n", msg);                                  \
      g_failures++;                                                          \
    }                                                                        \
  } while (0)

// Nonce layout: counter(4,LE) + salt(clamped to min(SALT_LEN,12)) +
// zero-padding, total REQUIRED_NONCE_LEN(16) bytes.
static void test_nonce_layout(void) {
  printf("  nonce layout (SALT_LEN=%d)\n", SALT_LEN);

  uint8_t salt_bytes[SALT_LEN];
  for (int i = 0; i < SALT_LEN; i++)
    salt_bytes[i] = (uint8_t)(0xE0 + i);
  SPsecSalt *salt_ptr = spsecsalt_new(salt_bytes);
  CHECK(salt_ptr != NULL, "salt allocation");
  if (!salt_ptr)
    return;

  uint32_t cnt = 0x04030201; /* distinct bytes so a byte-order bug is caught */
  uint8_t *nonce_ptr = NULL;
  int8_t ret = generate_nonce_from_session_cnt(cnt, &nonce_ptr, salt_ptr);
  CHECK(ret == 0, "generate_nonce_from_session_cnt succeeds");
  CHECK(nonce_ptr != NULL, "nonce allocated");
  if (nonce_ptr) {
    CHECK(nonce_ptr[0] == 0x01 && nonce_ptr[1] == 0x02 && nonce_ptr[2] == 0x03 &&
              nonce_ptr[3] == 0x04,
          "counter encoded little-endian in first 4 bytes");

    size_t expected_salt_bytes = REQUIRED_NONCE_LEN - 4;
    if (expected_salt_bytes > SALT_LEN)
      expected_salt_bytes = SALT_LEN;
    CHECK(memcmp(nonce_ptr + 4, salt_bytes, expected_salt_bytes) == 0,
          "salt bytes copied starting at offset 4");

    /* Any bytes beyond counter+salt must be zero, not uninitialized/garbage -
     * this is exactly the bug class this test guards against. */
    for (size_t i = 4 + expected_salt_bytes; i < REQUIRED_NONCE_LEN; i++) {
      CHECK(nonce_ptr[i] == 0, "trailing byte is zero-padded, not garbage");
    }
    free(nonce_ptr);
  }
  spsecsalt_free(salt_ptr);
}

// Refuse a nonce once the session counter is close enough to wrapping
// that key reuse becomes possible.
static void test_nonce_wrap_guard(void) {
  printf("  session counter wrap guard\n");

  uint8_t salt_bytes[SALT_LEN];
  memset(salt_bytes, 0xAA, sizeof(salt_bytes));
  SPsecSalt *salt_ptr = spsecsalt_new(salt_bytes);
  CHECK(salt_ptr != NULL, "salt allocation");
  if (!salt_ptr)
    return;

  uint8_t *nonce_ptr = NULL;
  int8_t ret = generate_nonce_from_session_cnt(UINT32_MAX, &nonce_ptr, salt_ptr);
  CHECK(ret != 0, "counter at UINT32_MAX is refused");
  CHECK(nonce_ptr == NULL, "no nonce leaked out on refusal");

  nonce_ptr = NULL;
  ret = generate_nonce_from_session_cnt(UINT32_MAX - 5000, &nonce_ptr, salt_ptr);
  CHECK(ret == 0, "counter well below the wrap margin still succeeds");
  if (nonce_ptr)
    free(nonce_ptr);

  /* Exact margin boundary tests (SESSION_CNT_WRAP_MARGIN = 1000) */
  nonce_ptr = NULL;
  ret = generate_nonce_from_session_cnt(UINT32_MAX - 1000, &nonce_ptr, salt_ptr);
  CHECK(ret != 0, "counter exactly at wrap margin (UINT32_MAX - 1000) is refused");
  if (nonce_ptr) { free(nonce_ptr); nonce_ptr = NULL; }

  nonce_ptr = NULL;
  ret = generate_nonce_from_session_cnt(UINT32_MAX - 1001, &nonce_ptr, salt_ptr);
  CHECK(ret == 0, "counter one below wrap margin (UINT32_MAX - 1001) succeeds");
  if (nonce_ptr) { free(nonce_ptr); nonce_ptr = NULL; }

  nonce_ptr = NULL;
  ret = generate_nonce_from_session_cnt(UINT32_MAX - 999, &nonce_ptr, salt_ptr);
  CHECK(ret != 0, "counter one above wrap margin (UINT32_MAX - 999) is refused");
  if (nonce_ptr) { free(nonce_ptr); nonce_ptr = NULL; }

  spsecsalt_free(salt_ptr);
}

// Cross-backend known-answer test: a fixed key/nonce/plaintext/AAD must
// produce byte-identical ciphertext+tag on wolfSSL and mbedTLS alike -
// vectors were captured from both backends and hardcoded here.
static void test_cross_backend_kat(CryptoHandler *h_ptr) {
  printf("  cross-backend AEAD known-answer test\n");

  uint8_t key[KEY_LEN];
  uint8_t nonce_ptr[REQUIRED_NONCE_LEN];
  for (int i = 0; i < KEY_LEN; i++)
    key[i] = (uint8_t)(0x10 + i);
  for (int i = 0; i < REQUIRED_NONCE_LEN; i++)
    nonce_ptr[i] = (uint8_t)(0xA0 + i);
  uint8_t plaintext[32];
  for (int i = 0; i < 32; i++)
    plaintext[i] = (uint8_t)i;
  uint8_t aad[5] = {1, 2, 3, 4, 5};

  struct {
    CryptoAlgorithm algo;
    const char *name;
    const char *ct_hex;
    const char *tag_hex;
  } vectors[] = {
      {CRYPTO_ALGO_AES_GCM, "AES-GCM",
       "24f26bc7e14189c513d2fb5a4888976bfba3cb476dacf61a2ab5199747b21bc2",
       "05636c3cb0b1ae94"},
      {CRYPTO_ALGO_CHACHA20_POLY1305, "ChaCha20-Poly1305",
       "105dd85955e2c399f053c842e5d893934bae41aac80afaab9605c57345ea1c1d",
       "328cd06f61a2680f"},
  };

  for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
    if (crypto_handler_select_algorithm(h_ptr, vectors[v].algo) != SPSEC_SUCCESS) {
      printf("    skip %s (unsupported by this backend)\n", vectors[v].name);
      continue;
    }
    CHECK(crypto_handler_set_context(h_ptr, key, nonce_ptr, REQUIRED_NONCE_LEN,
                                     AUTH_TAG_SIZE) == SPSEC_SUCCESS,
          "set context");

    uint8_t ct[32], tag[AUTH_TAG_SIZE];
    CHECK(crypto_handler_encrypt_with_assoc_data(h_ptr, plaintext, sizeof(plaintext),
                                                 ct, tag, aad,
                                                 sizeof(aad)) == SPSEC_SUCCESS,
          "encrypt succeeds");

    char ct_hex[65] = {0};
    for (int i = 0; i < 32; i++)
      snprintf(ct_hex + 2 * i, 3, "%02x", ct[i]);
    char tag_hex[17] = {0};
    for (int i = 0; i < AUTH_TAG_SIZE; i++)
      snprintf(tag_hex + 2 * i, 3, "%02x", tag[i]);

    char msg[128];
    snprintf(msg, sizeof(msg), "%s ciphertext matches known-answer vector",
             vectors[v].name);
    CHECK(strcmp(ct_hex, vectors[v].ct_hex) == 0, msg);
    snprintf(msg, sizeof(msg), "%s tag matches known-answer vector",
             vectors[v].name);
    CHECK(strcmp(tag_hex, vectors[v].tag_hex) == 0, msg);
  }
}

int main(void) {
  configure_logging("CRITICAL");

  test_nonce_layout();
  test_nonce_wrap_guard();

  CryptoHandler handler;
  if (crypto_handler_init(&handler) != SPSEC_SUCCESS) {
    fprintf(stderr, "crypto_handler_init failed\n");
    return 1;
  }
  test_cross_backend_kat(&handler);
  crypto_handler_destroy(&handler);

  if (g_failures) {
    fprintf(stderr, "\n%d check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nAll nonce/KAT checks passed.\n");
  return 0;
}
