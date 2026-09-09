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
 * @file test_timesync_auth.c
 * @brief Tests one-time key derivation and authentication for time synchronization.
 */

#include "crypto.h"
#include "crypto_kdf.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_keys.h"
#include "participant_timesync.h"
#include "spsec_common.h"
#include "spsec_errors.h"
#include "timer.h"

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

#define CLIENT_PID 121
#define TSA_PID 120

static void init_client_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = CLIENT_PID;
  p_ptr->crypto_algorithm = CRYPTO_ALGO_AES_GCM;
  crypto_handler_init(&p_ptr->crypto_handler);
  crypto_handler_select_algorithm(&p_ptr->crypto_handler, p_ptr->crypto_algorithm);
  timer_init(&p_ptr->timer, 8);
  communication_keys_init(&p_ptr->comm_keys);

  /* Set up seed key and salt */
  uint8_t seed[KEY_LEN];
  for (int i = 0; i < KEY_LEN; i++)
    seed[i] = (uint8_t)(0x30 + i);
  p_ptr->comm_keys.spsec_keys[3] = spseckey_new(0x12345678, seed);

  uint8_t salt[SALT_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
  p_ptr->comm_keys.spsec_salt[3] = spsecsalt_new(salt);
}

static void teardown_participant(Participant *p_ptr) {
  communication_keys_destroy(&p_ptr->comm_keys);
  crypto_handler_destroy(&p_ptr->crypto_handler);
  timer_destroy(&p_ptr->timer);
}

static void compute_expected_mtls_tag(Participant *p_ptr,
                                      const uint8_t *random_bytes_ptr,
                                      const uint8_t *timestamp_ptr,
                                      const uint8_t *csalt_ptr,
                                      uint8_t pid,
                                      uint8_t *out_tag_ptr) {
  /* One-time key = HKDF(IKM=SeedKey, Salt=rnd[12]||tim[8]||csalt[4], Info=NULL) per SPsec302 §6.5.2 */
  uint8_t salt[24];
  memcpy(salt, random_bytes_ptr, 12);
  memcpy(salt + 12, timestamp_ptr, 8);
  memcpy(salt + 20, csalt_ptr, 4);

  uint8_t one_time_key[KEY_LEN];
  crypto_hkdf_sha256(p_ptr->comm_keys.spsec_keys[3]->key, KEY_LEN,
                     salt, sizeof(salt),
                     NULL, 0,
                     one_time_key, KEY_LEN);

  /* Associated data: random || timestamp || csalt || can_id */
  uint8_t assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 4];
  memcpy(assoc_data, random_bytes_ptr, RANDOM_SIZE);
  memcpy(assoc_data + RANDOM_SIZE, timestamp_ptr, TIMESTAMP_SIZE);
  memcpy(assoc_data + RANDOM_SIZE + TIMESTAMP_SIZE, csalt_ptr, 4);

  uint32_t can_id = (0x00230000 | (CPMT_AUTH_TIME << 8) | (pid | 0x80));
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 0] = (uint8_t)(can_id & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 1] = (uint8_t)((can_id >> 8) & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 2] = (uint8_t)((can_id >> 16) & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 3] = (uint8_t)((can_id >> 24) & 0xFF);

  uint8_t nonce[REQUIRED_NONCE_LEN];
  memset(nonce, 0, sizeof(nonce));

  crypto_handler_set_context(&p_ptr->crypto_handler, one_time_key, nonce, 12, AUTH_TAG_SIZE);
  crypto_handler_update(&p_ptr->crypto_handler, assoc_data, sizeof(assoc_data));
  size_t tag_len = AUTH_TAG_SIZE;
  crypto_handler_get_digest(&p_ptr->crypto_handler, out_tag_ptr, &tag_len);
}

static void test_client_timesync_auth_success(void) {
  printf("Testing client timesync valid authentication tag...\n");
  Participant client;
  init_client_participant(&client);

  uint8_t client_random[RANDOM_SIZE];
  memset(client_random, 0x55, sizeof(client_random));

  uint8_t srv_ts[TIMESTAMP_SIZE] = {0x10, 0x20, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00};
  uint8_t srv_csalt[4] = {0xAA, 0xBB, 0xCC, 0xDD};

  uint8_t valid_tag[AUTH_TAG_SIZE];
  compute_expected_mtls_tag(&client, client_random, srv_ts, srv_csalt,
                            client.participant_id, valid_tag);

  SPsecTimeSyncResponse *resp_ptr =
      timesyncresponse_new(srv_ts, srv_csalt, valid_tag, AUTH_TAG_SIZE,
                           client.participant_id);
  CHECK(resp_ptr != NULL, "response message allocated");

  signed char ret = participant_process_mtls_auth_time(&client, resp_ptr, client_random);
  CHECK(ret == 0, "participant_process_mtls_auth_time returns 0 on authentic response");
  CHECK(client.timesync.last_successful > 0, "timesync last_successful updated");
  CHECK(memcmp(client.comm_keys.csalt, srv_csalt, 4) == 0, "csalt saved in communication keys");

  timesyncresponse_free(resp_ptr);
  teardown_participant(&client);
}

static void test_client_timesync_auth_bad_tag(void) {
  printf("Testing client timesync corrupted authentication tag rejection...\n");
  Participant client;
  init_client_participant(&client);

  uint8_t client_random[RANDOM_SIZE];
  memset(client_random, 0x55, sizeof(client_random));

  uint8_t srv_ts[TIMESTAMP_SIZE] = {0x10, 0x20, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00};
  uint8_t srv_csalt[4] = {0xAA, 0xBB, 0xCC, 0xDD};

  uint8_t corrupt_tag[AUTH_TAG_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00};

  SPsecTimeSyncResponse *resp_ptr =
      timesyncresponse_new(srv_ts, srv_csalt, corrupt_tag, AUTH_TAG_SIZE,
                           client.participant_id);

  signed char ret = participant_process_mtls_auth_time(&client, resp_ptr, client_random);
  CHECK(ret < 0, "participant_process_mtls_auth_time returns negative on bad tag");
  CHECK(client.timesync.last_successful == 0, "timesync last_successful remains 0 on failed auth");
  CHECK(client.state_info.last_event == SPSEC_SYNC_REQ_AUTH_FAILURE,
        "reports SPSEC_SYNC_REQ_AUTH_FAILURE on bad mTLS tag");

  timesyncresponse_free(resp_ptr);
  teardown_participant(&client);
}

static void test_client_timesync_wrong_pid(void) {
  printf("Testing client timesync ignores response for other PID...\n");
  Participant client;
  init_client_participant(&client);

  uint8_t client_random[RANDOM_SIZE] = {0};
  uint8_t srv_ts[TIMESTAMP_SIZE] = {0};
  uint8_t srv_csalt[4] = {0};
  uint8_t dummy_tag[AUTH_TAG_SIZE] = {0};

  SPsecTimeSyncResponse *resp_ptr =
      timesyncresponse_new(srv_ts, srv_csalt, dummy_tag, AUTH_TAG_SIZE,
                           CLIENT_PID + 1);

  signed char ret = participant_process_mtls_auth_time(&client, resp_ptr, client_random);
  CHECK(ret == 1, "response for wrong PID safely ignored (returns 1)");

  timesyncresponse_free(resp_ptr);
  teardown_participant(&client);
}

static void test_tsa_csalt_guards(void) {
  printf("Testing TSA timesync guards (unset csalt)...\n");
  Participant tsa;
  memset(&tsa, 0, sizeof(tsa));
  tsa.participant_id = TSA_PID;
  tsa.timesync.is_role_authority = true;

  uint8_t rnd[RANDOM_SIZE] = {0x01};
  SPsecTimeSyncRequest *req_ptr = timesyncrequest_new(CLIENT_PID, rnd);

  /* Case A: csalt is all zeros -> rejects */
  signed char ret = timesync_process_mtls_auth_time(&tsa, req_ptr);
  CHECK(ret == -1, "TSA rejects request when csalt is unset (all zeros)");

  timesyncrequest_free(req_ptr);
}

int main(void) {
  test_client_timesync_auth_success();
  test_client_timesync_auth_bad_tag();
  test_client_timesync_wrong_pid();
  test_tsa_csalt_guards();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d timesync_auth check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All timesync_auth checks passed.\n");
  return 0;
}
