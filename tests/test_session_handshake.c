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
 * @file test_session_handshake.c
 * @brief Unit tests for configuration session handshake, authentication, and termination.
 */

#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "register_operations.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include "utils_bytes.h"

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

#define TEST_PID 120

static const uint8_t s_prov_key[KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

static const uint8_t s_prov_salt[SALT_LEN] = {
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8};

static const uint8_t s_int_key[KEY_LEN] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78};

static const uint8_t s_int_salt[SALT_LEN] = {
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8};

static const uint8_t s_seed_key[KEY_LEN] = {
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8};

static const uint8_t s_seed_salt[SALT_LEN] = {
    0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8};

static void setup_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = TEST_PID;
  p_ptr->crypto_algorithm = CRYPTO_ALGO_AES_GCM;
  p_ptr->state_info.state = SPSEC_STATE_WAITING;
  p_ptr->state_info.last_event = SPSEC_NO_SEC_EVENT;

  crypto_handler_init(&p_ptr->crypto_handler);
  random_generator_init(&p_ptr->random_generator);
  timer_init(&p_ptr->timer, 8);

  communication_keys_init(&p_ptr->comm_keys);
  p_ptr->comm_keys.spsec_keys[1] = spseckey_new(1, s_prov_key);
  p_ptr->comm_keys.spsec_salt[1] = spsecsalt_new(s_prov_salt);
  p_ptr->comm_keys.spsec_keys[2] = spseckey_new(2, s_int_key);
  p_ptr->comm_keys.spsec_salt[2] = spsecsalt_new(s_int_salt);
  p_ptr->comm_keys.spsec_keys[3] = spseckey_new(3, s_seed_key);
  p_ptr->comm_keys.spsec_salt[3] = spsecsalt_new(s_seed_salt);

  p_ptr->secure_channel.channel.socket = -1;
  p_ptr->insecure_channel.socket = -1;
}

static void teardown_test_participant(Participant *p_ptr) {
  if (p_ptr->session.auth_tag_data_ptr) {
    authtagparticipantdata_free(p_ptr->session.auth_tag_data_ptr);
    p_ptr->session.auth_tag_data_ptr = NULL;
  }
  free(p_ptr->timesync.last_random_ptr);
  p_ptr->timesync.last_random_ptr = NULL;
  communication_keys_destroy(&p_ptr->comm_keys);
  crypto_handler_destroy(&p_ptr->crypto_handler);
  random_generator_free(&p_ptr->random_generator);
  timer_destroy(&p_ptr->timer);
}

/* ------------------------------------------------------------
 * 1. ClientHello Tests
 * ------------------------------------------------------------ */

static void test_client_hello(void) {
  printf("Testing participant_process_client_hello...\n");
  Participant p;
  setup_test_participant(&p);

  uint8_t client_random[RANDOM_SIZE];
  memset(client_random, 0x42, sizeof(client_random));

  /* Case 1: Wrong PID -> ignored */
  {
    SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID + 1, KEY_SELECTOR_ZERO, client_random);
    CHECK(participant_process_client_hello(&p, h_ptr) == SPSEC_STATUS_MSG_IGNORED,
          "ClientHello with wrong PID is ignored");
    CHECK(p.session.auth_tag_data_ptr == NULL, "no auth data allocated on wrong PID");
    spsecclienthello_free(h_ptr);
  }

  /* Case 2: Zero Key selector -> accepted */
  {
    SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID, KEY_SELECTOR_ZERO, client_random);
    CHECK(participant_process_client_hello(&p, h_ptr) == SPSEC_SUCCESS,
          "ClientHello with Zero Key is accepted");
    CHECK(p.session.active == true, "session is marked active");
    CHECK(p.session.auth_tag_data_ptr != NULL, "auth data allocated");
    spsecclienthello_free(h_ptr);
  }

  /* Case 3: Provisioning Key selector -> accepted */
  {
    SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID, KEY_SELECTOR_PROVISIONING, client_random);
    CHECK(participant_process_client_hello(&p, h_ptr) == SPSEC_SUCCESS,
          "ClientHello with Provisioning Key is accepted");
    CHECK(p.session.active == true, "session is active");
    spsecclienthello_free(h_ptr);
  }

  /* Case 4: Integrator Key selector -> accepted */
  {
    SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID, KEY_SELECTOR_INTEGRATOR, client_random);
    CHECK(participant_process_client_hello(&p, h_ptr) == SPSEC_SUCCESS,
          "ClientHello with Integrator Key is accepted");
    CHECK(p.session.active == true, "session is active");
    spsecclienthello_free(h_ptr);
  }

  /* Case 5: SEED KEY SELECTOR MUST BE REJECTED (REQ-PART-025 invariant) */
  {
    SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID, KEY_SELECTOR_SEED, client_random);
    spsec_ret_t ret = participant_process_client_hello(&p, h_ptr);
    CHECK(ret == SPSEC_ERROR_KEY_NOT_FOUND, "ClientHello with Seed Key selector is REJECTED");
    CHECK(p.state_info.last_event == SPSEC_SESS_HELLO_KEY_NOT_FOUND,
          "rejection reports SPSEC_SESS_HELLO_KEY_NOT_FOUND");
    spsecclienthello_free(h_ptr);
  }

  /* Case 6: Unknown key selector -> rejected */
  {
    SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID, 99, client_random);
    spsec_ret_t ret = participant_process_client_hello(&p, h_ptr);
    CHECK(ret == SPSEC_ERROR_KEY_NOT_FOUND, "ClientHello with unknown selector is rejected");
    CHECK(p.state_info.last_event == SPSEC_SESS_HELLO_KEY_NOT_FOUND,
          "unknown selector reports SPSEC_SESS_HELLO_KEY_NOT_FOUND");
    spsecclienthello_free(h_ptr);
  }

  teardown_test_participant(&p);
}

/* ------------------------------------------------------------
 * 2. ClientFinished Tests
 * ------------------------------------------------------------ */

static void test_client_finished(void) {
  printf("Testing participant_process_client_finished...\n");
  Participant p;
  setup_test_participant(&p);

  /* Case 1: Unsolicited ClientFinished (no ClientHello) -> safely ignored, no crash */
  {
    SPsecClientFinishedMessage *f_ptr = spsecclientfinished_new(TEST_PID, 1);
    CHECK(participant_process_client_finished(&p, f_ptr) == SPSEC_STATUS_MSG_IGNORED,
          "unsolicited ClientFinished is safely ignored without crash");
    spsecclientfinished_free(f_ptr);
  }

  /* Case 2: Wrong PID -> ignored */
  {
    uint8_t client_random[RANDOM_SIZE];
    memset(client_random, 0x11, sizeof(client_random));
    SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID, KEY_SELECTOR_PROVISIONING, client_random);
    participant_process_client_hello(&p, h_ptr);
    spsecclienthello_free(h_ptr);

    SPsecClientFinishedMessage *f_ptr = spsecclientfinished_new(TEST_PID + 1, p.session.cnt + 1);
    CHECK(participant_process_client_finished(&p, f_ptr) == SPSEC_STATUS_MSG_IGNORED,
          "ClientFinished for wrong PID is ignored");
    spsecclientfinished_free(f_ptr);
  }

  /* Case 3: Invalid auth tag -> rejected, counter not advanced, event reported */
  {
    uint32_t initial_cnt = p.session.cnt;
    SPsecClientFinishedMessage *f_ptr = spsecclientfinished_new(TEST_PID, initial_cnt + 1);
    f_ptr->address = 0x1E010078;
    memset(f_ptr->auth_tag, 0xDE, sizeof(f_ptr->auth_tag)); /* bogus tag */

    spsec_ret_t ret = participant_process_client_finished(&p, f_ptr);
    CHECK(ret == SPSEC_ERROR_CRYPTO_AUTH, "ClientFinished with bad tag returns SPSEC_ERROR_CRYPTO_AUTH");
    CHECK(p.session.cnt == initial_cnt, "session counter is NOT advanced on failed tag");
    CHECK(p.state_info.last_event == SPSEC_SESS_FINISH_AUTH_FAILURE,
          "failed tag reports SPSEC_SESS_FINISH_AUTH_FAILURE");
    spsecclientfinished_free(f_ptr);
  }

  /* Case 4: Bad auth tag -> rejected, counter does not advance, event raised */
  {
    uint32_t cnt_before = p.session.cnt;
    SPsecClientFinishedMessage *f_ptr = spsecclientfinished_new(TEST_PID, cnt_before + 1);
    f_ptr->address = 0x1E000000;
    memset(f_ptr->auth_tag, 0xEE, AUTH_TAG_SIZE);
    spsec_ret_t ret = participant_process_client_finished(&p, f_ptr);
    CHECK(ret == SPSEC_ERROR_CRYPTO_AUTH, "ClientFinished with bad tag rejected");
    CHECK(p.session.cnt == cnt_before, "counter does not advance on bad ClientFinished");
    CHECK(p.state_info.last_event == SPSEC_SESS_FINISH_AUTH_FAILURE,
          "reports SPSEC_SESS_FINISH_AUTH_FAILURE on bad ClientFinished tag");
    spsecclientfinished_free(f_ptr);
  }

  /* Case 5: Valid auth tag -> accepted, counter advanced, cli_auth_tag saved */
  {
    uint32_t initial_cnt = p.session.cnt;
    uint32_t validated_cnt = initial_cnt + 1;
    uint32_t test_address = 0x1E010078;

    /* Build associated data matching prepare_client_finished_assoc_data() */
    uint8_t assoc_data[40];
    memcpy(assoc_data, p.session.auth_tag_data_ptr->key_selector, KEY_SELECTOR_SIZE);
    memcpy(assoc_data + 4, p.session.auth_tag_data_ptr->cli_random, RANDOM_SIZE);
    memcpy(assoc_data + 20, p.session.auth_tag_data_ptr->srv_random, RANDOM_SIZE);
    u32_to_bytes_le(test_address, assoc_data + 36);

    /* Generate nonce from validated_cnt */
    uint8_t *nonce_ptr = NULL;
    generate_nonce_from_session_cnt(validated_cnt, &nonce_ptr, p.session.auth_tag_data_ptr->spsec_salt_ptr);
    CHECK(nonce_ptr != NULL, "nonce generated for valid test tag");

    uint8_t expected_tag[AUTH_TAG_SIZE];
    setup_crypto_context_and_calculate_tag(&p.crypto_handler, p.session.key, nonce_ptr,
                                           REQUIRED_NONCE_LEN, assoc_data, sizeof(assoc_data),
                                           expected_tag, AUTH_TAG_SIZE);
    free(nonce_ptr);

    SPsecClientFinishedMessage *f_ptr = spsecclientfinished_new(TEST_PID, validated_cnt);
    f_ptr->address = test_address;
    memcpy(f_ptr->auth_tag, expected_tag, AUTH_TAG_SIZE);

    spsec_ret_t ret = participant_process_client_finished(&p, f_ptr);
    CHECK(ret == SPSEC_SUCCESS, "ClientFinished with valid auth tag is accepted");
    CHECK(p.session.cnt == validated_cnt, "session counter advances to validated_cnt");
    CHECK(memcmp(p.session.auth_tag_data_ptr->cli_auth_tag, expected_tag, AUTH_TAG_SIZE) == 0,
          "client auth tag saved in session auth data");
    spsecclientfinished_free(f_ptr);
  }

  teardown_test_participant(&p);
}

/* ------------------------------------------------------------
 * 3. SessionTerminate Tests
 * ------------------------------------------------------------ */

static void test_session_terminate(void) {
  printf("Testing participant_process_session_terminate...\n");
  Participant p;
  setup_test_participant(&p);

  /* Case 1: Unsolicited SessionTerminate -> safely ignored */
  {
    SPsecSessionTerminateMessage *t_ptr = spsecsessionterminatemsg_new(TEST_PID, 1);
    CHECK(participant_process_session_terminate(&p, t_ptr) == SPSEC_STATUS_MSG_IGNORED,
          "unsolicited SessionTerminate is safely ignored");
    spsecsessionterminatemsg_free(t_ptr);
  }

  /* Establish session first */
  uint8_t client_random[RANDOM_SIZE];
  memset(client_random, 0x77, sizeof(client_random));
  SPsecClientHelloMessage *h_ptr = spsecclienthello_new(TEST_PID, KEY_SELECTOR_PROVISIONING, client_random);
  participant_process_client_hello(&p, h_ptr);
  spsecclienthello_free(h_ptr);

  /* Case 2: Wrong PID -> ignored */
  {
    SPsecSessionTerminateMessage *t_ptr = spsecsessionterminatemsg_new(TEST_PID + 1, p.session.cnt);
    CHECK(participant_process_session_terminate(&p, t_ptr) == SPSEC_STATUS_MSG_IGNORED,
          "SessionTerminate for wrong PID is ignored");
    spsecsessionterminatemsg_free(t_ptr);
  }

  /* Case 3: Bad auth tag -> rejected, counter rolled back, event raised */
  {
    uint32_t cnt_before = p.session.cnt;
    SPsecSessionTerminateMessage *t_ptr = spsecsessionterminatemsg_new(TEST_PID, cnt_before);
    t_ptr->address = 0x1E010678;
    memset(t_ptr->auth_tag, 0xEE, sizeof(t_ptr->auth_tag)); /* bogus */

    spsec_ret_t ret = participant_process_session_terminate(&p, t_ptr);
    CHECK(ret == SPSEC_ERROR_CRYPTO_AUTH, "terminate with bad tag returns SPSEC_ERROR_CRYPTO_AUTH");
    CHECK(p.session.cnt == cnt_before, "counter is rolled back on bad terminate tag");
    CHECK(p.state_info.last_event == SPSEC_SESS_KEY_AUTH_FAILURE,
          "reports SPSEC_SESS_KEY_AUTH_FAILURE on bad terminate tag");
    spsecsessionterminatemsg_free(t_ptr);
  }

  /* Case 4: Valid auth tag -> accepted */
  {
    uint32_t cnt_before = p.session.cnt;
    uint32_t term_cnt = cnt_before + 1;
    uint32_t term_address = 0x1E010678;

    uint8_t *nonce_ptr = NULL;
    generate_nonce_from_session_cnt(term_cnt, &nonce_ptr, p.session.auth_tag_data_ptr->spsec_salt_ptr);
    CHECK(nonce_ptr != NULL, "nonce generated for terminate");

    uint8_t expected_tag[AUTH_TAG_SIZE];
    uint8_t *assoc_data_ptr = (uint8_t *)&term_address;
    setup_crypto_context_and_calculate_tag(&p.crypto_handler, p.session.key, nonce_ptr,
                                           REQUIRED_NONCE_LEN, assoc_data_ptr, 4,
                                           expected_tag, AUTH_TAG_SIZE);
    free(nonce_ptr);

    SPsecSessionTerminateMessage *t_ptr = spsecsessionterminatemsg_new(TEST_PID, cnt_before);
    t_ptr->address = term_address;
    memcpy(t_ptr->auth_tag, expected_tag, AUTH_TAG_SIZE);

    spsec_ret_t ret = participant_process_session_terminate(&p, t_ptr);
    CHECK(ret == SPSEC_SUCCESS, "terminate with valid tag returns SPSEC_SUCCESS");
    CHECK(p.session.cnt == term_cnt, "counter committed after valid terminate");
    spsecsessionterminatemsg_free(t_ptr);
  }

  teardown_test_participant(&p);
}

int main(void) {
  test_client_hello();
  test_client_finished();
  test_session_terminate();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d session_handshake check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All session_handshake checks passed.\n");
  return 0;
}
