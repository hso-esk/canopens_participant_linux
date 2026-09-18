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

// Regression tests for message constructors, destructors, and parsers.
#include "messages.h"
#include "spsec_common.h"

#include <assert.h>
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

/* Test group: handshake messages */
static void test_handshake(void) {
  fprintf(stderr, "\n=== Handshake Messages ===\n");

  /* Test spsecclienthello_new/_free */
  uint8_t cli_random[RANDOM_SIZE];
  for (int i = 0; i < RANDOM_SIZE; i++) {
    cli_random[i] = (uint8_t)(i + 10);
  }

  SPsecClientHelloMessage *cli_hello_ptr = spsecclienthello_new(42, 5, cli_random);
  CHECK(cli_hello_ptr != NULL, "spsecclienthello_new allocates memory");
  if (cli_hello_ptr) {
    CHECK(cli_hello_ptr->participant_id == 42, "spsecclienthello: participant_id preserved");
    CHECK(cli_hello_ptr->key_selector[0] == 5, "spsecclienthello: key_selector[0] set from parameter");
    CHECK(cli_hello_ptr->key_selector[1] == 0xFF, "spsecclienthello: key_selector[1] == 0xFF");
    CHECK(cli_hello_ptr->key_selector[2] == 0xFF, "spsecclienthello: key_selector[2] == 0xFF");
    CHECK(cli_hello_ptr->key_selector[3] == 0xFF, "spsecclienthello: key_selector[3] == 0xFF");
    CHECK(memcmp(cli_hello_ptr->random, cli_random, RANDOM_SIZE) == 0, "spsecclienthello: random copied");
    spsecclienthello_free(cli_hello_ptr);
  }

  /* Test spsecserverhello_new/_free */
  uint8_t srv_random[RANDOM_SIZE];
  for (int i = 0; i < RANDOM_SIZE; i++) {
    srv_random[i] = (uint8_t)(i + 20);
  }

  SPsecServerHelloMessage *srv_hello_ptr = spsecserverhello_new(73, srv_random);
  CHECK(srv_hello_ptr != NULL, "spsecserverhello_new allocates memory");
  if (srv_hello_ptr) {
    CHECK(srv_hello_ptr->participant_id == 73, "spsecserverhello: participant_id preserved");
    CHECK(memcmp(srv_hello_ptr->random, srv_random, RANDOM_SIZE) == 0, "spsecserverhello: random copied");
    spsecserverhello_free(srv_hello_ptr);
  }

  /* Test spsecclientfinished_new/_free */
  SPsecClientFinishedMessage *cli_fin_ptr = spsecclientfinished_new(50, 0x12345678);
  CHECK(cli_fin_ptr != NULL, "spsecclientfinished_new allocates memory");
  if (cli_fin_ptr) {
    CHECK(cli_fin_ptr->participant_id == 50, "spsecclientfinished: participant_id preserved");
    CHECK(cli_fin_ptr->cnt == 0x12345678, "spsecclientfinished: cnt preserved");
    spsecclientfinished_free(cli_fin_ptr);
  }

  /* Test spsecserverfinished_new/_free */
  SPsecServerFinishedMessage *srv_fin_ptr = spsecserverfinished_new(99, 0xDEADBEEF);
  CHECK(srv_fin_ptr != NULL, "spsecserverfinished_new allocates memory");
  if (srv_fin_ptr) {
    CHECK(srv_fin_ptr->participant_id == 99, "spsecserverfinished: participant_id preserved");
    CHECK(srv_fin_ptr->cnt == 0xDEADBEEF, "spsecserverfinished: cnt preserved");
    spsecserverfinished_free(srv_fin_ptr);
  }

  /* Test authtagparticipantdata_new/_free with zero-initialization */
  ConfigurationSessionAuthTagData *auth_data_ptr = authtagparticipantdata_new();
  CHECK(auth_data_ptr != NULL, "authtagparticipantdata_new allocates memory");
  if (auth_data_ptr) {
    uint8_t zero_buf[sizeof(ConfigurationSessionAuthTagData)];
    memset(zero_buf, 0, sizeof(zero_buf));
    CHECK(memcmp(auth_data_ptr, zero_buf, sizeof(ConfigurationSessionAuthTagData)) == 0,
          "authtagparticipantdata: all fields zero-initialized");
    
    /* Now test calculate_shared_cnt with known values */
    auth_data_ptr->cli_random[0] = 0x01;
    auth_data_ptr->cli_random[1] = 0x02;
    auth_data_ptr->cli_random[2] = 0x03;
    auth_data_ptr->cli_random[3] = 0x04;
    
    auth_data_ptr->srv_random[0] = 0x10;
    auth_data_ptr->srv_random[1] = 0x20;
    auth_data_ptr->srv_random[2] = 0x30;
    auth_data_ptr->srv_random[3] = 0x40;
    
    uint32_t shared_cnt = calculate_shared_cnt(auth_data_ptr);
    /* XOR: {0x11, 0x22, 0x33, 0x44} -> little-endian 0x44332211 */
    CHECK(shared_cnt == 0x44332211, "calculate_shared_cnt: correct XOR result (0x44332211)");

    /* Additional test case: all zeros */
    memset(auth_data_ptr, 0, sizeof(ConfigurationSessionAuthTagData));
    shared_cnt = calculate_shared_cnt(auth_data_ptr);
    CHECK(shared_cnt == 0, "calculate_shared_cnt: zero XOR gives 0");

    /* Another test: all ones in first 4 bytes */
    memset(auth_data_ptr->cli_random, 0xFF, 4);
    memset(auth_data_ptr->srv_random, 0x00, 4);
    shared_cnt = calculate_shared_cnt(auth_data_ptr);
    CHECK(shared_cnt == 0xFFFFFFFF, "calculate_shared_cnt: 0xFF XOR 0x00 gives 0xFFFFFFFF");

    authtagparticipantdata_free(auth_data_ptr);
  }

  /* Test spsecsessionterminatemsg_new/_free */
  SPsecSessionTerminateMessage *term_msg_ptr = spsecsessionterminatemsg_new(25, 0xAABBCCDD);
  CHECK(term_msg_ptr != NULL, "spsecsessionterminatemsg_new allocates memory");
  if (term_msg_ptr) {
    CHECK(term_msg_ptr->participant_id == 25, "spsecsessionterminatemsg: participant_id preserved");
    CHECK(term_msg_ptr->cnt == 0xAABBCCDD, "spsecsessionterminatemsg: cnt preserved");
    spsecsessionterminatemsg_free(term_msg_ptr);
  }
}

/* Test group: register messages (read/write) */
static void test_register(void) {
  fprintf(stderr, "\n=== Register Messages ===\n");

  /* Test spsecreadinitiatemessage_new + parse_plaintext round-trip */
  SPsecReadInitiateMessage *read_init_ptr = spsecreadinitiatemessage_new(11, 0x11223344, 5, 1000);
  CHECK(read_init_ptr != NULL, "spsecreadinitiatemessage_new allocates memory");
  if (read_init_ptr) {
    /* Before parse */
    CHECK(read_init_ptr->reg == 5, "spsecreadinitiatemessage: reg field set before parse");
    CHECK(read_init_ptr->len == 1000, "spsecreadinitiatemessage: len field set before parse");
    
    /* Check plaintext encoding */
    CHECK(read_init_ptr->plaintext[0] == 5, "spsecreadinitiatemessage: plaintext[0] == reg");
    CHECK(read_init_ptr->plaintext[1] == 0xFF, "spsecreadinitiatemessage: plaintext[1] == 0xFF");
    CHECK(read_init_ptr->plaintext[2] == 0xFF, "spsecreadinitiatemessage: plaintext[2] == 0xFF");
    CHECK(read_init_ptr->plaintext[3] == 0xFF, "spsecreadinitiatemessage: plaintext[3] == 0xFF");
    
    /* Check little-endian length encoding */
    uint32_t len_encoded = (uint32_t)read_init_ptr->plaintext[4] |
                          ((uint32_t)read_init_ptr->plaintext[5] << 8) |
                          ((uint32_t)read_init_ptr->plaintext[6] << 16) |
                          ((uint32_t)read_init_ptr->plaintext[7] << 24);
    CHECK(len_encoded == 1000, "spsecreadinitiatemessage: length little-endian encoded correctly");

    /* Test parse_plaintext */
    spsecreadinitiatemessage_parse_plaintext(read_init_ptr);
    CHECK(read_init_ptr->reg == 5, "spsecreadinitiatemessage_parse_plaintext: reg round-trip");
    CHECK(read_init_ptr->len == 1000, "spsecreadinitiatemessage_parse_plaintext: len round-trip");

    spsecreadinitiatemessage_free(read_init_ptr);
  }

  /* Test spsecreadsegmentrequest_new/_free */
  SPsecClientReadSegmentRequest *read_seg_req_ptr = spsecreadsegmentrequest_new(15, 0x99887766);
  CHECK(read_seg_req_ptr != NULL, "spsecreadsegmentrequest_new allocates memory");
  if (read_seg_req_ptr) {
    CHECK(read_seg_req_ptr->participant_id == 15, "spsecreadsegmentrequest: participant_id");
    CHECK(read_seg_req_ptr->cnt == 0x99887766, "spsecreadsegmentrequest: cnt");
    spsecreadsegmentrequest_free(read_seg_req_ptr);
  }

  /* Test spsecreadsegmentresponse_new/_free with malloc'd data_ptr */
  uint8_t *data_buf_ptr = (uint8_t *)malloc(50);
  CHECK(data_buf_ptr != NULL, "malloc data buffer for read segment response");
  if (data_buf_ptr) {
    for (int i = 0; i < 50; i++) {
      data_buf_ptr[i] = (uint8_t)i;
    }
    
    SPsecServerReadSegmentResponse *read_seg_resp_ptr = 
        spsecreadsegmentresponse_new(22, 0x44556677, data_buf_ptr, 50);
    CHECK(read_seg_resp_ptr != NULL, "spsecreadsegmentresponse_new allocates memory");
    if (read_seg_resp_ptr) {
      CHECK(read_seg_resp_ptr->data_ptr == data_buf_ptr, "spsecreadsegmentresponse: data_ptr aliased correctly");
      CHECK(read_seg_resp_ptr->data_len == 50, "spsecreadsegmentresponse: data_len preserved");
      CHECK(read_seg_resp_ptr->ciphertext_ptr == NULL, "spsecreadsegmentresponse: ciphertext_ptr starts NULL");
      spsecreadsegmentresponse_free(read_seg_resp_ptr);
    } else {
      free(data_buf_ptr);
    }
  }

  /* Test spsecwriteinitiatemessage_new + parse_plaintext round-trip */
  SPsecWriteInitiateMessage *write_init_ptr = spsecwriteinitiatemessage_new(33, 0x55667788, 7, 500);
  CHECK(write_init_ptr != NULL, "spsecwriteinitiatemessage_new allocates memory");
  if (write_init_ptr) {
    CHECK(write_init_ptr->reg == 7, "spsecwriteinitiatemessage: reg field");
    CHECK(write_init_ptr->len == 500, "spsecwriteinitiatemessage: len field");
    CHECK(write_init_ptr->plaintext[0] == 7, "spsecwriteinitiatemessage: plaintext[0]");
    CHECK(write_init_ptr->plaintext[1] == 0xFF, "spsecwriteinitiatemessage: plaintext[1]");
    
    spsecwriteinitiatemessage_parse_plaintext(write_init_ptr);
    CHECK(write_init_ptr->reg == 7, "spsecwriteinitiatemessage_parse_plaintext: reg round-trip");
    CHECK(write_init_ptr->len == 500, "spsecwriteinitiatemessage_parse_plaintext: len round-trip");

    spsecwriteinitiatemessage_free(write_init_ptr);
  }

  /* Test spsecwritesegmentmessage_parse_plaintext with error code */
  SPsecClientWriteSegmentResponse *write_seg_resp_ptr = spsecwritesegmentresponse_new(44, 0x12341234, 42);
  CHECK(write_seg_resp_ptr != NULL, "spsecwritesegmentresponse_new allocates memory");
  if (write_seg_resp_ptr) {
    CHECK(write_seg_resp_ptr->err == 42, "spsecwritesegmentresponse: err field");
    CHECK(write_seg_resp_ptr->plaintext[0] == 42, "spsecwritesegmentresponse: plaintext[0] == err");
    CHECK(write_seg_resp_ptr->plaintext[1] == 0xFF, "spsecwritesegmentresponse: plaintext[1] == 0xFF");
    
    spsecwritesegmentmessage_parse_plaintext(write_seg_resp_ptr);
    CHECK(write_seg_resp_ptr->err == 42, "spsecwritesegmentresponse_parse_plaintext: err round-trip");

    spsecwritesegmentresponse_free(write_seg_resp_ptr);
  }

  /* Test spsecwritesegmentrequest_new/_free with malloc'd data_ptr */
  uint8_t test_data[32];
  for (int i = 0; i < 32; i++) {
    test_data[i] = (uint8_t)(i * 2);
  }
  
  SPsecClientWriteSegmentRequest *write_seg_req_ptr = 
      spsecwritesegmentrequest_new(55, 0xAABBCCDD, test_data, (uint8_t)32);
  CHECK(write_seg_req_ptr != NULL, "spsecwritesegmentrequest_new allocates memory");
  if (write_seg_req_ptr) {
    CHECK(write_seg_req_ptr->data_ptr != NULL, "spsecwritesegmentrequest: data_ptr allocated");
    CHECK(write_seg_req_ptr->ciphertext_ptr != NULL, "spsecwritesegmentrequest: ciphertext_ptr allocated");
    CHECK(write_seg_req_ptr->data_ptr != write_seg_req_ptr->ciphertext_ptr, "spsecwritesegmentrequest: data and ciphertext separate");
    CHECK(memcmp(write_seg_req_ptr->data_ptr, test_data, 32) == 0, "spsecwritesegmentrequest: data copied");
    
    /* Check auth_tag is zero-initialized */
    uint8_t zero_tag[AUTH_TAG_SIZE];
    memset(zero_tag, 0, AUTH_TAG_SIZE);
    CHECK(memcmp(write_seg_req_ptr->auth_tag, zero_tag, AUTH_TAG_SIZE) == 0, 
          "spsecwritesegmentrequest: auth_tag zero-initialized");

    /* Verify data was copied, not aliased */
    test_data[0] = 99;
    CHECK(write_seg_req_ptr->data_ptr[0] != 99, "spsecwritesegmentrequest: data is copy, not alias");

    spsecwritesegmentrequest_free(write_seg_req_ptr);
  }
}

/* Test group: session messages */
static void test_session(void) {
  fprintf(stderr, "\n=== Session Messages ===\n");

  /* Test timesyncrequest_new/_free */
  uint8_t ts_req_random[RANDOM_SIZE];
  for (int i = 0; i < RANDOM_SIZE; i++) {
    ts_req_random[i] = (uint8_t)(i + 30);
  }

  SPsecTimeSyncRequest *ts_req_ptr = timesyncrequest_new(66, ts_req_random);
  CHECK(ts_req_ptr != NULL, "timesyncrequest_new allocates memory");
  if (ts_req_ptr) {
    CHECK(ts_req_ptr->participant_id == 66, "timesyncrequest: participant_id");
    CHECK(memcmp(ts_req_ptr->random, ts_req_random, 16) == 0, "timesyncrequest: random[16] copied");
    timesyncrequest_free(ts_req_ptr);
  }

  /* Test timesyncresponse_new/_free with csalt != NULL */
  uint8_t timestamp[8];
  for (int i = 0; i < 8; i++) {
    timestamp[i] = (uint8_t)(i + 40);
  }
  uint8_t csalt_data[4] = {0x11, 0x22, 0x33, 0x44};
  uint8_t auth_tag[AUTH_TAG_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

  SPsecTimeSyncResponse *ts_resp_ptr = timesyncresponse_new(timestamp, csalt_data, auth_tag, AUTH_TAG_SIZE, 77);
  CHECK(ts_resp_ptr != NULL, "timesyncresponse_new (with csalt) allocates memory");
  if (ts_resp_ptr) {
    CHECK(ts_resp_ptr->participant_id == 77, "timesyncresponse: participant_id");
    CHECK(memcmp(ts_resp_ptr->timestamp, timestamp, 8) == 0, "timesyncresponse: timestamp copied");
    CHECK(memcmp(ts_resp_ptr->csalt, csalt_data, 4) == 0, "timesyncresponse: csalt copied when not NULL");
    CHECK(ts_resp_ptr->auth_tag_len == AUTH_TAG_SIZE, "timesyncresponse: auth_tag_len");
    timesyncresponse_free(ts_resp_ptr);
  }

  /* Test timesyncresponse_new/_free with csalt == NULL (must memset to 0) */
  SPsecTimeSyncResponse *ts_resp_no_csalt_ptr = timesyncresponse_new(timestamp, NULL, auth_tag, AUTH_TAG_SIZE, 88);
  CHECK(ts_resp_no_csalt_ptr != NULL, "timesyncresponse_new (with csalt=NULL) allocates memory");
  if (ts_resp_no_csalt_ptr) {
    uint8_t zero_csalt[4];
    memset(zero_csalt, 0, 4);
    CHECK(memcmp(ts_resp_no_csalt_ptr->csalt, zero_csalt, 4) == 0, "timesyncresponse: csalt memset to 0 when NULL");
    timesyncresponse_free(ts_resp_no_csalt_ptr);
  }

  /* Test appdata_new/_free with stack buffer (copied, not aliased) */
  uint8_t app_buf[16];
  for (int i = 0; i < 16; i++) {
    app_buf[i] = (uint8_t)(i + 50);
  }

  AppData *app_data_ptr = appdata_new(0x12345678, app_buf, 16);
  CHECK(app_data_ptr != NULL, "appdata_new allocates memory");
  if (app_data_ptr) {
    CHECK(app_data_ptr->address == 0x12345678, "appdata: address preserved");
    CHECK(app_data_ptr->data_len == 16, "appdata: data_len");
    CHECK(memcmp(app_data_ptr->data_ptr, app_buf, 16) == 0, "appdata: data copied");

    /* Verify data was copied, not aliased */
    app_buf[0] = 200;
    CHECK(app_data_ptr->data_ptr[0] != 200, "appdata: data is copy, not alias");

    appdata_free(app_data_ptr);
  }

  /* Test spsecappdata_new/_free */
  uint8_t secure_data[24];
  for (int i = 0; i < 24; i++) {
    secure_data[i] = (uint8_t)(i + 60);
  }
  uint8_t app_auth_tag[AUTH_TAG_SIZE];
  for (int i = 0; i < AUTH_TAG_SIZE; i++) {
    app_auth_tag[i] = (uint8_t)(i + 70);
  }
  uint8_t app_ts[TIMESTAMP_SIZE];
  for (int i = 0; i < TIMESTAMP_SIZE; i++) {
    app_ts[i] = (uint8_t)(i + 80);
  }

  SPsecAppData *spsec_app_data_ptr = spsecappdata_new(0x87654321, secure_data, 24, 1, app_ts, app_auth_tag, AUTH_TAG_SIZE);
  CHECK(spsec_app_data_ptr != NULL, "spsecappdata_new allocates memory");
  if (spsec_app_data_ptr) {
    CHECK(spsec_app_data_ptr->address == 0x87654321, "spsecappdata: address");
    CHECK(spsec_app_data_ptr->secure_data_len == 24, "spsecappdata: secure_data_len");
    CHECK(spsec_app_data_ptr->padding_size == 1, "spsecappdata: padding_size");
    CHECK(memcmp(spsec_app_data_ptr->secure_data_ptr, secure_data, 24) == 0, "spsecappdata: secure_data copied");
    CHECK(memcmp(spsec_app_data_ptr->timestamp, app_ts, TIMESTAMP_SIZE) == 0, "spsecappdata: timestamp");
    CHECK(memcmp(spsec_app_data_ptr->auth_tag_ptr, app_auth_tag, AUTH_TAG_SIZE) == 0, "spsecappdata: auth_tag copied");

    /* Verify secure_data was copied, not aliased */
    secure_data[0] = 200;
    CHECK(spsec_app_data_ptr->secure_data_ptr[0] != 200, "spsecappdata: secure_data is copy, not alias");

    spsecappdata_free(spsec_app_data_ptr);
  }

  /* Test spsecheartbeat_new/_free */
  SPsecHeartbeatMessage *hb_msg_ptr = spsecheartbeat_new(99, 0x55);
  CHECK(hb_msg_ptr != NULL, "spsecheartbeat_new allocates memory");
  if (hb_msg_ptr) {
    CHECK(hb_msg_ptr->participant_id == 99, "spsecheartbeat: participant_id");
    CHECK(hb_msg_ptr->status == 0x55, "spsecheartbeat: status");
    CHECK(hb_msg_ptr->app_data_ptr != NULL, "spsecheartbeat: app_data_ptr non-NULL (constructed internally)");
    CHECK(hb_msg_ptr->spsec_app_data_ptr == NULL, "spsecheartbeat: spsec_app_data_ptr starts NULL");
    spsecheartbeat_free(hb_msg_ptr);
  }

  /* Test spsecsynctimebroadcast_new/_free + set_spsecsynctimebroadcast_timestamp */
  SPsecSyncTimeBroadcastMessage *sync_msg_ptr = spsecsynctimebroadcast_new(0x1122);
  CHECK(sync_msg_ptr != NULL, "spsecsynctimebroadcast_new allocates memory");
  if (sync_msg_ptr) {
    CHECK(sync_msg_ptr->app_data_ptr == NULL, "spsecsynctimebroadcast: app_data_ptr starts NULL");
    CHECK(sync_msg_ptr->spsec_app_data_ptr == NULL, "spsecsynctimebroadcast: spsec_app_data_ptr starts NULL");
    CHECK(sync_msg_ptr->cor[0] == 0x22, "spsecsynctimebroadcast: cor[0] (low byte)");
    CHECK(sync_msg_ptr->cor[1] == 0x11, "spsecsynctimebroadcast: cor[1] (high byte)");

    /* Set timestamp - this should make app_data_ptr non-NULL */
    uint8_t sync_ts[TIMESTAMP_SIZE];
    for (int i = 0; i < TIMESTAMP_SIZE; i++) {
      sync_ts[i] = (uint8_t)(i + 100);
    }
    set_spsecsynctimebroadcast_timestamp(sync_msg_ptr, sync_ts);
    CHECK(sync_msg_ptr->app_data_ptr != NULL, "spsecsynctimebroadcast: app_data_ptr becomes non-NULL after set_timestamp");
    CHECK(memcmp(sync_msg_ptr->timestamp, sync_ts, TIMESTAMP_SIZE) == 0, "spsecsynctimebroadcast: timestamp set");

    spsecsynctimebroadcast_free(sync_msg_ptr);
  }

  /* Test spsecinternalevent_new/_free */
  SPsecInternalEventMessage *evt_msg_ptr = spsecinternalevent_new(0x42, 0xDEADBEEF);
  CHECK(evt_msg_ptr != NULL, "spsecinternalevent_new allocates memory");
  if (evt_msg_ptr) {
    CHECK(evt_msg_ptr->reg == 0x42, "spsecinternalevent: reg");
    CHECK(evt_msg_ptr->data == 0xDEADBEEF, "spsecinternalevent: data");
    spsecinternalevent_free(evt_msg_ptr);
  }
}

int main(void) {
  configure_logging("CRITICAL");

  test_handshake();
  test_register();
  test_session();

  if (g_failures) {
    fprintf(stderr, "\n%d messages check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All messages checks passed.\n");
  return 0;
}
