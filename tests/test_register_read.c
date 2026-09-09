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
 * @file test_register_read.c
 * @brief Unit tests for SPsec register read operations (0x41–0x91).
 */

#include "keys.h"
#include "participant.h"
#include "register_operations.h"
#include "register_read.h"
#include "register_validation.h"
#include "register_write.h"
#include "spsec_common.h"
#include "spsec_registers.h"

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

#define TEST_PID 77

static void setup_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  p_ptr->participant_id = TEST_PID;
  p_ptr->state_info.state = SPSEC_STATE_CONFIGURATION;
  p_ptr->state_info.status = 0x04; /* CONFIGURATION */
  p_ptr->state_info.last_event = 0x1234;

  timer_init(&p_ptr->timer, 8);
  communication_keys_init(&p_ptr->comm_keys);

  p_ptr->session.auth_tag_data_ptr = authtagparticipantdata_new();
  if (p_ptr->session.auth_tag_data_ptr) {
    p_ptr->session.auth_tag_data_ptr->key_selector[0] = KEY_SELECTOR_PROVISIONING;
  }

  uint8_t zero_key[KEY_LEN] = {0};
  p_ptr->comm_keys.spsec_keys[1] = spseckey_new(0x11223344, zero_key);
  p_ptr->comm_keys.spsec_keys[2] = spseckey_new(0x55667788, zero_key);
  p_ptr->comm_keys.spsec_keys[3] = spseckey_new(0x99AABBCC, zero_key);

  p_ptr->heartbeat.timing = SPSEC_HEARTBEAT_1S;
  p_ptr->heartbeat.monitor.participant_ids[0] = 10;
  p_ptr->heartbeat.monitor.participant_ids[1] = 20;
  p_ptr->heartbeat.monitor.participant_ids[2] = 30;
  p_ptr->heartbeat.monitor.participant_ids[3] = 40;

  strcpy(p_ptr->device_info.core_version_info, "0.34");
  strcpy(p_ptr->device_info.mapping_version_info, "302-1.40");
  strcpy(p_ptr->device_info.device_identification, "TestDevice/1.0");
  memset(p_ptr->device_info.mcu_serial_number, 0x55, 16);
  p_ptr->device_info.code_update_capabilities.raw = 0x01;
  p_ptr->timesync.is_role_authority = true;
}

static void teardown_test_participant(Participant *p_ptr) {
  if (p_ptr->session.auth_tag_data_ptr) {
    authtagparticipantdata_free(p_ptr->session.auth_tag_data_ptr);
    p_ptr->session.auth_tag_data_ptr = NULL;
  }
  crypto_handler_destroy(&p_ptr->crypto_handler);
  communication_keys_destroy(&p_ptr->comm_keys);
  timer_destroy(&p_ptr->timer);
}

static void test_read_segment_data(void) {
  printf("Testing register_prepare_read_segment_data for all registers...\n");
  Participant p;
  setup_test_participant(&p);

  uint8_t *data_ptr = NULL;
  uint32_t len = 0;

  /* 1. Status Register (50h) */
  p.state_info.prepared_read_register = SPSEC_REG_STATUS;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 50h succeeds");
  CHECK(len == 1 && data_ptr[0] == 0x04, "50h returns 1 byte status");
  free(data_ptr); data_ptr = NULL;

  /* 2. Last Security Event (51h) */
  p.state_info.prepared_read_register = SPSEC_REG_LAST_SECURITY_EVENT;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 51h succeeds");
  CHECK(len == 2 && data_ptr[0] == 0x34 && data_ptr[1] == 0x12, "51h returns 2 bytes LE event code");
  free(data_ptr); data_ptr = NULL;

  /* 3. Provisioning Key ID (41h) */
  p.state_info.prepared_read_register = SPSEC_REG_PROVISIONING_KEY_ID;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 41h succeeds");
  uint32_t read_id = (uint32_t)data_ptr[0] | ((uint32_t)data_ptr[1] << 8) | ((uint32_t)data_ptr[2] << 16) | ((uint32_t)data_ptr[3] << 24);
  CHECK(len == 4 && read_id == 0x11223344, "41h returns correct Prov Key ID");
  free(data_ptr); data_ptr = NULL;

  /* 4. Integrator Key ID (42h) */
  p.state_info.prepared_read_register = SPSEC_REG_INTEGRATOR_KEY_ID;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 42h succeeds");
  read_id = (uint32_t)data_ptr[0] | ((uint32_t)data_ptr[1] << 8) | ((uint32_t)data_ptr[2] << 16) | ((uint32_t)data_ptr[3] << 24);
  CHECK(len == 4 && read_id == 0x55667788, "42h returns correct Int Key ID");
  free(data_ptr); data_ptr = NULL;

  /* 5. Seed Key ID (43h) */
  p.state_info.prepared_read_register = SPSEC_REG_SEED_KEY_ID;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 43h succeeds");
  read_id = (uint32_t)data_ptr[0] | ((uint32_t)data_ptr[1] << 8) | ((uint32_t)data_ptr[2] << 16) | ((uint32_t)data_ptr[3] << 24);
  CHECK(len == 4 && read_id == 0x99AABBCC, "43h returns correct Seed Key ID");
  free(data_ptr); data_ptr = NULL;

  /* 6. Heartbeat Timing (61h) */
  p.state_info.prepared_read_register = SPSEC_REG_SECURE_HEARTBEAT_TIMING;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 61h succeeds");
  CHECK(len == 1 && data_ptr[0] == (uint8_t)SPSEC_HEARTBEAT_1S, "61h returns heartbeat timing");
  free(data_ptr); data_ptr = NULL;

  /* 7. Heartbeat Monitor (62h) */
  p.state_info.prepared_read_register = SPSEC_REG_SECURE_HEARTBEAT_MONITOR;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 62h succeeds");
  CHECK(len == 4 && data_ptr[0] == 10 && data_ptr[1] == 20 && data_ptr[2] == 30 && data_ptr[3] == 40,
        "62h returns 4 monitored PIDs");
  free(data_ptr); data_ptr = NULL;

  /* 8. Core Version Info (58h) */
  p.state_info.prepared_read_register = SPSEC_REG_CORE_VERSION_INFO;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 58h succeeds");
  CHECK(len == strlen("0.34") && memcmp(data_ptr, "0.34", len) == 0, "58h returns core version string");
  free(data_ptr); data_ptr = NULL;

  /* 9. Mapping Version Info (59h) */
  p.state_info.prepared_read_register = SPSEC_REG_MAPPING_VERSION_INFO;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 59h succeeds");
  CHECK(len == strlen("302-1.40") && memcmp(data_ptr, "302-1.40", len) == 0, "59h returns mapping version");
  free(data_ptr); data_ptr = NULL;

  /* 10. Device Identification (81h) */
  p.state_info.prepared_read_register = SPSEC_REG_DEVICE_IDENTIFICATION;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 81h succeeds");
  CHECK(len == strlen("TestDevice/1.0"), "81h returns device ID string");
  free(data_ptr); data_ptr = NULL;

  /* 11. MCU Serial Number (82h) */
  p.state_info.prepared_read_register = SPSEC_REG_MCU_SERIAL_NUMBER;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 82h succeeds");
  CHECK(len == 16, "82h returns 16 bytes serial");
  free(data_ptr); data_ptr = NULL;

  /* 12. Code Update Capabilities (90h) */
  p.state_info.prepared_read_register = SPSEC_REG_CODE_UPDATE_CAPABILITIES;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 90h succeeds");
  CHECK(len == 4 && data_ptr[0] == 0x01, "90h returns capabilities");
  free(data_ptr); data_ptr = NULL;

  /* 13. Public Auth Key (91h) */
  p.state_info.prepared_read_register = SPSEC_REG_PUBLIC_AUTH_KEY;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 91h succeeds");
  CHECK(len == KEY_LEN, "91h returns 32 bytes (all-zero when unprovisioned)");
  free(data_ptr); data_ptr = NULL;

  /* 14. Participant ID (60h) */
  p.state_info.prepared_read_register = SPSEC_REG_PARTICIPANT_ID;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 60h succeeds");
  CHECK(len == 1 && data_ptr[0] == TEST_PID, "60h returns participant ID");
  free(data_ptr); data_ptr = NULL;

  /* 15. Sync Role Activation (63h) */
  p.state_info.prepared_read_register = SPSEC_REG_SYNC_ROLE_ACTIVATION;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_SUCCESS, "read 63h succeeds");
  CHECK(len == 1 && data_ptr[0] == SPSEC_SYNC_ROLE_ON, "63h returns sync role ON");
  free(data_ptr); data_ptr = NULL;

  /* 16. Unknown register returns invalid */
  p.state_info.prepared_read_register = 0xAA;
  CHECK(register_prepare_read_segment_data(&p, &data_ptr, &len) == SPSEC_ERROR_REGISTER_INVALID,
        "unknown register returns SPSEC_ERROR_REGISTER_INVALID");

  teardown_test_participant(&p);
}

static void test_read_access_rules(void) {
  printf("Testing register_check_access for read permissions...\n");
  Participant p;
  setup_test_participant(&p);

  /* Write-only registers must reject read access */
  CHECK(register_check_access(&p, SPSEC_REG_CAN_FD_BIT_RATE, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "7Bh (CAN FD Bit Rate) is write-only, read rejected");
  CHECK(register_check_access(&p, SPSEC_REG_MANUFACTURER_RESET, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "7Fh (Manufacturer Reset) is write-only, read rejected");
  CHECK(register_check_access(&p, SPSEC_REG_CODE_UPDATE_FILE, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "92h (Code Update File) is write-only, read rejected");

  /* Keys and salts are write-only */
  CHECK(register_check_access(&p, SPSEC_REG_PROVISIONING_KEY, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "21h (Provisioning Key) is write-only");
  CHECK(register_check_access(&p, SPSEC_REG_INTEGRATOR_KEY, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "22h (Integrator Key) is write-only");
  CHECK(register_check_access(&p, SPSEC_REG_SEED_KEY, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "23h (Seed Key) is write-only");
  CHECK(register_check_access(&p, SPSEC_REG_PROVISIONING_KEY_SALT, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "31h (Provisioning Salt) is write-only");
  CHECK(register_check_access(&p, SPSEC_REG_INTEGRATOR_KEY_SALT, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "32h (Integrator Salt) is write-only");
  CHECK(register_check_access(&p, SPSEC_REG_SEED_KEY_SALT, false) == SPSEC_ERROR_REGISTER_WRITE_ONLY,
        "33h (Seed Salt) is write-only");

  /* Readable registers must accept read access under Provisioning key */
  CHECK(register_check_access(&p, SPSEC_REG_STATUS, false) == SPSEC_SUCCESS, "50h readable");
  CHECK(register_check_access(&p, SPSEC_REG_LAST_SECURITY_EVENT, false) == SPSEC_SUCCESS, "51h readable");
  CHECK(register_check_access(&p, SPSEC_REG_CORE_VERSION_INFO, false) == SPSEC_SUCCESS, "58h readable");
  CHECK(register_check_access(&p, SPSEC_REG_MAPPING_VERSION_INFO, false) == SPSEC_SUCCESS, "59h readable");
  CHECK(register_check_access(&p, SPSEC_REG_PARTICIPANT_ID, false) == SPSEC_SUCCESS, "60h readable under Prov");
  CHECK(register_check_access(&p, SPSEC_REG_SECURE_HEARTBEAT_TIMING, false) == SPSEC_SUCCESS, "61h readable under Prov");
  CHECK(register_check_access(&p, SPSEC_REG_SECURE_HEARTBEAT_MONITOR, false) == SPSEC_SUCCESS, "62h readable under Prov");
  CHECK(register_check_access(&p, SPSEC_REG_SYNC_ROLE_ACTIVATION, false) == SPSEC_SUCCESS, "63h readable under Prov");
  CHECK(register_check_access(&p, SPSEC_REG_DEVICE_IDENTIFICATION, false) == SPSEC_SUCCESS, "81h readable");
  CHECK(register_check_access(&p, SPSEC_REG_MCU_SERIAL_NUMBER, false) == SPSEC_SUCCESS, "82h readable");
  CHECK(register_check_access(&p, SPSEC_REG_CODE_UPDATE_CAPABILITIES, false) == SPSEC_SUCCESS, "90h readable under Prov");
  CHECK(register_check_access(&p, SPSEC_REG_PUBLIC_AUTH_KEY, false) == SPSEC_SUCCESS, "91h readable under Prov");

  /* Zero Key session restrictions: 60h-63h and 90h-91h must be DENIED */
  p.session.auth_tag_data_ptr->key_selector[0] = KEY_SELECTOR_ZERO;
  CHECK(register_check_access(&p, SPSEC_REG_STATUS, false) == SPSEC_SUCCESS, "50h readable under Zero");
  CHECK(register_check_access(&p, SPSEC_REG_DEVICE_IDENTIFICATION, false) == SPSEC_SUCCESS, "81h readable under Zero");
  CHECK(register_check_access(&p, SPSEC_REG_PARTICIPANT_ID, false) == SPSEC_ERROR_REGISTER_ACCESS_DENIED,
        "60h rejected under Zero");
  CHECK(register_check_access(&p, SPSEC_REG_SECURE_HEARTBEAT_TIMING, false) == SPSEC_ERROR_REGISTER_ACCESS_DENIED,
        "61h rejected under Zero");
  CHECK(register_check_access(&p, SPSEC_REG_SECURE_HEARTBEAT_MONITOR, false) == SPSEC_ERROR_REGISTER_ACCESS_DENIED,
        "62h rejected under Zero");
  CHECK(register_check_access(&p, SPSEC_REG_SYNC_ROLE_ACTIVATION, false) == SPSEC_ERROR_REGISTER_ACCESS_DENIED,
        "63h rejected under Zero");
  CHECK(register_check_access(&p, SPSEC_REG_CODE_UPDATE_CAPABILITIES, false) == SPSEC_ERROR_REGISTER_ACCESS_DENIED,
        "90h rejected under Zero");
  CHECK(register_check_access(&p, SPSEC_REG_PUBLIC_AUTH_KEY, false) == SPSEC_ERROR_REGISTER_ACCESS_DENIED,
        "91h rejected under Zero");

  teardown_test_participant(&p);
}

static void test_counter_rollback_on_bad_tag(void) {
  printf("Testing counter rollback on bad decrypt/auth tag...\n");
  Participant p;
  setup_test_participant(&p);
  p.session.cnt = 42;
  p.session.active = true;

  SPsecSalt test_salt;
  uint8_t salt_bytes[SALT_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
  spsecsalt_init(&test_salt, salt_bytes);
  p.session.auth_tag_data_ptr->spsec_salt_ptr = &test_salt;

  SPsecReadInitiateMessage read_init = {0};
  read_init.participant_id = TEST_PID;
  read_init.address = 0x12345678;
  memset(read_init.ciphertext, 0xAA, sizeof(read_init.ciphertext));
  memset(read_init.auth_tag, 0xBB, sizeof(read_init.auth_tag));

  uint8_t read_reg = 0;
  uint32_t real_len = 0;
  spsec_ret_t ret = register_process_read_initiate(&p, &read_init, &read_reg, &real_len);
  CHECK(ret != SPSEC_SUCCESS, "bad read initiate decrypt fails");
  CHECK(p.session.cnt == 42, "session.cnt rolled back after failed read initiate decrypt");
  CHECK(p.state_info.last_event == SPSEC_SESS_KEY_AUTH_FAILURE,
        "security event reported on failed read initiate");

  SPsecClientWriteSegmentRequest write_seg = {0};
  write_seg.participant_id = TEST_PID;
  write_seg.cnt = 42;
  write_seg.address = 0x12345678;
  uint8_t dummy_cipher[16] = {0xCC};
  uint8_t dummy_out[16] = {0};
  write_seg.ciphertext_ptr = dummy_cipher;
  write_seg.data_ptr = dummy_out;
  write_seg.data_len = 16;
  memset(write_seg.auth_tag, 0xDD, AUTH_TAG_SIZE);

  ret = register_check_write_segment(&p, &write_seg);
  CHECK(ret != SPSEC_SUCCESS, "bad write segment decrypt fails");
  CHECK(p.session.cnt == 42, "session.cnt rolled back after failed write segment decrypt");
  CHECK(p.state_info.last_event == SPSEC_SESS_KEY_AUTH_FAILURE,
        "security event reported on failed write segment");

  teardown_test_participant(&p);
}

int main(void) {
  test_read_segment_data();
  test_read_access_rules();
  test_counter_rollback_on_bad_tag();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d register_read check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All register_read checks passed.\n");
  return 0;
}
