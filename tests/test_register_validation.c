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
 * @file test_register_validation.c
 * @brief Unit tests for register validation functions
 *        (register_is_key_set, register_validate_key_installation_sequence,
 *         register_check_access).
 */

#include "spsec_common.h"
#include "register_validation.h"
#include "keys.h"
#include "messages.h"
#include "spsec_registers.h"
#include "spsec_errors.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static int g_failures = 0;
#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s\n", msg);                                    \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

// Zero-init a Participant for register_validation tests - only comm_keys
// and session.auth_tag_data_ptr are touched.
static void init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
}

/* ============================================================
 * Test register_is_key_set
 * ============================================================ */

static void test_register_is_key_set(void) {
  Participant p;
  init_test_participant(&p);
  uint8_t dummy_key[KEY_LEN];
  memset(dummy_key, 0x42, KEY_LEN);

  /* Case 1: NULL slot -> false */
  CHECK(register_is_key_set(&p, 1) == false,
        "register_is_key_set: NULL slot returns false");

  /* Case 2: non-NULL slot, key_id = SPSEC_KEY_ID_INVALID (0x00000000) -> false */
  SPsecKey *k_invalid_ptr = spseckey_new(SPSEC_KEY_ID_INVALID, dummy_key);
  CHECK(k_invalid_ptr != NULL, "spseckey_new with SPSEC_KEY_ID_INVALID");
  if (k_invalid_ptr) {
    p.comm_keys.spsec_keys[1] = k_invalid_ptr;
    CHECK(register_is_key_set(&p, 1) == false,
          "register_is_key_set: key_id=SPSEC_KEY_ID_INVALID returns false");
    spseckey_free(k_invalid_ptr);
    p.comm_keys.spsec_keys[1] = NULL; /* UAF prevention */
  }

  /* Case 3: non-NULL slot, key_id = SPSEC_KEY_ID_RESERVED (0xFFFFFFFF) -> false */
  SPsecKey *k_reserved_ptr = spseckey_new((uint32_t)SPSEC_KEY_ID_RESERVED, dummy_key);
  CHECK(k_reserved_ptr != NULL, "spseckey_new with SPSEC_KEY_ID_RESERVED");
  if (k_reserved_ptr) {
    p.comm_keys.spsec_keys[1] = k_reserved_ptr;
    CHECK(register_is_key_set(&p, 1) == false,
          "register_is_key_set: key_id=SPSEC_KEY_ID_RESERVED returns false");
    spseckey_free(k_reserved_ptr);
    p.comm_keys.spsec_keys[1] = NULL; /* UAF prevention */
  }

  /* Case 4: non-NULL slot, key_id = 0x12345678 -> true */
  SPsecKey *k_valid_ptr = spseckey_new(0x12345678u, dummy_key);
  CHECK(k_valid_ptr != NULL, "spseckey_new with valid key_id");
  if (k_valid_ptr) {
    p.comm_keys.spsec_keys[1] = k_valid_ptr;
    CHECK(register_is_key_set(&p, 1) == true,
          "register_is_key_set: key_id=0x12345678 returns true");
    spseckey_free(k_valid_ptr);
    p.comm_keys.spsec_keys[1] = NULL; /* UAF prevention */
  }
}

/* ============================================================
 * Test register_validate_key_installation_sequence
 * ============================================================ */

static void test_register_validate_key_installation_sequence(void) {
  Participant p;
  init_test_participant(&p);
  uint8_t dummy_key[KEY_LEN];
  memset(dummy_key, 0x55, KEY_LEN);

  /* Case: reg=0x23 (SEED_KEY) -> always SPSEC_SUCCESS immediately */
  CHECK(register_validate_key_installation_sequence(&p, 0x23) == SPSEC_SUCCESS,
        "SEED_KEY (0x23): always returns SPSEC_SUCCESS");

  /* Case: reg=0x21 (PROVISIONING_KEY), key not set -> SPSEC_SUCCESS */
  CHECK(register_validate_key_installation_sequence(&p, 0x21) == SPSEC_SUCCESS,
        "PROVISIONING_KEY (0x21): not set -> SPSEC_SUCCESS");

  /* Case: reg=0x21, key already set -> SPSEC_ERROR_KEY_ALREADY_SET */
  {
    SPsecKey *k_ptr = spseckey_new(0x11111111u, dummy_key);
    CHECK(k_ptr != NULL, "spseckey_new for PROVISIONING_KEY already-set test");
    if (k_ptr) {
      p.comm_keys.spsec_keys[1] = k_ptr;
      CHECK(register_validate_key_installation_sequence(&p, 0x21) == SPSEC_ERROR_KEY_ALREADY_SET,
            "PROVISIONING_KEY (0x21): already set -> SPSEC_ERROR_KEY_ALREADY_SET");
      spseckey_free(k_ptr);
      p.comm_keys.spsec_keys[1] = NULL;
    }
  }

  /* Case: reg=0x22 (INTEGRATOR_KEY), not set -> SPSEC_SUCCESS */
  CHECK(register_validate_key_installation_sequence(&p, 0x22) == SPSEC_SUCCESS,
        "INTEGRATOR_KEY (0x22): not set -> SPSEC_SUCCESS");

  /* Case: reg=0x22, already set -> SPSEC_ERROR_KEY_ALREADY_SET */
  {
    SPsecKey *k_ptr = spseckey_new(0x22222222u, dummy_key);
    CHECK(k_ptr != NULL, "spseckey_new for INTEGRATOR_KEY already-set test");
    if (k_ptr) {
      p.comm_keys.spsec_keys[2] = k_ptr;
      CHECK(register_validate_key_installation_sequence(&p, 0x22) == SPSEC_ERROR_KEY_ALREADY_SET,
            "INTEGRATOR_KEY (0x22): already set -> SPSEC_ERROR_KEY_ALREADY_SET");
      spseckey_free(k_ptr);
      p.comm_keys.spsec_keys[2] = NULL;
    }
  }

  /* Case: reg=0x99 (unmapped) -> SPSEC_SUCCESS */
  CHECK(register_validate_key_installation_sequence(&p, 0x99) == SPSEC_SUCCESS,
        "Unmapped register (0x99): returns SPSEC_SUCCESS");

  /* Case: reg=0x21, slot exists with key_id=SPSEC_KEY_ID_INVALID
   * (non-NULL, so "should be erased" warning logs) -> SPSEC_SUCCESS
   * The warning does NOT change the return value. */
  {
    SPsecKey *k_ptr = spseckey_new(SPSEC_KEY_ID_INVALID, dummy_key);
    CHECK(k_ptr != NULL, "spseckey_new with SPSEC_KEY_ID_INVALID for warning test");
    if (k_ptr) {
      p.comm_keys.spsec_keys[1] = k_ptr;
      CHECK(register_validate_key_installation_sequence(&p, 0x21) == SPSEC_SUCCESS,
            "PROVISIONING_KEY with key_id=INVALID: returns SPSEC_SUCCESS (warning logged)");
      spseckey_free(k_ptr);
      p.comm_keys.spsec_keys[1] = NULL;
    }
  }
}

/* ============================================================
 * Test register_check_access
 * ============================================================ */

static void test_register_check_access(void) {
  Participant p;
  init_test_participant(&p);

  /* Allocate ONE fixture at main start */
  ConfigurationSessionAuthTagData *fixture_ptr = authtagparticipantdata_new();
  CHECK(fixture_ptr != NULL, "authtagparticipantdata_new allocates fixture");
  if (!fixture_ptr) return;

  uint8_t dummy_key[KEY_LEN];
  memset(dummy_key, 0xAA, KEY_LEN);

  /* Helper to set p.session.auth_tag_data_ptr and run a check */
#define RUN_CHECK(reg, is_write, selector, expected, msg)                        \
  do {                                                                           \
    if (selector != 0xFF) {                                                      \
      fixture_ptr->key_selector[0] = selector;                                       \
      p.session.auth_tag_data_ptr = fixture_ptr;                                         \
    } else {                                                                     \
      p.session.auth_tag_data_ptr = NULL;                                            \
    }                                                                            \
    CHECK(register_check_access(&p, reg, is_write) == expected, msg);            \
  } while (0)

  /* -----------------------------------------------------------
   * READ PATH (is_write=false)
   * ----------------------------------------------------------- */

  /* Read-only registers (0x20-0x2F range): must be SPSEC_ERROR_REGISTER_WRITE_ONLY */
  RUN_CHECK(0x20, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ 0x20 (in 0x20-0x2F range): SPSEC_ERROR_REGISTER_WRITE_ONLY");
  RUN_CHECK(0x2F, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ 0x2F (in 0x20-0x2F range): SPSEC_ERROR_REGISTER_WRITE_ONLY");
  /* 0x1F sits below the key range but is not in the Zero Key discovery
   * allow-list, so an unauthenticated session may not read it. */
  RUN_CHECK(0x1F, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "READ 0x1F (below 0x20, not in Zero Key allow-list): DENIED");
  /* Pre-shared salts 30h-3Fh: SPsec302 §2.3.2 gives each salt the "same
   * access type" as its key, and keys are never readable. */
  RUN_CHECK(0x30, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ 0x30 (salt range 30h-3Fh): SPSEC_ERROR_REGISTER_WRITE_ONLY");
  RUN_CHECK(0x3F, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ 0x3F (salt range upper bound): SPSEC_ERROR_REGISTER_WRITE_ONLY");

  /* Write-only config registers (reads rejected) */
  RUN_CHECK(SPSEC_REG_CAN_FD_BIT_RATE, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ CAN_FD_BIT_RATE (0x7B): SPSEC_ERROR_REGISTER_WRITE_ONLY");
  RUN_CHECK(SPSEC_REG_MANUFACTURER_RESET, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ MANUFACTURER_RESET (0x7F): SPSEC_ERROR_REGISTER_WRITE_ONLY");
  RUN_CHECK(SPSEC_REG_CODE_UPDATE_FILE, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ CODE_UPDATE_FILE (0x92): SPSEC_ERROR_REGISTER_WRITE_ONLY");

  // Zero Key read allow-list (discovery set): Zero Key sessions are
  // unauthenticated (SPsec201 §2.4), so reads are restricted to key IDs
  // plus initial Provisioning writes - enough to discover a node.
  RUN_CHECK(SPSEC_REG_STATUS, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ STATUS (0x50) with Zero Key: allowed");
  RUN_CHECK(SPSEC_REG_LAST_SECURITY_EVENT, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ LAST_SECURITY_EVENT (0x51) with Zero Key: allowed");
  RUN_CHECK(SPSEC_REG_CORE_VERSION_INFO, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ CORE_VERSION_INFO (0x58) with Zero Key: allowed");
  RUN_CHECK(SPSEC_REG_MAPPING_VERSION_INFO, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ MAPPING_VERSION_INFO (0x59) with Zero Key: allowed");
  RUN_CHECK(SPSEC_REG_DEVICE_IDENTIFICATION, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ DEVICE_IDENTIFICATION (0x81) with Zero Key: allowed");
  RUN_CHECK(SPSEC_REG_MCU_SERIAL_NUMBER, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ MCU_SERIAL_NUMBER (0x82) with Zero Key: allowed");
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_ID, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ PROVISIONING_KEY_ID (0x41) with Zero Key: allowed (SPsec201 §2.4)");
  RUN_CHECK(SPSEC_REG_INTEGRATOR_KEY_ID, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ INTEGRATOR_KEY_ID (0x42) with Zero Key: allowed");
  RUN_CHECK(SPSEC_REG_SEED_KEY_ID, false, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "READ SEED_KEY_ID (0x43) with Zero Key: allowed");

  /* Salts are never readable, by any selector - regression pin for the
   * deviation this test file previously documented as "current behavior". */
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_SALT, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ PROVISIONING_KEY_SALT (0x31) with Zero Key: WRITE_ONLY");
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_SALT, false, KEY_SELECTOR_INTEGRATOR, SPSEC_ERROR_REGISTER_WRITE_ONLY,
            "READ PROVISIONING_KEY_SALT (0x31) with Integrator Key: WRITE_ONLY");

  /* Registers outside the allow-list are readable with a real key, denied
   * with the Zero Key. 0x63 (sync role activation) is a config register. */
  RUN_CHECK(SPSEC_REG_SYNC_ROLE_ACTIVATION, false, KEY_SELECTOR_INTEGRATOR, SPSEC_SUCCESS,
            "READ SYNC_ROLE_ACTIVATION (0x63) with Integrator Key: allowed");
  RUN_CHECK(SPSEC_REG_SYNC_ROLE_ACTIVATION, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "READ SYNC_ROLE_ACTIVATION (0x63) with Zero Key: DENIED");

  /* -----------------------------------------------------------
   * WRITE PATH (is_write=true) - Selector-dependent gate tests
   * ----------------------------------------------------------- */

  /* PROVISIONING_KEY (0x21): requires KEY_SELECTOR_ZERO */
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY, true, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "WRITE PROVISIONING_KEY (0x21) with KEY_SELECTOR_ZERO: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY, true, KEY_SELECTOR_PROVISIONING, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE PROVISIONING_KEY (0x21) with KEY_SELECTOR_PROVISIONING: DENIED");
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY, true, 0, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE PROVISIONING_KEY (0x21) with selector=0 (explicitly != ZERO): DENIED");

  /* INTEGRATOR_KEY (0x22): requires KEY_SELECTOR_PROVISIONING */
  RUN_CHECK(SPSEC_REG_INTEGRATOR_KEY, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE INTEGRATOR_KEY (0x22) with KEY_SELECTOR_PROVISIONING: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_INTEGRATOR_KEY, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE INTEGRATOR_KEY (0x22) with KEY_SELECTOR_ZERO: DENIED");

  /* SEED_KEY (0x23): requires KEY_SELECTOR_PROVISIONING or INTEGRATOR */
  RUN_CHECK(SPSEC_REG_SEED_KEY, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE SEED_KEY (0x23) with KEY_SELECTOR_PROVISIONING: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_SEED_KEY, true, KEY_SELECTOR_INTEGRATOR, SPSEC_SUCCESS,
            "WRITE SEED_KEY (0x23) with KEY_SELECTOR_INTEGRATOR: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_SEED_KEY, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE SEED_KEY (0x23) with KEY_SELECTOR_ZERO: DENIED");

  /* -----------------------------------------------------------
   * Key-salt registers (same selector rules + offset adjustment)
   * ----------------------------------------------------------- */

  /* PROVISIONING_KEY_SALT (0x31): same as PROVISIONING_KEY, delegates to sequence check with reg-0x10=0x21 */
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_SALT, true, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "WRITE PROVISIONING_KEY_SALT (0x31) with KEY_SELECTOR_ZERO: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_SALT, true, KEY_SELECTOR_PROVISIONING, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE PROVISIONING_KEY_SALT (0x31) with KEY_SELECTOR_PROVISIONING: DENIED");

  /* INTEGRATOR_KEY_SALT (0x32): same as INTEGRATOR_KEY */
  RUN_CHECK(SPSEC_REG_INTEGRATOR_KEY_SALT, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE INTEGRATOR_KEY_SALT (0x32) with KEY_SELECTOR_PROVISIONING: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_INTEGRATOR_KEY_SALT, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE INTEGRATOR_KEY_SALT (0x32) with KEY_SELECTOR_ZERO: DENIED");

  /* SEED_KEY_SALT (0x33): same as SEED_KEY */
  RUN_CHECK(SPSEC_REG_SEED_KEY_SALT, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE SEED_KEY_SALT (0x33) with KEY_SELECTOR_PROVISIONING: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_SEED_KEY_SALT, true, KEY_SELECTOR_INTEGRATOR, SPSEC_SUCCESS,
            "WRITE SEED_KEY_SALT (0x33) with KEY_SELECTOR_INTEGRATOR: SPSEC_SUCCESS");

  /* -----------------------------------------------------------
   * Key-ID registers (no installation-sequence check, selector gates only)
   * ----------------------------------------------------------- */

  /* PROVISIONING_KEY_ID (0x41): requires KEY_SELECTOR_ZERO */
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_ID, true, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
            "WRITE PROVISIONING_KEY_ID (0x41) with KEY_SELECTOR_ZERO: SPSEC_SUCCESS");

  /* INTEGRATOR_KEY_ID (0x42): requires KEY_SELECTOR_PROVISIONING */
  RUN_CHECK(SPSEC_REG_INTEGRATOR_KEY_ID, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE INTEGRATOR_KEY_ID (0x42) with KEY_SELECTOR_PROVISIONING: SPSEC_SUCCESS");

  /* SEED_KEY_ID (0x43): requires KEY_SELECTOR_PROVISIONING or INTEGRATOR */
  RUN_CHECK(SPSEC_REG_SEED_KEY_ID, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE SEED_KEY_ID (0x43) with KEY_SELECTOR_PROVISIONING: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_SEED_KEY_ID, true, KEY_SELECTOR_INTEGRATOR, SPSEC_SUCCESS,
            "WRITE SEED_KEY_ID (0x43) with KEY_SELECTOR_INTEGRATOR: SPSEC_SUCCESS");

  /* -----------------------------------------------------------
   * Read-only registers (always reject writes)
   * ----------------------------------------------------------- */
  const uint8_t read_only_regs[] = {
    SPSEC_REG_STATUS,
    SPSEC_REG_LAST_SECURITY_EVENT,
    SPSEC_REG_CORE_VERSION_INFO,
    SPSEC_REG_MAPPING_VERSION_INFO,
    SPSEC_REG_DEVICE_IDENTIFICATION,
    SPSEC_REG_MCU_SERIAL_NUMBER,
    SPSEC_REG_CODE_UPDATE_CAPABILITIES,
    SPSEC_REG_PUBLIC_AUTH_KEY
  };
  for (size_t i = 0; i < sizeof(read_only_regs); i++) {
    char msg[128];
    snprintf(msg, sizeof(msg), "WRITE read-only 0x%02x with ZERO: SPSEC_ERROR_REGISTER_READ_ONLY",
             read_only_regs[i]);
    RUN_CHECK(read_only_regs[i], true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_READ_ONLY, msg);
    snprintf(msg, sizeof(msg), "WRITE read-only 0x%02x with PROVISIONING: SPSEC_ERROR_REGISTER_READ_ONLY",
             read_only_regs[i]);
    RUN_CHECK(read_only_regs[i], true, KEY_SELECTOR_PROVISIONING, SPSEC_ERROR_REGISTER_READ_ONLY, msg);
  }

  /* -----------------------------------------------------------
   * Write-only config registers (allowed from any non-ZERO selector)
   * ----------------------------------------------------------- */

  /* CODE_UPDATE_FILE (0x92) */
  RUN_CHECK(SPSEC_REG_CODE_UPDATE_FILE, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE CODE_UPDATE_FILE (0x92) with ZERO: DENIED");
  RUN_CHECK(SPSEC_REG_CODE_UPDATE_FILE, true, KEY_SELECTOR_SESSION, SPSEC_SUCCESS,
            "WRITE CODE_UPDATE_FILE (0x92) with SESSION: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_CODE_UPDATE_FILE, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE CODE_UPDATE_FILE (0x92) with PROVISIONING: SPSEC_SUCCESS");

  /* CAN_FD_BIT_RATE (0x7B) */
  RUN_CHECK(SPSEC_REG_CAN_FD_BIT_RATE, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE CAN_FD_BIT_RATE (0x7B) with ZERO: DENIED");
  RUN_CHECK(SPSEC_REG_CAN_FD_BIT_RATE, true, KEY_SELECTOR_SESSION, SPSEC_SUCCESS,
            "WRITE CAN_FD_BIT_RATE (0x7B) with SESSION: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_CAN_FD_BIT_RATE, true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS,
            "WRITE CAN_FD_BIT_RATE (0x7B) with PROVISIONING: SPSEC_SUCCESS");

  /* -----------------------------------------------------------
   * MANUFACTURER_RESET (0x7F): requires INTEGRATOR
   * ----------------------------------------------------------- */
  RUN_CHECK(SPSEC_REG_MANUFACTURER_RESET, true, KEY_SELECTOR_INTEGRATOR, SPSEC_SUCCESS,
            "WRITE MANUFACTURER_RESET (0x7F) with INTEGRATOR: SPSEC_SUCCESS");
  RUN_CHECK(SPSEC_REG_MANUFACTURER_RESET, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE MANUFACTURER_RESET (0x7F) with ZERO: DENIED");
  RUN_CHECK(SPSEC_REG_MANUFACTURER_RESET, true, KEY_SELECTOR_PROVISIONING, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE MANUFACTURER_RESET (0x7F) with PROVISIONING: DENIED");

  /* -----------------------------------------------------------
   * Configuration registers (rejected only from KEY_SELECTOR_ZERO)
   * ----------------------------------------------------------- */
  const uint8_t config_regs[] = {
    SPSEC_REG_PARTICIPANT_ID,
    SPSEC_REG_SECURE_HEARTBEAT_TIMING,
    SPSEC_REG_SECURE_HEARTBEAT_MONITOR,
    SPSEC_REG_SYNC_ROLE_ACTIVATION
  };
  for (size_t i = 0; i < sizeof(config_regs); i++) {
    char msg[128];
    snprintf(msg, sizeof(msg), "WRITE config 0x%02x with ZERO: DENIED", config_regs[i]);
    RUN_CHECK(config_regs[i], true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED, msg);
    snprintf(msg, sizeof(msg), "WRITE config 0x%02x with PROVISIONING: SPSEC_SUCCESS", config_regs[i]);
    RUN_CHECK(config_regs[i], true, KEY_SELECTOR_PROVISIONING, SPSEC_SUCCESS, msg);
    snprintf(msg, sizeof(msg), "WRITE config 0x%02x with SESSION: SPSEC_SUCCESS", config_regs[i]);
    RUN_CHECK(config_regs[i], true, KEY_SELECTOR_SESSION, SPSEC_SUCCESS, msg);
  }

  /* -----------------------------------------------------------
   * NULL auth_tag_data_ptr (default selector = KEY_SELECTOR_ZERO)
   * ----------------------------------------------------------- */
  /* PROVISIONING_KEY write -> delegates to sequence -> SPSEC_SUCCESS
   * (because NULL is treated as KEY_SELECTOR_ZERO) */
  RUN_CHECK(SPSEC_REG_PROVISIONING_KEY, true, 0xFF, SPSEC_SUCCESS,
            "WRITE PROVISIONING_KEY with NULL auth_tag_data_ptr: SPSEC_SUCCESS (treated as ZERO)");

  /* PARTICIPANT_ID write -> SPSEC_ERROR_REGISTER_ACCESS_DENIED
   * (because NULL is treated as KEY_SELECTOR_ZERO) */
  RUN_CHECK(SPSEC_REG_PARTICIPANT_ID, true, 0xFF, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "WRITE PARTICIPANT_ID with NULL auth_tag_data_ptr: DENIED (treated as ZERO)");

  /* -----------------------------------------------------------
   * Invalid register (not in any case)
   * ----------------------------------------------------------- */
  RUN_CHECK(0xEE, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_INVALID,
            "WRITE invalid register 0xEE: SPSEC_ERROR_REGISTER_INVALID");
  RUN_CHECK(0xEE, false, KEY_SELECTOR_ZERO, SPSEC_ERROR_REGISTER_ACCESS_DENIED,
            "READ 0xEE with Zero Key: DENIED (not in the discovery allow-list)");
  RUN_CHECK(0xEE, false, KEY_SELECTOR_INTEGRATOR, SPSEC_SUCCESS,
            "READ 0xEE with Integrator Key: allowed (manufacturer-specific range)");

  // Provisioning Key ID (41h) is write-once like the key itself - without
  // this, an unauthenticated Zero Key session could rewrite the ID of an
  // already-provisioned device (register_is_key_set() keys off it).
  {
    /* Key ID still erased (FFh) - mid-provisioning, the write must pass. */
    SPsecKey *k_ptr = spseckey_new((uint32_t)SPSEC_KEY_ID_RESERVED, dummy_key);
    CHECK(k_ptr != NULL, "spseckey_new with erased key ID for write-once test");
    if (k_ptr) {
      p.comm_keys.spsec_keys[1] = k_ptr;
      RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_ID, true, KEY_SELECTOR_ZERO, SPSEC_SUCCESS,
                "WRITE PROVISIONING_KEY_ID (0x41), key ID still erased: allowed");
      spseckey_free(k_ptr);
      p.comm_keys.spsec_keys[1] = NULL;
    }
  }
  {
    /* Provisioning key installed - a rewrite must now be refused. */
    SPsecKey *k_ptr = spseckey_new(0x11111111u, dummy_key);
    CHECK(k_ptr != NULL, "spseckey_new with valid key ID for write-once test");
    if (k_ptr) {
      p.comm_keys.spsec_keys[1] = k_ptr;
      RUN_CHECK(SPSEC_REG_PROVISIONING_KEY_ID, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_KEY_ALREADY_SET,
                "WRITE PROVISIONING_KEY_ID (0x41) once provisioned: KEY_ALREADY_SET");
      RUN_CHECK(SPSEC_REG_PROVISIONING_KEY, true, KEY_SELECTOR_ZERO, SPSEC_ERROR_KEY_ALREADY_SET,
                "WRITE PROVISIONING_KEY (0x21) once provisioned: KEY_ALREADY_SET");
      spseckey_free(k_ptr);
      p.comm_keys.spsec_keys[1] = NULL;
    }
  }

  /* Free fixture ONCE at end */
  authtagparticipantdata_free(fixture_ptr);
  fixture_ptr = NULL;
  p.session.auth_tag_data_ptr = NULL;
}

/* ============================================================
 * Main
 * ============================================================ */

int main(void) {
  configure_logging("CRITICAL");

  test_register_is_key_set();
  test_register_validate_key_installation_sequence();
  test_register_check_access();

  if (g_failures) {
    fprintf(stderr, "\n%d register_validation check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All register_validation checks passed.\n");
  return 0;
}
