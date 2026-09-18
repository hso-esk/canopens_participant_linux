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

// Regression tests for register recognition and length validation.
#include "keys.h"
#include "spsec_common.h"
#include "spsec_mapping.h"
#include "spsec_registers.h"

#include <assert.h>
#include <stdio.h>

static int g_failures = 0;
#define CHECK(cond, msg)                                                     \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "  FAIL: %s\n", msg);                                  \
      g_failures++;                                                          \
    }                                                                        \
  } while (0)

/* Assert that `reg` is known and resolves to exactly `expected` bytes. */
static void check_known(uint8_t reg, uint32_t expected, const char *msg_ptr) {
  uint32_t len = 0xDEADBEEFu;
  bool known = spsec_is_known_register(reg, &len);
  CHECK(known, msg_ptr);
  if (known) {
    char buf[160];
    snprintf(buf, sizeof(buf), "%s (expected_len)", msg_ptr);
    CHECK(len == expected, buf);
  }
}

/* Assert that `reg` is NOT known. */
static void check_unknown(uint8_t reg, const char *msg_ptr) {
  uint32_t len = 0xDEADBEEFu;
  bool known = spsec_is_known_register(reg, &len);
  CHECK(!known, msg_ptr);
}

int main(void) {
  configure_logging("CRITICAL");

  /* --- Full mirror of the current specs[] table in spsec_mapping.h ---
   * Manually kept in sync with the table; that IS the point of this test.
   */
  check_known(SPSEC_REG_STATUS, 1, "STATUS (0x50)");
  check_known(SPSEC_REG_LAST_SECURITY_EVENT, 2, "LAST_SECURITY_EVENT (0x51)");
  check_known(SPSEC_REG_PROVISIONING_KEY, KEY_LEN, "PROVISIONING_KEY (0x21)");
  check_known(SPSEC_REG_INTEGRATOR_KEY, KEY_LEN, "INTEGRATOR_KEY (0x22)");
  check_known(SPSEC_REG_SEED_KEY, KEY_LEN, "SEED_KEY (0x23)");
  check_known(SPSEC_REG_PROVISIONING_KEY_SALT, SALT_LEN,
              "PROVISIONING_KEY_SALT (0x31)");
  check_known(SPSEC_REG_INTEGRATOR_KEY_SALT, SALT_LEN,
              "INTEGRATOR_KEY_SALT (0x32)");
  check_known(SPSEC_REG_SEED_KEY_SALT, SALT_LEN, "SEED_KEY_SALT (0x33)");
  check_known(SPSEC_REG_PROVISIONING_KEY_ID, 4, "PROVISIONING_KEY_ID (0x41)");
  check_known(SPSEC_REG_INTEGRATOR_KEY_ID, 4, "INTEGRATOR_KEY_ID (0x42)");
  check_known(SPSEC_REG_SEED_KEY_ID, 4, "SEED_KEY_ID (0x43)");
  check_known(SPSEC_REG_SECURE_HEARTBEAT_TIMING, 1,
              "SECURE_HEARTBEAT_TIMING (0x61)");
  check_known(SPSEC_REG_SECURE_HEARTBEAT_MONITOR, 4,
              "SECURE_HEARTBEAT_MONITOR (0x62)");
  check_known(SPSEC_REG_SYNC_ROLE_ACTIVATION, 1,
              "SYNC_ROLE_ACTIVATION (0x63)");
  check_known(SPSEC_REG_PARTICIPANT_ID, 1, "PARTICIPANT_ID (0x60)");
  check_known(SPSEC_REG_CAN_FD_BIT_RATE, 2, "CAN_FD_BIT_RATE (0x7B)");
  check_known(SPSEC_REG_MANUFACTURER_RESET, 4, "MANUFACTURER_RESET (0x7F)");
  check_known(SPSEC_REG_DEVICE_IDENTIFICATION, 0,
              "DEVICE_IDENTIFICATION (0x81) is intentionally variable-length");
  check_known(SPSEC_REG_MCU_SERIAL_NUMBER, 16, "MCU_SERIAL_NUMBER (0x82)");
  check_known(SPSEC_REG_CODE_UPDATE_CAPABILITIES, 4,
              "CODE_UPDATE_CAPABILITIES (0x90)");
  check_known(SPSEC_REG_PUBLIC_AUTH_KEY, KEY_LEN, "PUBLIC_AUTH_KEY (0x91)");
  check_known(SPSEC_REG_CODE_UPDATE_FILE, 4096, "CODE_UPDATE_FILE (0x92)");
  check_known(SPSEC_REG_CORE_VERSION_INFO, 0,
              "CORE_VERSION_INFO (0x58) is intentionally variable-length");
  check_known(SPSEC_REG_MAPPING_VERSION_INFO, 0,
              "MAPPING_VERSION_INFO (0x59) is intentionally variable-length");

  /* Manufacturer-specific range placeholders are not registered */
  check_unknown((uint8_t)SPSEC_REG_MANUFACTURER_SPECIFIC_START,
                "MANUFACTURER_SPECIFIC_START (0xD0) is not a real register");
  check_unknown((uint8_t)SPSEC_REG_MANUFACTURER_SPECIFIC_END,
                "MANUFACTURER_SPECIFIC_END (0xEF) is not a real register");

  /* --- Regression pin: F-08 (0x60-0x63 were entirely missing) --- */
  CHECK(SPSEC_REG_PARTICIPANT_ID == 0x60, "enum PARTICIPANT_ID is 0x60");
  CHECK(SPSEC_REG_SECURE_HEARTBEAT_TIMING == 0x61,
        "enum SECURE_HEARTBEAT_TIMING is 0x61");
  CHECK(SPSEC_REG_SECURE_HEARTBEAT_MONITOR == 0x62,
        "enum SECURE_HEARTBEAT_MONITOR is 0x62");
  CHECK(SPSEC_REG_SYNC_ROLE_ACTIVATION == 0x63,
        "enum SYNC_ROLE_ACTIVATION is 0x63");
  check_known(0x60, 1, "F-08 regression: 0x60 resolves to expected_len 1");
  check_known(0x61, 1, "F-08 regression: 0x61 resolves to expected_len 1");
  check_known(0x62, 4, "F-08 regression: 0x62 resolves to expected_len 4");
  check_known(0x63, 1, "F-08 regression: 0x63 resolves to expected_len 1");

  /* --- Regression pin: F-12 (0x92 wrongly had expected_len = 0) --- */
  CHECK(SPSEC_REG_CODE_UPDATE_FILE == 0x92,
        "enum CODE_UPDATE_FILE is 0x92");
  check_known(0x92, 4096,
              "F-12 regression: 0x92 resolves to expected_len 4096, not 0");

  /* --- Unknown register ID must be rejected --- */
  check_unknown(0xFF, "unassigned register 0xFF is not known");

  if (g_failures) {
    fprintf(stderr, "\n%d register dispatch check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All register dispatch checks passed.\n");
  return 0;
}
