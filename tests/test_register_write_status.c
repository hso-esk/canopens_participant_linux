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
 * @file test_register_write_status.c
 * @brief Unit tests for register_check_write_status() function.
 */

#include "spsec_common.h"
#include "register_write.h"
#include "spsec_mapping.h"
#include "spsec_registers.h"
#include "spsec_errors.h"
#include "keys.h"

#include <stdint.h>
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

// Zero-init a Participant - register_check_write_status touches only
// register_check_access and spsec_is_known_register.
static void init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
}

/* Test register_check_write_status */

static void test_register_check_write_status(void) {
  Participant p;
  init_test_participant(&p);

  /* Use sentinel value 0xAA to detect if prepared_write_register is modified */
  const uint8_t SENTINEL = 0xAA;
  p.state_info.prepared_write_register = SENTINEL;

  /* Case 1: Denied access leaves state unchanged */
  p.state_info.prepared_write_register = SENTINEL;
  {
    spsec_ret_t ret = register_check_write_status(&p, SPSEC_REG_PARTICIPANT_ID, 1);
    CHECK(ret == SPSEC_ERROR_REGISTER_ACCESS_DENIED,
          "Case 1: PARTICIPANT_ID with ZERO selector returns SPSEC_ERROR_REGISTER_ACCESS_DENIED");
    CHECK(p.state_info.prepared_write_register == SENTINEL,
          "Case 1: prepared_write_register unchanged on access failure");
  }

  /* Case 2: Unknown register (0xFF) is rejected */
  p.state_info.prepared_write_register = SENTINEL;
  {
    spsec_ret_t ret = register_check_write_status(&p, 0xFF, 1);
    CHECK(ret == SPSEC_ERROR_REGISTER_INVALID,
          "Case 2: unregistered reg 0xFF rejected via register_check_access's own default case");
    CHECK(p.state_info.prepared_write_register == SENTINEL,
          "Case 2: prepared_write_register unchanged on unregistered reg");
  }

  /* Case 3: Length mismatch is rejected */
  p.state_info.prepared_write_register = SENTINEL;
  {
    spsec_ret_t ret = register_check_write_status(&p, SPSEC_REG_INTEGRATOR_KEY, 99);
    CHECK(ret == SPSEC_ERROR_REGISTER_INVALID_LENGTH,
          "Case 3: INTEGRATOR_KEY with wrong len returns SPSEC_ERROR_REGISTER_INVALID_LENGTH");
    CHECK(p.state_info.prepared_write_register == SENTINEL,
          "Case 3: prepared_write_register unchanged on length mismatch");
  }

  /* Case 4: Valid register write sets prepared register */
  p.state_info.prepared_write_register = SENTINEL;
  {
    spsec_ret_t ret = register_check_write_status(&p, SPSEC_REG_INTEGRATOR_KEY, KEY_LEN);
    CHECK(ret == SPSEC_SUCCESS,
          "Case 4: INTEGRATOR_KEY with correct len returns SPSEC_SUCCESS");
    CHECK(p.state_info.prepared_write_register == SPSEC_REG_INTEGRATOR_KEY,
          "Case 4: prepared_write_register set to 0x22 on success");
  }
}

/* Main */

int main(void) {
  configure_logging("CRITICAL");

  test_register_check_write_status();

  if (g_failures) {
    fprintf(stderr, "\n%d register_write_status check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All register_write_status checks passed.\n");
  return 0;
}
