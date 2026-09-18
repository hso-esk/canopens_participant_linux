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

// Regression tests for config_init_defaults() and config_validate().
#include "config.h"
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

int main(void) {
  configure_logging("CRITICAL");

  /* 1. config_init_defaults(NULL) returns negative */
  CHECK(config_init_defaults(NULL) < 0, "config_init_defaults(NULL) returns negative");

  /* 2. config_init_defaults(&cfg) returns 0 AND config_validate(&cfg) returns 0 */
  ParticipantConfig cfg;
  CHECK(config_init_defaults(&cfg) == 0, "config_init_defaults(&cfg) returns 0");
  CHECK(config_validate(&cfg) == 0, "fresh defaulted config passes config_validate (invariant)");

  /* 3. config_validate(NULL) returns negative */
  CHECK(config_validate(NULL) < 0, "config_validate(NULL) returns negative");

  /* 4. F-07 regression: participant_id boundary (0 and 128 rejected, 1 and 127 accepted) */
  config_init_defaults(&cfg);
  cfg.participant_id = 0;
  CHECK(config_validate(&cfg) < 0, "participant_id=0 rejected");

  config_init_defaults(&cfg);
  cfg.participant_id = 128;
  CHECK(config_validate(&cfg) < 0, "participant_id=128 rejected");

  config_init_defaults(&cfg);
  cfg.participant_id = 1;
  CHECK(config_validate(&cfg) == 0, "participant_id=1 accepted");

  config_init_defaults(&cfg);
  cfg.participant_id = 127;
  CHECK(config_validate(&cfg) == 0, "participant_id=127 accepted");

  /* 5. secure_interface / insecure_interface NULL and empty-string rejection */
  config_init_defaults(&cfg);
  cfg.secure_interface_ptr = NULL;
  CHECK(config_validate(&cfg) < 0, "secure_interface=NULL rejected");

  config_init_defaults(&cfg);
  cfg.secure_interface_ptr = "";
  CHECK(config_validate(&cfg) < 0, "secure_interface=\"\" rejected");

  config_init_defaults(&cfg);
  cfg.insecure_interface_ptr = NULL;
  CHECK(config_validate(&cfg) < 0, "insecure_interface=NULL rejected");

  config_init_defaults(&cfg);
  cfg.insecure_interface_ptr = "";
  CHECK(config_validate(&cfg) < 0, "insecure_interface=\"\" rejected");

  /* 6. session_timeout_us and session_response_timeout_us zero rejection */
  config_init_defaults(&cfg);
  cfg.session_timeout_us = 0;
  CHECK(config_validate(&cfg) < 0, "session_timeout_us=0 rejected");

  config_init_defaults(&cfg);
  cfg.session_response_timeout_us = 0;
  CHECK(config_validate(&cfg) < 0, "session_response_timeout_us=0 rejected");

  if (g_failures) {
    fprintf(stderr, "\n%d config check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All config checks passed.\n");
  return 0;
}
