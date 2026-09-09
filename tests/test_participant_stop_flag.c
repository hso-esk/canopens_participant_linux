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
 * @file test_participant_stop_flag.c
 * @brief Unit tests for participant_request_stop()/participant_shutdown_requested().
 */

#include "spsec_common.h"
#include "participant.h"

#include <stdio.h>

static int g_failures = 0;
#define CHECK(cond, msg)                                                     \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "  FAIL: %s\n", msg);                                  \
      g_failures++;                                                          \
    }                                                                        \
  } while (0)

int main(void) {
  configure_logging("CRITICAL");

  // g_stop_requested is set-once by design (signal-handler global), so
  // this test only observes one false-to-true transition.
  CHECK(participant_shutdown_requested() == false,
        "not requested before participant_request_stop() is ever called");

  participant_request_stop();
  CHECK(participant_shutdown_requested() == true,
        "requested after participant_request_stop()");

  /* Idempotent: calling again must not crash or change the observed state. */
  participant_request_stop();
  CHECK(participant_shutdown_requested() == true,
        "still requested after a second participant_request_stop() call");

  if (g_failures) {
    fprintf(stderr, "\n%d participant_stop_flag check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All participant_stop_flag checks passed.\n");
  return 0;
}
