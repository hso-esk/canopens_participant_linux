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
 * @file test_heartbeat_cycle.c
 * @brief Regression tests for participant_get_heartbeat_cycle_ms().
 */

#include "spsec_common.h"
#include "participant.h"
#include "spsec_registers.h"

#include <stdio.h>

static int g_failures = 0;
#define CHECK(cond, msg)                                                      \
  do {                                                                        \
    if (!(cond)) {                                                            \
      fprintf(stderr, "  FAIL: %s\n", msg);                                   \
      g_failures++;                                                           \
    }                                                                         \
  } while (0)

int main(void) {
  configure_logging("CRITICAL");

  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_DISABLED) == 0,
        "DISABLED -> 0ms");
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_8S) == 8000,
        "8S -> 8000ms");
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_4S) == 4000,
        "4S -> 4000ms");
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_2S) == 2000,
        "2S -> 2000ms");
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_1S) == 1000,
        "1S -> 1000ms");
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_500MS) == 500,
        "500MS -> 500ms");
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_250MS) == 250,
        "250MS -> 250ms");

  // Manufacturer-specific range (0x80-0x8F): fixed 1000ms per the default case.
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_MANUFACTURER_MIN) ==
            1000,
        "manufacturer range lower bound (0x80) -> 1000ms");
  CHECK(participant_get_heartbeat_cycle_ms(SPSEC_HEARTBEAT_MANUFACTURER_MAX) ==
            1000,
        "manufacturer range upper bound (0x8F) -> 1000ms");
  CHECK(participant_get_heartbeat_cycle_ms(
            (spsec_heartbeat_timing_t)0x85) == 1000,
        "manufacturer range midpoint (0x85) -> 1000ms");

  // Values outside every known case and outside the manufacturer range fall
  // through to the default's final `return 0`.
  CHECK(participant_get_heartbeat_cycle_ms((spsec_heartbeat_timing_t)0x07) ==
            0,
        "value just above 250MS (0x07), below manufacturer range -> 0ms");
  CHECK(participant_get_heartbeat_cycle_ms((spsec_heartbeat_timing_t)0x7F) ==
            0,
        "value just below manufacturer range (0x7F) -> 0ms");
  CHECK(participant_get_heartbeat_cycle_ms((spsec_heartbeat_timing_t)0x90) ==
            0,
        "value just above manufacturer range (0x90) -> 0ms");
  CHECK(participant_get_heartbeat_cycle_ms((spsec_heartbeat_timing_t)0xFF) ==
            0,
        "arbitrary unmapped value (0xFF) -> 0ms");

  if (g_failures) {
    fprintf(stderr, "\n%d heartbeat_cycle check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All heartbeat_cycle checks passed.\n");
  return 0;
}
