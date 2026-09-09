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
 * @file test_timesync_ready.c
 * @brief Regression tests for participant_check_timesync_ready().
 */

#include "spsec_common.h"
#include "participant.h"
#include "keys.h"
#include "messages.h"
#include "participant_timesync.h"
#include "../spsec_participant/session_loops_internal.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;
#define CHECK(cond, msg)                                                      \
  do {                                                                        \
    if (!(cond)) {                                                            \
      fprintf(stderr, "  FAIL: %s\n", msg);                                   \
      g_failures++;                                                           \
    }                                                                         \
  } while (0)

static int init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  return 0;
}

int main(void) {
  configure_logging("CRITICAL");

  Participant p;
  init_test_participant(&p);

  // Case 1: both seed key (index 3) and seed salt (index 3) NULL (zero-init
  // default) -> not ready.
  CHECK(participant_check_timesync_ready(&p) == -1,
        "Case 1: both seed key and salt NULL returns -1 (not ready)");

  // Case 2: seed key present, seed salt still NULL -> not ready.
  uint8_t key_buf[KEY_LEN];
  memset(key_buf, 0x11, KEY_LEN);
  p.comm_keys.spsec_keys[3] = spseckey_new(0xAABBCCDD, key_buf);
  CHECK(p.comm_keys.spsec_keys[3] != NULL, "Case 2 setup: spseckey_new succeeds");
  CHECK(participant_check_timesync_ready(&p) == -1,
        "Case 2: seed key present, seed salt NULL returns -1 (not ready)");

  // Case 3: seed key present, seed salt now present too -> ready.
  uint8_t salt_buf[SALT_LEN];
  memset(salt_buf, 0x22, SALT_LEN);
  p.comm_keys.spsec_salt[3] = spsecsalt_new(salt_buf);
  CHECK(p.comm_keys.spsec_salt[3] != NULL, "Case 3 setup: spsecsalt_new succeeds");
  CHECK(participant_check_timesync_ready(&p) == 0,
        "Case 3: both seed key and salt present returns 0 (ready)");

  // Case 4: seed key freed/NULLed again, seed salt still present -> not ready.
  spseckey_free(p.comm_keys.spsec_keys[3]);
  p.comm_keys.spsec_keys[3] = NULL;
  CHECK(participant_check_timesync_ready(&p) == -1,
        "Case 4: seed key NULL, seed salt present returns -1 (not ready)");

  // Cleanup
  spsecsalt_free(p.comm_keys.spsec_salt[3]);
  p.comm_keys.spsec_salt[3] = NULL;

  // Case 5: timesync_process_mtls_auth_time rejects if csalt is not set
  printf("Testing Case 5: timesync_process_mtls_auth_time csalt-zero rejection...\n");
  {
    Participant ts;
    memset(&ts, 0, sizeof(ts));
    ts.participant_id = 120;
    ts.timesync.is_role_authority = true;
    memset(ts.comm_keys.csalt, 0, sizeof(ts.comm_keys.csalt)); // csalt unset

    uint8_t rnd[RANDOM_SIZE] = {0x42};
    SPsecTimeSyncRequest *req_ptr = timesyncrequest_new(121, rnd);
    CHECK(req_ptr != NULL, "Case 5 setup: timesyncrequest_new succeeds");

    signed char res = timesync_process_mtls_auth_time(&ts, req_ptr);
    CHECK(res == -1, "Case 5: timesync_process_mtls_auth_time rejects when csalt is unset");

    timesyncrequest_free(req_ptr);
  }

  if (g_failures) {
    fprintf(stderr, "\n%d timesync_ready check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All timesync_ready checks passed.\n");
  return 0;
}
