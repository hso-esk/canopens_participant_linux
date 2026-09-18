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
 * @file test_sync_restart_recovery.c
 * @brief Tests Sync-role restart recovery when sync broadcasts become unverifiable.
 */

#include "participant.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include "timer.h"

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

static int init_test_participant(Participant *p_ptr) {
  memset(p_ptr, 0, sizeof(*p_ptr));
  if (timer_init(&p_ptr->timer, 8) != 0) {
    fprintf(stderr, "timer_init failed\n");
    return 1;
  }
  // Defaults matching participant_init()'s timesync block.
  p_ptr->timesync.broadcast_wait_us = 15000000ULL; // 15 s
  p_ptr->timesync.is_synchronized = true;
  p_ptr->timesync.last_successful = 0;
  return 0;
}

static void destroy_test_participant(Participant *p_ptr) { timer_destroy(&p_ptr->timer); }

int main(void) {
  configure_logging("CRITICAL");

  const uint64_t WAIT = 15000000ULL; // 15 s window used throughout

  // A healthy bus keeps refreshing last_successful, so a broadcast that
  // fails to verify is a stray frame and must NOT evict the node.
  printf("Testing failure inside the wait window is ignored...\n");
  {
    Participant p;
    if (init_test_participant(&p))
      return 1;

    p.timesync.last_successful = 1000000ULL; // 1 s
    // Only 5 s of silence - well inside the 15 s window.
    CHECK(!participant_should_abort_on_sync_failure(&p, 6000000ULL),
          "5 s of silence: no abort (stray bad frame, not a restart)");
    // Exactly at the boundary must not trip it either (strict >).
    CHECK(!participant_should_abort_on_sync_failure(&p, 1000000ULL + WAIT),
          "exactly at the window boundary: no abort");

    destroy_test_participant(&p);
  }

  // Silence beyond the window + an unverifiable broadcast means the Sync
  // role restarted with a new csalt - abort and re-authenticate.
  printf("Testing failure after the wait window triggers abort...\n");
  {
    Participant p;
    if (init_test_participant(&p))
      return 1;

    p.timesync.last_successful = 1000000ULL; // 1 s
    CHECK(participant_should_abort_on_sync_failure(&p, 1000000ULL + WAIT + 1),
          "just past the window: abort");
    CHECK(participant_should_abort_on_sync_failure(&p, 60000000ULL),
          "59 s of silence: abort");

    destroy_test_participant(&p);
  }

  // ============================================================
  // Guards.
  // ============================================================
  printf("Testing guards (never synced / detection disabled / NULL)...\n");
  {
    Participant p;
    if (init_test_participant(&p))
      return 1;

    // A node that never synchronized is already in WAITING doing parameter
    // authentication - there is nothing to abort back to.
    p.timesync.is_synchronized = false;
    p.timesync.last_successful = 0;
    CHECK(!participant_should_abort_on_sync_failure(&p, 60000000ULL),
          "never synchronized: no abort");

    // wait == 0 disables Sync-restart detection entirely.
    p.timesync.is_synchronized = true;
    p.timesync.broadcast_wait_us = 0;
    CHECK(!participant_should_abort_on_sync_failure(&p, 60000000ULL),
          "broadcast_wait_us == 0: detection disabled");

    CHECK(!participant_should_abort_on_sync_failure(NULL, 60000000ULL),
          "NULL participant: no abort, no crash");

    destroy_test_participant(&p);
  }

  // Verified broadcast refreshes last_successful timestamp.
  printf("Testing a refreshed last_successful re-arms the window...\n");
  {
    Participant p;
    if (init_test_participant(&p))
      return 1;

    p.timesync.last_successful = 1000000ULL;
    CHECK(participant_should_abort_on_sync_failure(&p, 20000000ULL),
          "stale: would abort");

    // A broadcast verifies at t=20 s and refreshes the mark.
    p.timesync.last_successful = 20000000ULL;
    CHECK(!participant_should_abort_on_sync_failure(&p, 20000000ULL),
          "after a verified broadcast: window re-armed, no abort");
    CHECK(!participant_should_abort_on_sync_failure(&p, 30000000ULL),
          "10 s after that broadcast: still inside the window");
    CHECK(participant_should_abort_on_sync_failure(&p, 36000000ULL),
          "16 s after that broadcast: stale again, abort");

    destroy_test_participant(&p);
  }

  if (g_failures) {
    fprintf(stderr, "\n%d sync_restart_recovery check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All sync_restart_recovery checks passed.\n");
  return 0;
}
