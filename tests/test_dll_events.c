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
 * @file test_dll_events.c
 * @brief Unit tests for Data Link Layer (DLL) event detection.
 */

#include "dll_events.h"
#include "spsec_registers.h"
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

static void test_dll_init_and_registration(void) {
  printf("Testing DLL initialization and own CAN ID registration...\n");
  DLLEventContext ctx;
  CHECK(dll_events_init(&ctx, 120) == 0, "dll_events_init succeeds");
  CHECK(ctx.own_can_id_count == 26, "registers 26 control-plane CAN IDs (13 CPMTs x 2 modes)");
  CHECK(ctx.rx_overrun_detected == false, "rx_overrun initially false");
  CHECK(ctx.tx_overrun_detected == false, "tx_overrun initially false");

  /* Duplicate registration does not increase count */
  uint32_t first_id = ctx.own_can_ids[0];
  dll_events_register_own_can_id(&ctx, first_id);
  CHECK(ctx.own_can_id_count == 26, "re-registering existing ID is a no-op");

  dll_events_cleanup(&ctx);
  CHECK(ctx.own_can_id_count == 0, "dll_events_cleanup zeroes context");
}

static void test_dll_address_guard(void) {
  printf("Testing DLL Address ID guard (own CAN ID detection)...\n");
  DLLEventContext ctx;
  dll_events_init(&ctx, 120);

  /* Any of own registered IDs must trigger DLL_ADRID_GUARD */
  uint32_t own_hello_id = (uint32_t)(0x1E000000 | (0 << 8) | 120);
  uint16_t evt = dll_events_check_address_guard(&ctx, own_hello_id);
  CHECK(evt == SPSEC_DLL_ADRID_GUARD, "own control-plane ID triggers SPSEC_DLL_ADRID_GUARD");

  /* Other participant's ID must pass cleanly */
  uint32_t other_node_id = (uint32_t)(0x1E000000 | (0 << 8) | 121);
  evt = dll_events_check_address_guard(&ctx, other_node_id);
  CHECK(evt == 0, "other participant's ID does not trigger guard");

  /* Non-existent context returns 0 */
  CHECK(dll_events_check_address_guard(NULL, own_hello_id) == 0, "NULL context returns 0");

  dll_events_cleanup(&ctx);
}

static void test_dll_duplicate_frame(void) {
  printf("Testing DLL duplicate frame detection...\n");
  DLLEventContext ctx;
  dll_events_init(&ctx, 120);

  uint32_t can_id = 0x181;
  uint64_t t0 = 1000000ULL;

  /* First frame arrives: accepted */
  uint16_t evt = dll_events_check_duplicate_frame(&ctx, can_id, t0);
  CHECK(evt == 0, "first frame accepted");
  CHECK(ctx.last_received_can_id == can_id, "last_received_can_id updated");
  CHECK(ctx.last_received_timestamp == t0, "last_received_timestamp updated");

  /* Duplicate frame arrives within 500 us (< 1000 us window): rejected */
  uint64_t t1 = t0 + 500ULL;
  evt = dll_events_check_duplicate_frame(&ctx, can_id, t1);
  CHECK(evt == SPSEC_DLL_DUP_FRAME_IGNORED, "frame within 1000 us rejected as duplicate");

  /* Different CAN ID within 500 us: accepted */
  uint32_t different_can_id = 0x201;
  evt = dll_events_check_duplicate_frame(&ctx, different_can_id, t1);
  CHECK(evt == 0, "different CAN ID accepted even within window");

  /* Same CAN ID after window expires (diff = 1500 us >= 1000 us): accepted */
  uint64_t t2 = t1 + 1500ULL;
  evt = dll_events_check_duplicate_frame(&ctx, different_can_id, t2);
  CHECK(evt == 0, "frame after window expires accepted");

  /* NULL context safe */
  CHECK(dll_events_check_duplicate_frame(NULL, can_id, t0) == 0, "NULL context returns 0");

  dll_events_cleanup(&ctx);
}

static void test_dll_overruns(void) {
  printf("Testing DLL RX and TX overrun detection...\n");
  DLLEventContext ctx;
  dll_events_init(&ctx, 120);

  CHECK(dll_events_check_rx_overrun(&ctx) == 0, "initial rx overrun is 0");
  CHECK(dll_events_check_tx_overrun(&ctx) == 0, "initial tx overrun is 0");

  /* Flag set: returns event and resets flag */
  ctx.rx_overrun_detected = true;
  CHECK(dll_events_check_rx_overrun(&ctx) == SPSEC_DLL_RX_OVERRUN, "detects rx overrun");
  CHECK(ctx.rx_overrun_detected == false, "rx overrun resets after reporting");
  CHECK(dll_events_check_rx_overrun(&ctx) == 0, "second call returns 0");

  ctx.tx_overrun_detected = true;
  CHECK(dll_events_check_tx_overrun(&ctx) == SPSEC_DLL_TX_OVERRUN, "detects tx overrun");
  CHECK(ctx.tx_overrun_detected == false, "tx overrun resets after reporting");
  CHECK(dll_events_check_tx_overrun(&ctx) == 0, "second call returns 0");

  /* NULL context safe */
  CHECK(dll_events_check_rx_overrun(NULL) == 0, "NULL rx overrun returns 0");
  CHECK(dll_events_check_tx_overrun(NULL) == 0, "NULL tx overrun returns 0");

  dll_events_cleanup(&ctx);
}

static void test_dll_process_received_frame(void) {
  printf("Testing dll_events_process_received_frame pipeline...\n");
  DLLEventContext ctx;
  dll_events_init(&ctx, 120);

  uint32_t own_id = ctx.own_can_ids[0];
  uint64_t now = 5000000ULL;

  /* Address ID guard takes precedence */
  uint16_t evt = dll_events_process_received_frame(&ctx, own_id, now);
  CHECK(evt == SPSEC_DLL_ADRID_GUARD, "pipeline catches address guard violation");

  /* Clean frame */
  uint32_t foreign_id = 0x601;
  evt = dll_events_process_received_frame(&ctx, foreign_id, now);
  CHECK(evt == 0, "pipeline accepts valid foreign frame");

  /* Duplicate foreign frame */
  evt = dll_events_process_received_frame(&ctx, foreign_id, now + 200ULL);
  CHECK(evt == SPSEC_DLL_DUP_FRAME_IGNORED, "pipeline catches duplicate frame");

  dll_events_cleanup(&ctx);
}

int main(void) {
  test_dll_init_and_registration();
  test_dll_address_guard();
  test_dll_duplicate_frame();
  test_dll_overruns();
  test_dll_process_received_frame();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d dll_events check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All dll_events checks passed.\n");
  return 0;
}
