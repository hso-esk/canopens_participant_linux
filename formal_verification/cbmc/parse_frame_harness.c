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

/* CBMC harness: verifies memory safety of frame parsers. */
#include "messages.h"
#include "spsec_protocol_can.h"
#include "spsec_protocol_internal.h"

/* Logging sink lives in platform/logging.c; not under test. */
void log_message(int level, const char *name_ptr, const char *format_ptr, ...) {}

uint32_t nondet_u32(void);
uint8_t nondet_u8(void);

int main(void) {
  CanFrame frame; /* data[] is nondeterministic */
  frame.can_id = nondet_u32() & CAN_ID_MASK;
  frame.len = nondet_u8();
  __CPROVER_assume(frame.len <= 64);

  uint32_t base_id = frame.can_id;
  uint8_t *arb_id_bytes_ptr = (uint8_t *)&base_id;
  SPsecMessage *msg_ptr =
      can_protocol_parse_received_frame(base_id, arb_id_bytes_ptr, &frame);
  spsecmessage_dispose(msg_ptr);
  return 0;
}
