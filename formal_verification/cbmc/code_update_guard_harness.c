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

/* CBMC harness for 92h code update accumulator buffer guard. */
#include <stdint.h>
#include <string.h>

/* Buffer bound arithmetic check harness. */
#define MAX 64u

typedef struct {
  uint8_t buf[MAX];
  uint32_t len;
  uint32_t expected;
  int active;
} Accum;

uint32_t nondet_u32(void);
uint8_t nondet_u8(void);

/* Verbatim guard from register_apply_write_segment(), 92h case. */
static int apply_code_update_segment(Accum *a, const uint8_t *data, uint8_t data_len) {
  if (!a->active)
    return -1;
  if (data_len == 0)
    return -1;
  if ((uint32_t)data_len > a->expected - a->len) { /* overflow guard */
    a->len = 0; a->expected = 0; a->active = 0;    /* write_accum_reset */
    return -1;
  }
  memcpy(a->buf + a->len, data, data_len);         /* line 419 in source */
  a->len += data_len;
  return 0;
}

int main(void) {
  Accum a;
  /* Upstream invariant (register_check_write_status): expected is the
   * register length, validated <= MAX; len is what prior segments left. */
  a.expected = nondet_u32();
  a.len = nondet_u32();
  __CPROVER_assume(a.expected <= MAX);
  __CPROVER_assume(a.len <= a.expected);
  a.active = 1;

  uint8_t data_len = nondet_u8(); /* attacker-chosen, wire field is uint8_t */
  uint8_t data[256];

  int rc = apply_code_update_segment(&a, data, data_len);

  __CPROVER_assert(a.len <= MAX, "accumulator length stays within buf[]");
  (void)rc;
  return 0;
}
