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
 * @file test_can_link_recovery.c
 * @brief Unit tests for CAN channel link-bounce recovery.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "communication_interface.h"

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PF_CAN
#define PF_CAN 29
#endif
#ifndef CAN_RAW
#define CAN_RAW 1
#endif
#ifndef SIOCGIFINDEX
#define SIOCGIFINDEX 0x8933
#endif

/* Local socket declarations to avoid pulling in Linux CAN headers. */
struct ifreq_local {
    char ifr_name[IF_NAMESIZE];
};

static int g_failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__);                \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

#define VCAN_IFACE "vcan0"

static int vcan_exists(void) {
  int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
  if (s < 0)
    return 0;
  struct ifreq_local ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, VCAN_IFACE, sizeof(ifr.ifr_name) - 1);
  int ret = ioctl(s, SIOCGIFINDEX, &ifr);
  close(s);
  return ret == 0;
}

static void test_check_link_alive_invalid(void) {
  printf("Testing can_channel_check_link_alive: invalid channel returns -1...\n");
  CHECK(can_channel_check_link_alive(NULL) == -1,
        "NULL channel rejected by check_link_alive");

  CommChannel ch = {0};
  ch.socket = -1;
  CHECK(can_channel_check_link_alive(&ch) == -1,
        "uninitialised channel rejected by check_link_alive");
}

static void test_recover_invalid(void) {
  printf("Testing can_channel_recover: invalid channel returns -1...\n");
  CHECK(can_channel_recover(NULL) == -1, "NULL channel rejected by recover");
}

static void test_full_cycle(void) {
  if (!vcan_exists()) {
    printf("Skipping live cycle test: %s not present (sudo ./setup_vcan.sh)\n",
           VCAN_IFACE);
    return;
  }
  printf("Testing can_channel init -> check_link_alive -> recover -> check...\n");
  CommChannel ch = {0};
  signed char ret = can_channel_init(&ch, VCAN_IFACE, 500000, 2000000);
  CHECK(ret == 0, "can_channel_init succeeds on vcan0");
  if (ret != 0)
    return;

  CHECK(can_channel_check_link_alive(&ch) == 0,
        "link is alive after init");

  /* Re-bind the same interface. */
  CHECK(can_channel_recover(&ch) == 0, "recover succeeds on healthy link");
  CHECK(can_channel_check_link_alive(&ch) == 0,
        "link still alive after recover");

  can_channel_destroy(&ch);
}

int main(void) {
  test_check_link_alive_invalid();
  test_recover_invalid();
  test_full_cycle();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d can_link_recovery check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All can_link_recovery checks passed.\n");
  return 0;
}
