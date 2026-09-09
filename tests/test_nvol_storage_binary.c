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
 * @file test_nvol_storage_binary.c
 * @brief Unit tests for nvol_storage binary format functions.
 */

#include "spsec_common.h"
#include "nvol_storage.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

  // Initialize nvol_storage with binary format (true)
  if (nvol_storage_init("./test_nvol_storage_binary_data", true) < 0) {
    fprintf(stderr, "Failed to initialize nvol_storage\n");
    return 1;
  }

  // ============================================================
  // u16 tests
  // ============================================================
  printf("Testing u16 write/read round-trip...\n");
  {
    // Test 0xABCD
    CHECK(nvol_storage_write_u16("test_u16_a", 0xABCD) == 0,
          "u16 0xABCD: write succeeds");
    uint16_t val = 0;
    CHECK(nvol_storage_read_u16("test_u16_a", &val) == 0,
          "u16 0xABCD: read succeeds");
    CHECK(val == 0xABCD, "u16 0xABCD: value matches");

    // Test 0
    CHECK(nvol_storage_write_u16("test_u16_b", 0) == 0,
          "u16 0: write succeeds");
    val = 0xFFFF;
    CHECK(nvol_storage_read_u16("test_u16_b", &val) == 0,
          "u16 0: read succeeds");
    CHECK(val == 0, "u16 0: value matches");

    // Test 0xFFFF
    CHECK(nvol_storage_write_u16("test_u16_c", 0xFFFF) == 0,
          "u16 0xFFFF: write succeeds");
    val = 0;
    CHECK(nvol_storage_read_u16("test_u16_c", &val) == 0,
          "u16 0xFFFF: read succeeds");
    CHECK(val == 0xFFFF, "u16 0xFFFF: value matches");
  }

  // ============================================================
  // u32 tests
  // ============================================================
  printf("Testing u32 write/read round-trip...\n");
  {
    // Test 0xDEADBEEF
    CHECK(nvol_storage_write_u32("test_u32_a", 0xDEADBEEF) == 0,
          "u32 0xDEADBEEF: write succeeds");
    uint32_t val = 0;
    CHECK(nvol_storage_read_u32("test_u32_a", &val) == 0,
          "u32 0xDEADBEEF: read succeeds");
    CHECK(val == 0xDEADBEEF, "u32 0xDEADBEEF: value matches");

    // Test 0
    CHECK(nvol_storage_write_u32("test_u32_b", 0) == 0,
          "u32 0: write succeeds");
    val = 0xFFFFFFFF;
    CHECK(nvol_storage_read_u32("test_u32_b", &val) == 0,
          "u32 0: read succeeds");
    CHECK(val == 0, "u32 0: value matches");

    // Test 0xFFFFFFFF
    CHECK(nvol_storage_write_u32("test_u32_c", 0xFFFFFFFF) == 0,
          "u32 0xFFFFFFFF: write succeeds");
    val = 0;
    CHECK(nvol_storage_read_u32("test_u32_c", &val) == 0,
          "u32 0xFFFFFFFF: read succeeds");
    CHECK(val == 0xFFFFFFFF, "u32 0xFFFFFFFF: value matches");
  }

  // ============================================================
  // u64 tests
  // ============================================================
  printf("Testing u64 write/read round-trip...\n");
  {
    // Test 0x0123456789ABCDEF
    CHECK(nvol_storage_write_u64("test_u64_a", 0x0123456789ABCDEFULL) == 0,
          "u64 0x0123456789ABCDEF: write succeeds");
    uint64_t val = 0;
    CHECK(nvol_storage_read_u64("test_u64_a", &val) == 0,
          "u64 0x0123456789ABCDEF: read succeeds");
    CHECK(val == 0x0123456789ABCDEFULL, "u64 0x0123456789ABCDEF: value matches");

    // Test 0
    CHECK(nvol_storage_write_u64("test_u64_b", 0) == 0,
          "u64 0: write succeeds");
    val = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(nvol_storage_read_u64("test_u64_b", &val) == 0,
          "u64 0: read succeeds");
    CHECK(val == 0, "u64 0: value matches");

    // Test 0xFFFFFFFFFFFFFFFF
    CHECK(nvol_storage_write_u64("test_u64_c", 0xFFFFFFFFFFFFFFFFULL) == 0,
          "u64 0xFFFFFFFFFFFFFFFF: write succeeds");
    val = 0;
    CHECK(nvol_storage_read_u64("test_u64_c", &val) == 0,
          "u64 0xFFFFFFFFFFFFFFFF: read succeeds");
    CHECK(val == 0xFFFFFFFFFFFFFFFFULL, "u64 0xFFFFFFFFFFFFFFFF: value matches");
  }

  // ============================================================
  // varlen tests
  // ============================================================
  printf("Testing varlen write/read round-trip...\n");
  {
    uint8_t write_buf[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t read_buf[10] = {0};

    CHECK(nvol_storage_write_varlen("test_varlen_a", write_buf, 5) == 0,
          "varlen 5 bytes: write succeeds");
    size_t actual_len = 0;
    CHECK(nvol_storage_read_varlen("test_varlen_a", read_buf, sizeof(read_buf), &actual_len) == 0,
          "varlen 5 bytes: read succeeds");
    CHECK(actual_len == 5, "varlen 5 bytes: length matches");
    CHECK(memcmp(read_buf, write_buf, 5) == 0,
          "varlen 5 bytes: data matches via memcmp");
  }

  // ============================================================
  // Atomicity & Orphaned .tmp file isolation test
  // ============================================================
  printf("Testing atomic write isolation (abandoned .tmp files ignored)...\n");
  {
    uint32_t val = 0x12345678;
    CHECK(nvol_storage_write_u32("config/atomic_test", val) == 0, "write initial file succeeds");

    // Simulate an interrupted write leaving a corrupted .tmp file on disk
    FILE *corrupted_tmp_ptr = fopen("./test_nvol_storage_binary_data/config/atomic_test.bin.tmp", "wb");
    CHECK(corrupted_tmp_ptr != NULL, "create simulated corrupted .tmp file");
    if (corrupted_tmp_ptr) {
      uint8_t garbage[16] = {0xFF, 0xFF, 0xFF, 0xFF};
      fwrite(garbage, 1, sizeof(garbage), corrupted_tmp_ptr);
      fclose(corrupted_tmp_ptr);
    }

    // Read should still read the valid, atomic committed file
    uint32_t read_back = 0;
    CHECK(nvol_storage_read_u32("config/atomic_test", &read_back) == 0, "read ignores .tmp and succeeds");
    CHECK(read_back == val, "read value is uncorrupted by .tmp file");
  }

  // ============================================================
  // Final cleanup
  // ============================================================
  nvol_storage_cleanup();
  {
    int rc = system("rm -rf ./test_nvol_storage_binary_data");
    (void)rc;
  }

  if (g_failures) {
    fprintf(stderr, "\n%d nvol_storage_binary check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All nvol_storage_binary checks passed.\n");
  return 0;
}
