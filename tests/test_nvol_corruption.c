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
 * @file test_nvol_corruption.c
 * @brief Tests handling of corrupted and truncated NVOL storage files.
 */

#include "platform_nvol_storage.h"
#include "spsec_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__);                \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

#define TEST_FILE "/tmp/test_nvol_corruption_data.txt"

static void write_file(const char *content_ptr) {
  FILE *f_ptr = fopen(TEST_FILE, "w");
  if (f_ptr) {
    fputs(content_ptr, f_ptr);
    fclose(f_ptr);
  }
}

static void remove_test_file(void) {
  unlink(TEST_FILE);
}

static void test_nonexistent_file(void) {
  printf("Testing non-existent file retrieval...\n");
  size_t out_len = 0;
  uint8_t *val_ptr = platform_retrieve_dict_from_file("/tmp/this_file_does_not_exist_12345.txt",
                                                  "my_key", &out_len);
  CHECK(val_ptr == NULL, "non-existent file returns NULL");
  CHECK(out_len == 0, "out_len remains 0 on missing file");
}

static void test_missing_key_and_malformed_lines(void) {
  printf("Testing malformed lines without colons and missing keys...\n");
  write_file("# This is a comment without a colon\n"
             "invalid_line_no_colon\n"
             "other_key: 11223344\n"
             "another line\n");

  size_t out_len = 0;
  uint8_t *val_ptr = platform_retrieve_dict_from_file(TEST_FILE, "target_key", &out_len);
  CHECK(val_ptr == NULL, "missing key returns NULL despite malformed lines");

  /* Existing key should still be retrievable */
  val_ptr = platform_retrieve_dict_from_file(TEST_FILE, "other_key", &out_len);
  CHECK(val_ptr != NULL, "valid key on later line is found");
  CHECK(out_len == 4, "out_len is 4 bytes");
  if (val_ptr) {
    uint8_t expected[4] = {0x11, 0x22, 0x33, 0x44};
    CHECK(memcmp(val_ptr, expected, 4) == 0, "retrieved bytes match expected hex");
    free(val_ptr);
  }
  remove_test_file();
}

static void test_odd_length_hex_string(void) {
  printf("Testing odd-length hex string rejection...\n");
  write_file("odd_key: 12345\n");

  size_t out_len = 0;
  uint8_t *val_ptr = platform_retrieve_dict_from_file(TEST_FILE, "odd_key", &out_len);
  CHECK(val_ptr == NULL, "odd-length hex string rejected (returns NULL)");
  remove_test_file();
}

static void test_invalid_hex_digits(void) {
  printf("Testing non-hex characters rejection...\n");
  write_file("bad_hex: 1234ZZ56\n");

  size_t out_len = 0;
  uint8_t *val_ptr = platform_retrieve_dict_from_file(TEST_FILE, "bad_hex", &out_len);
  CHECK(val_ptr == NULL, "non-hex digits rejected (returns NULL)");
  remove_test_file();
}

static void test_long_line_parsing(void) {
  printf("Testing long line (>512 bytes) parsing with getline()...\n");
  /* Build a 128-byte hex string (256 hex chars) plus padding */
  char long_content[1024];
  strcpy(long_content, "long_key: ");
  for (int i = 0; i < 128; i++) {
    strcat(long_content, "ab");
  }
  strcat(long_content, "\n");
  write_file(long_content);

  size_t out_len = 0;
  uint8_t *val_ptr = platform_retrieve_dict_from_file(TEST_FILE, "long_key", &out_len);
  CHECK(val_ptr != NULL, "long line (>256 chars) successfully parsed");
  CHECK(out_len == 128, "out_len is 128 bytes");
  if (val_ptr) {
    bool all_match = true;
    for (size_t i = 0; i < out_len; i++) {
      if (val_ptr[i] != 0xAB) {
        all_match = false;
        break;
      }
    }
    CHECK(all_match, "all bytes of 128-byte value match 0xAB");
    free(val_ptr);
  }
  remove_test_file();
}

int main(void) {
  test_nonexistent_file();
  test_missing_key_and_malformed_lines();
  test_odd_length_hex_string();
  test_invalid_hex_digits();
  test_long_line_parsing();

  if (g_failures != 0) {
    fprintf(stderr, "\n%d nvol_corruption check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("All nvol_corruption checks passed.\n");
  return 0;
}
