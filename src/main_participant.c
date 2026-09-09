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

#include "config.h"
#include "crypto_types.h"
#include "participant.h"
#include "platform_system.h"
#include "spsec_common.h"
#include <getopt.h>

#include <stdint.h>
#include <stdlib.h>

#include <time.h>

static const char *logger_name_ptr = "main_participant";

// Parse CLI options, then start the participant.
int main(int argc, char *argv_ptr[]) {
  const char *secure_if_ptr = "vcan0";
  const char *insecure_if_ptr = "vcan1";
  const char *log_level_ptr = "INFO";
  uint8_t participant_id = 123; // Default ID
  const char *keys_file_ptr = NULL;
  bool enable_timesync_role = false;
  bool use_chacha = false;
  bool use_ascon = false;
  bool auth_only_mode = false;
  bool use_bin_storage = false;
  uint32_t accept_window_ticks = SPSEC_ACCEPT_WINDOW_TICKS; /* Default 150 = 15 ms */
  uint64_t sync_broadcast_wait_us = 0;
  bool sync_broadcast_wait_set = false;
  uint64_t sync_broadcast_interval_us = 0;
  bool sync_broadcast_interval_set = false;
  spsec_csalt_regen_mode_t csalt_regen_mode = SPSEC_CSALT_REGEN_POWER_UP;

  // Long-only options (no short letter) - the short-option space is crowded.
  enum {
    OPT_SYNC_BROADCAST_WAIT = 1000,
    OPT_SYNC_BROADCAST_INTERVAL,
    OPT_CSALT_REGEN,
  };

  struct option long_options[] = {{"secure-if", required_argument, 0, 's'},
                                  {"insecure-if", required_argument, 0, 'i'},
                                  {"log-level", required_argument, 0, 'l'},
                                  {"id", required_argument, 0, 'p'},
                                  {"keys_file", required_argument, 0, 'k'},
                                  {"timesync", no_argument, 0, 't'},
                                  {"chacha", no_argument, 0, 'c'},
                                  {"ascon", no_argument, 0, 'a'},
                                  {"auth-only", no_argument, 0, 'A'},
                                  {"bin-storage", no_argument, 0, 'b'},
                                  {"accept-window", required_argument, 0, 'w'},
                                  {"sync-broadcast-wait", required_argument, 0,
                                   OPT_SYNC_BROADCAST_WAIT},
                                  {"sync-broadcast-interval", required_argument, 0,
                                   OPT_SYNC_BROADCAST_INTERVAL},
                                  {"csalt-regen", required_argument, 0,
                                   OPT_CSALT_REGEN},
                                  {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv_ptr, "s:i:l:p:k:tcaAbw:", long_options,
                            NULL)) != -1) {
    switch (opt) {
    case 's':
      secure_if_ptr = optarg;
      break;
    case 'i':
      insecure_if_ptr = optarg;
      break;
    case 'l':
      log_level_ptr = optarg;
      break;
    case 'p': {
      char *end_ptr = NULL;
      long pid = strtol(optarg, &end_ptr, 10);
      if (*end_ptr != '\0' || pid < 1 || pid > 127) {
        fprintf(stderr, "Participant ID must be 1-127\n");
        return 1;
      }
      participant_id = (uint8_t)pid;
      break;
    }
    case 'k':
      keys_file_ptr = optarg;
      break;
    case 't':
      enable_timesync_role = true;
      break;
    case 'c':
      use_chacha = true;
      break;
    case 'a':
      use_ascon = true;
      break;
    case 'A':
      auth_only_mode = true;
      break;
    case 'b':
      use_bin_storage = true;
      break;
    case 'w': {
      char *end_ptr = NULL;
      long w = strtol(optarg, &end_ptr, 10);
      if (*end_ptr != '\0' || w < 0 || w > 40950) { // 40950 ticks = full 12-bit range (~4095 ms)
        fprintf(stderr, "Acceptance window must be 0-40950 ticks (0.1ms each)\n");
        return 1;
      }
      accept_window_ticks = (uint32_t)w;
      break;
    }
    case OPT_SYNC_BROADCAST_WAIT: {
      char *end_ptr = NULL;
      long ms = strtol(optarg, &end_ptr, 10);
      if (*end_ptr != '\0' || ms < 0 || ms > 3600000L) {
        fprintf(stderr,
                "Sync broadcast wait must be 0-3600000 ms (0 disables "
                "Sync-restart detection)\n");
        return 1;
      }
      sync_broadcast_wait_us = (uint64_t)ms * 1000ULL;
      sync_broadcast_wait_set = true;
      break;
    }
    case OPT_SYNC_BROADCAST_INTERVAL: {
      char *end_ptr = NULL;
      long ms = strtol(optarg, &end_ptr, 10);
      if (*end_ptr != '\0' || ms < 100 || ms > 3600000L) {
        fprintf(stderr, "Sync broadcast interval must be 100-3600000 ms\n");
        return 1;
      }
      sync_broadcast_interval_us = (uint64_t)ms * 1000ULL;
      sync_broadcast_interval_set = true;
      break;
    }
    case OPT_CSALT_REGEN:
      if (strcmp(optarg, "powerup") == 0) {
        csalt_regen_mode = SPSEC_CSALT_REGEN_POWER_UP;
      } else if (strcmp(optarg, "secure-entry") == 0) {
        csalt_regen_mode = SPSEC_CSALT_REGEN_SECURE_ENTRY;
      } else {
        fprintf(stderr, "--csalt-regen must be 'powerup' or 'secure-entry'\n");
        return 1;
      }
      break;
    default:
      fprintf(stderr,
              "Usage: %s [-s secure_if] [-i insecure_if] [-l log_level] [-p "
              "id] [-k keys_file] [-t] [--chacha] [--ascon] [--auth-only] [--bin-storage] [-w accept_window_ticks]\n",
              argv_ptr[0]);
      fprintf(stderr, "  -t, --timesync    Enable timesync role (acts as time "
                      "sync server)\n");
      fprintf(
          stderr,
          "  --chacha          Use ChaCha20-Poly1305 for AEAD encryption\n");
      fprintf(stderr,
              "  --ascon           Use ASCON-128 for AEAD encryption\n");
      fprintf(stderr, "  --auth-only       Enable authentication-only mode (no "
                      "encryption, data_ptr in AAD)\n");
      fprintf(stderr, "  --bin-storage     Use binary file format for storage instead of text\n");
      fprintf(stderr, "  -w, --accept-window <ticks>  Data-plane replay acceptance window in reference\n"
                      "                               0.1ms ticks, i.e. a fixed time regardless of the\n"
                      "                               configured CAN FD data bitrate (default 150 = 15 ms)\n");
      fprintf(stderr, "      --sync-broadcast-wait <ms>  Silence window after which an unverifiable sync\n"
                      "                               broadcast is treated as a Sync-role restart and the\n"
                      "                               node re-authenticates (default 30000, 3x the\n"
                      "                               broadcast interval; 0 disables)\n");
      fprintf(stderr, "      --sync-broadcast-interval <ms>  Sync role's periodic re-sync broadcast\n"
                      "                               interval (default 10000, paper v2 SS586/SS717)\n");
      fprintf(stderr, "      --csalt-regen <mode>     When the Sync role draws a fresh comm-key derivation\n"
                      "                               salt: 'powerup' (default, once per start) or\n"
                      "                               'secure-entry' (every WAITING->SECURE transition)\n");
      return 1;
    }
  }

  // Validate that only one algorithm flag is specified
  if (use_chacha && use_ascon) {
    fprintf(stderr, "Error: Cannot specify both --chacha and --ascon flags\n");
    return 1;
  }

  // Determine algorithm from CLI flags
  CryptoAlgorithm cli_algorithm;
  bool cli_algorithm_set = false;
  if (use_ascon) {
    cli_algorithm = CRYPTO_ALGO_ASCON128;
    cli_algorithm_set = true;
  } else if (use_chacha) {
    cli_algorithm = CRYPTO_ALGO_CHACHA20_POLY1305;
    cli_algorithm_set = true;
  }

  /* Build ParticipantConfig from CLI args for validation */
  ParticipantConfig config;
  config_init_defaults(&config);
  config.secure_interface_ptr = secure_if_ptr;
  config.insecure_interface_ptr = insecure_if_ptr;
  config.participant_id = participant_id;
  config.keys_file_ptr = keys_file_ptr;
  config.enable_timesync_role = enable_timesync_role;
  config.crypto_algorithm = cli_algorithm_set ? cli_algorithm : SPSEC_DEFAULT_AEAD_ALGO;
  config.auth_only_mode = auth_only_mode;
  config.log_level_ptr = log_level_ptr;

  if (config_validate(&config) != 0) {
    return 1;
  }

  configure_logging(log_level_ptr);
#if SPSEC_LOG_SECRETS
  LOG_CRITICAL(logger_name_ptr,
              "*** SECRET LOGGING ENABLED - DO NOT USE IN PRODUCTION ***");
#else
  LOG_INFO(logger_name_ptr, "Secret logging disabled (production build)");
#endif

  platform_request_stop_on_signal(participant_request_stop);

  // Zero-initialize entire struct to ensure clean default state
  Participant participant = {0};

  if (enable_timesync_role) {
    if (participant_init(&participant, participant_id, secure_if_ptr,
                         insecure_if_ptr, keys_file_ptr, true, 0, 0,
                         cli_algorithm_set ? &cli_algorithm : NULL,
                         auth_only_mode, use_bin_storage,
                         accept_window_ticks) < 0) {
      LOG_ERROR("main", "Failed to initialize participant");
      return -1;
    }
  } else {
    if (participant_init(&participant, participant_id, secure_if_ptr,
                         insecure_if_ptr, keys_file_ptr, false, 0, 0,
                         cli_algorithm_set ? &cli_algorithm : NULL,
                         auth_only_mode, use_bin_storage,
                         accept_window_ticks) < 0) {
      LOG_ERROR("main", "Failed to initialize participant");
      return -1;
    }
  }

  // Applied after init (which sets the defaults) and before the loops start,
  // so no participant_init() signature change is needed for two runtime knobs.
  if (sync_broadcast_interval_set) {
    participant.timesync.broadcast_interval_us = sync_broadcast_interval_us;
  }
  if (sync_broadcast_wait_set) {
    participant.timesync.broadcast_wait_us = sync_broadcast_wait_us;
  }
  participant.timesync.csalt_regen_mode = csalt_regen_mode;
  LOG_INFO(logger_name_ptr,
           "Sync-restart detection: broadcast_interval=%llu us, wait=%llu "
           "us, csalt regen=%s",
           (unsigned long long)participant.timesync.broadcast_interval_us,
           (unsigned long long)participant.timesync.broadcast_wait_us,
           csalt_regen_mode == SPSEC_CSALT_REGEN_POWER_UP ? "powerup"
                                                          : "secure-entry");

  participant_start_main_loop(&participant);
  participant_destroy(&participant);
  return 0;
}