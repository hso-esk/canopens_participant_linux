# Formal verification

| File | Tool | What it covers |
|------|------|----------------|
| `microtls.spthy` | Tamarin | Handshake (ClientHello … ServerFinished), `session_handshake.c` |
| `microTLS_handshake.pv` | ProVerif | Same handshake, second prover |
| `handshake_computational.pcv` | CryptoVerif | Same handshake, computational model with probability bound |
| `param_auth.spthy` | Tamarin | Time-auth: initial Parameter Authentication, `session_timesync.c` |
| `param_auth.pv` | ProVerif | Same exchange, second prover (unbounded) |
| `sync_broadcast.spthy` | Tamarin | Time-auth: ongoing Sync Time Broadcast, `session_loops_common.c` |
| `sync_broadcast_fixed.spthy` | Tamarin | Proposed forward-only fix for the broadcast replay gap |
| `sync_broadcast.pv` | ProVerif | Ongoing Sync Time Broadcast authenticity, second prover |
| `key_hierarchy.spthy` | Tamarin | Configuration sessions, PSK onboarding, key-write access policy |
| `key_hierarchy.pv` | ProVerif | Same key hierarchy & onboarding child key secrecy/origin, second prover |
| `config_session.spthy` | Tamarin | Register read + SessionTerminate under the Session Key |
| `config_session.pv` | ProVerif | Same configuration session, second prover (unbounded) |
| `data_plane.spthy` | Tamarin | Communication Keys, group frames, heartbeat replay (abstracted) |
| `data_plane.pv` | ProVerif | Same group data plane authenticity & epoch key secrecy, second prover |
| `cbmc/parse_frame_harness.c` | CBMC | Memory safety of the CAN frame parsers, `spsec_can_protocol/` |
| `cbmc/code_update_guard_harness.c` | CBMC | 92h code-update accumulator overflow guard |
| `timing/AcceptanceWindow.tla` | TLC | 12-bit timestamp reconstruction + acceptance window |

Tested with tamarin-prover 1.12.0 (Maude 3.5.1), ProVerif 2.05,
CryptoVerif 2.13, CBMC 6.11.0, TLA+ tools 1.7.4.

## Run

```bash
formal_verification/run_proofs.sh    # runs every tool found on PATH
# CryptoVerif also needs CRYPTOVERIF_LIB=<cryptoverif dir>/default
```

`ctest -R formal_verification` is registered when `tamarin-prover` and
`proverif` are installed at configure time. It runs the same script, which
skips any tool that isn't on PATH: CBMC runs only if `cbmc` is found,
CryptoVerif only if `CRYPTOVERIF_LIB` is set in the environment. Takes
about 80 s with all tools.

Tamarin lemmas named `attack_*` are `exists-trace` lemmas: **verified means the
documented attack exists**. Every Tamarin lemma is expected to be `verified`.

## Results and what they mean

**Handshake** (all three provers)
- Session-key secrecy (Tamarin, ProVerif).
- Injective agreement in both directions on participant ID, key selector,
  randoms and key (Tamarin, ProVerif).
- Injective agreement on the randoms (CryptoVerif), with
  Adv ≤ (N_C + N_S)·P_mac + 3(N_C² + N_S²)/2^|nonce| + P_prf.
  This assumes HKDF is a (dual) PRF and the 64-bit tag-only AEAD is SUF-CMA.
  P_mac carries the tag-truncation term that Dolev-Yao models ignore.
- Zero-Key sessions are unauthenticated by design (`zero_key_unauthenticated`).
- Only Tamarin models PSK compromise; ProVerif assumes non-Zero PSKs stay
  secret. CryptoVerif proves authentication only: the session key is used
  both for the Finished tags and the later AEAD, so key indistinguishability
  isn't claimed.

**Time authentication, part 1 — initial Parameter Authentication**
(`param_auth.spthy` Tamarin, `param_auth.pv` ProVerif)
- Tamarin `sync_authentic_and_fresh`: the adopted timer value and csalt were
  sent by the Sync, after and for this request, and are accepted once.
- ProVerif: seed secrecy, and injective agreement Sync→Participant on
  (request random, timer, csalt), over unbounded sessions. The response is
  authenticated but not encrypted, so timer/csalt integrity is the goal, not
  their secrecy; the request carries no tag, so the Sync does not authenticate
  the requester.
- `attack_T8_sync_impersonation` (Tamarin): a Seed Key holder can impersonate
  the Sync.
- Not modeled: delaying the response, which shifts the adopted timer and needs
  a timed model.

**Time authentication, part 2 — ongoing Sync Time Broadcast**
(`sync_broadcast.spthy` Tamarin, `sync_broadcast.pv` ProVerif)
- `broadcast_authentic` (Tamarin, ProVerif): an external attacker cannot forge
  a broadcast timer value; any adopted value was broadcast by the Sync.
- `attack_broadcast_replay_rollback`: the broadcast carries no per-receiver
  random and the receive path applies no freshness/replay check, so a recorded
  broadcast replayed later rolls the receiver's clock backward. This is
  reproduced end to end — down to AES-GCM nonce reuse on the victim's own
  outbound frames — by `poc/poc_sync_broadcast_replay.c` (build target
  `poc_sync_broadcast_replay`). The rolled-back clock also refreshes
  `timesync.last_successful`, suppressing the Sync-restart recovery abort.

**Configuration session** (`config_session.spthy` Tamarin, `config_session.pv` ProVerif)
- `key_material_secret` (Tamarin, ProVerif): write-only key registers never
  disclose key material on the read path (`attacker(keyval)` is true).
- `read_authentic_no_replay`, `terminate_authentic_no_replay`,
  `no_forged_terminate` (Tamarin, ProVerif): register reads and
  SessionTerminate are authentic, non-replayable (injective correspondence),
  and unforgeable by an external attacker.
- Abstraction: the session counter is modeled as accept-once per nonce.

**Key hierarchy** (`key_hierarchy.spthy` Tamarin, `key_hierarchy.pv` ProVerif)
- `attack_TOFU_provisioning_key`: anyone can install the Provisioning Key of
  an unprovisioned device (Zero-Key session, write-once).
- `attack_provisioning_key_eavesdropped`: a Provisioning Key written in a
  Zero-Key session is readable by a passive eavesdropper.
- `attack_seed_key_after_inband_provisioning`: the same holds for keys later
  derived under that key.
- `child_key_secrecy`, `child_key_origin`, `child_key_no_replay`
  (Tamarin, ProVerif): if the Provisioning Key is delivered out of band
  (manufacturer, as the paper assumes), Integrator and Seed Keys stay secret,
  are installed only from an honest Configurator (injective agreement on
  generation and installation across unbounded sessions), and each write is
  accepted once.
- Abstraction: the session counter is modeled as accept-once per nonce;
  message ordering, segmentation and reads are not modeled.

**Data plane** (`data_plane.spthy` Tamarin, `data_plane.pv` ProVerif)
- `group_authenticity`, `payload_secrecy` (Tamarin, ProVerif): hold against
  external attackers. A leaked Communication Key of another/compromised epoch
  does not compromise secrecy or authenticity in the active epoch.
- `attack_T3_replay`: replay is accepted without per-nonce state. The
  acceptance window, which bounds replay in time, is not modeled.
- `attack_T7_injection_by_member`: group-level authentication only.
- `attack_heartbeat_liveness_spoof`: Secure Heartbeat is AppData with no
  per-frame freshness, so a replayed heartbeat refreshes a monitor's last-seen
  timer — loss detection (`participant_check_heartbeat_timeouts`) can be
  suppressed for a node that has gone silent.
- Abstractions: epochs are public names; nonce uniqueness is assumed.

**Frame parsers** (`cbmc/parse_frame_harness.c`)
- Any frame with `len <= 64` parses and disposes with no out-of-bounds access,
  invalid pointer, overflow or leak (4704 checks, unwind 70).
- This check found a leak in `parse_sync_broadcast_frame` and
  `parse_heartbeat_broadcast_frame` on allocation failure, now fixed.

**Code update accumulator** (`cbmc/code_update_guard_harness.c`)
- The 92h multi-segment overflow guard keeps the accumulator within its
  buffer for any attacker-chosen segment length and reachable state; removing
  the guard makes the assertion fail (mutation-checked). Self-contained logic
  model: it mirrors the guard rather than linking the real function, whose
  full `Participant`/crypto struct makes CBMC exhaust memory. The buffer is
  modeled small — the guard arithmetic is identical at the real 4096.

**Timing** (`timing/AcceptanceWindow.tla`, run with TLC)
- `Reconstruct`: 12-bit timestamp reconstruction is exact whenever the true
  skew is within the unambiguous ±2^11-tick band.
- `WindowSound`: reconstruction cannot smuggle a frame outside the acceptance
  window past the window check. Run: `java -cp tla2tools.jar tlc2.TLC
  -config timing/AcceptanceWindow.cfg timing/AcceptanceWindow.tla`. Not wired
  into `run_proofs.sh`.

## Code conformance

The models rely on bindings that unit tests pin in the C code:
- The key selector in the ClientFinished AD (`tests/test_session_handshake.c`, case 4b).
- The full request random in the time-sync response AD
  (`tests/test_timesync_auth.c`, `test_client_timesync_stale_response_rejected`).
- The ClientFinished AD layout, Seed Key rejection and the register access
  policy are covered by existing tests.

## Not covered

Response-delay attacks that shift the adopted timer within the acceptance
window (needs a timed model beyond the reconstruction arithmetic in
`AcceptanceWindow.tla`); segmented register writes of non-key registers;
side channels and the reduced margin from tag truncation (partly quantified
by the CryptoVerif bound).
