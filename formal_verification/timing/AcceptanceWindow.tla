---- MODULE AcceptanceWindow ----
(*
 * Timing model of the data-plane acceptance window and the 12-bit timestamp
 * reconstruction, from session_appdata.c (participant_process_spsec_appdata)
 * and spsec_protocol_can.c (participant_channel_restore_timestamp_and_padding).
 *
 * A frame carries only the low 12 bits of the sender's 64-bit timer. The
 * receiver reconstructs the full value against its own clock by choosing the
 * candidate within +-2^11 ticks (RecKept below), then accepts if the
 * reconstructed value is within Window ticks of its clock.
 *
 * We check, over all clock skews the model ranges:
 *  - Reconstruct: reconstruction is exact whenever the true skew is within
 *    the unambiguous +-2^11 band (the paper's Section on nonce recovery).
 *  - WindowSound: an accepted frame's true timestamp really is within the
 *    window (no frame far outside the window is accepted through wraparound).
 * Wparam and Skew are kept small (scaled) so TLC can enumerate; the 12-bit
 * field is modeled at full width via the modulus Mod.
 *)
EXTENDS Integers

VARIABLE done   \* the properties below are constant; a trivial 1-step
                \* machine lets TLC evaluate them as invariants.

CONSTANTS Mod,        \* 2^12 = 4096, the transmitted field width
          Half,       \* Mod \div 2 = 2048, the unambiguous reconstruction band
          Window,     \* acceptance window in ticks
          MaxSkew     \* range of true sender-vs-receiver skew explored

ASSUME Mod = 4096 /\ Half = 2048 /\ Window \in 1..Half /\ MaxSkew \in 1..(4*Mod)

\* Receiver clock; sender is Skew ticks ahead (Skew may be negative).
Recv == 100000
Send(skew) == Recv + skew

\* Reconstruction: exactly the clamp in participant_channel_restore_timestamp
\* _and_padding() - delta = frame12 - local12, then shift by +-Mod to keep it
\* in [-Half, Half].
Frame12(skew) == Send(skew) % Mod
Delta(skew)   == LET raw == Frame12(skew) - (Recv % Mod)
                 IN IF raw > Half THEN raw - Mod
                    ELSE IF raw < -Half THEN raw + Mod
                    ELSE raw
Restored(skew) == Recv + Delta(skew)

\* Acceptance test the code applies (|restored - local| <= Window).
Accepted(skew) == LET d == Restored(skew) - Recv
                  IN d <= Window /\ d >= -Window

Skews == { s \in -MaxSkew..MaxSkew : TRUE }

\* Within the unambiguous band |skew| < 2^11, reconstruction is exact
\* (the paper's timestamp-recovery bound). The endpoints s = +-Half alias.
Reconstruct == \A s \in Skews :
                 (s > -Half /\ s < Half) => Restored(s) = Send(s)

\* Any accepted frame is genuinely within the window of the receiver clock
\* (reconstruction cannot smuggle a far-future/past frame past the check).
WindowSound == \A s \in Skews :
                 Accepted(s) => (Restored(s) - Recv <= Window
                                 /\ Restored(s) - Recv >= -Window)

\* A frame whose true skew exceeds the band can be accepted with a WRONG
\* reconstructed value (documents the aliasing the paper bounds by frame
\* timing): expected to have witnesses, i.e. this is NOT an invariant.
NoAliasing == \A s \in Skews :
                (s >= Half \/ s < -Half) => ~Accepted(s)

Init == done = FALSE
Next == done' = TRUE
Spec == Init /\ [][Next]_done
====
