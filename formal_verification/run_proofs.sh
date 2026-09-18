#!/usr/bin/env bash

#
# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.
#

# Run formal models and verify expected proof outcomes.
set -u
cd "$(dirname "$0")"
TAMARIN=${TAMARIN:-tamarin-prover}
PROVERIF=${PROVERIF:-proverif}
fail=0
if command -v "$TAMARIN" >/dev/null; then
  for f in *.spthy; do
    out=$("$TAMARIN" --prove "$f" 2>&1)
    summary=$(grep -E '(verified|falsified|analysis incomplete) \(' <<<"$out")
    echo "== $f"; echo "$summary"
    [ -z "$summary" ] && fail=1
    grep -q 'analysis incomplete' <<<"$summary" && fail=1
    grep -q 'falsified' <<<"$summary" && fail=1
  done
else
  echo "== tamarin-prover: not found (skipping *.spthy)"
fi

if command -v "$PROVERIF" >/dev/null; then
  for f in *.pv; do
    results=$("$PROVERIF" "$f" 2>&1 | grep '^RESULT')
    echo "== $f"; echo "$results"
    [ -z "$results" ] && fail=1
    grep '^RESULT not event' <<<"$results" | grep -qv 'is false\.$' && fail=1
    grep -v '^RESULT not event' <<<"$results" | grep -qv 'is true\.$' && fail=1
  done
else
  echo "== proverif: not found (skipping *.pv)"
fi

# CRYPTOVERIF_LIB: path to CryptoVerif's default library, without .cvl
CRYPTOVERIF=${CRYPTOVERIF:-cryptoverif}
if [ -z "${CRYPTOVERIF_LIB:-}" ]; then
  if [ -f "/opt/cryptoverif/default.cvl" ]; then
    CRYPTOVERIF_LIB="/opt/cryptoverif/default"
  elif [ -f "/usr/local/share/cryptoverif/default.cvl" ]; then
    CRYPTOVERIF_LIB="/usr/local/share/cryptoverif/default"
  fi
fi

if command -v "$CRYPTOVERIF" >/dev/null && [ -n "${CRYPTOVERIF_LIB:-}" ]; then
  for f in *.pcv; do
    out=$("$CRYPTOVERIF" -lib "$CRYPTOVERIF_LIB" "$f" 2>&1)
    echo "== $f"; grep -E '^RESULT (Proved|Could)|^All queries proved' <<<"$out"
    grep -q '^All queries proved' <<<"$out" || fail=1
  done
else
  echo "== cryptoverif: not found or CRYPTOVERIF_LIB not set (skipping *.pcv)"
fi
CBMC=${CBMC:-cbmc}
if command -v "$CBMC" >/dev/null; then
  echo "== cbmc/parse_frame_harness.c"
  out=$(cd .. && "$CBMC" formal_verification/cbmc/parse_frame_harness.c \
    spsec_can_protocol/spsec_protocol_can.c spsec_can_protocol/protocol_handshake.c \
    spsec_can_protocol/protocol_register.c spsec_can_protocol/protocol_session.c \
    common/messages_core.c common/messages_handshake.c common/messages_register.c \
    common/messages_session.c common/spsec_common.c \
    -I common/include -I common/hal/include -I spsec_can_protocol/include -I spsec_can_protocol \
    --bounds-check --pointer-check --memory-leak-check --pointer-overflow-check \
    --div-by-zero-check --signed-overflow-check --unwind 70 --unwinding-assertions 2>&1)
  grep -E '^\*\* [0-9]+ of|^VERIFICATION' <<<"$out"
  grep -q '^VERIFICATION SUCCESSFUL' <<<"$out" || fail=1

  echo "== cbmc/code_update_guard_harness.c"
  out=$("$CBMC" cbmc/code_update_guard_harness.c \
    --bounds-check --pointer-check --unwind 300 --unwinding-assertions 2>&1)
  grep -E '^\*\* [0-9]+ of|^VERIFICATION' <<<"$out"
  grep -q '^VERIFICATION SUCCESSFUL' <<<"$out" || fail=1
else
  echo "== cbmc: not found (skipping CBMC harnesses)"
fi

exit $fail
