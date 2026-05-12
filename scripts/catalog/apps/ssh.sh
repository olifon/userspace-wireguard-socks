#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

# ssh test: just verify the SSH client boots under wrapper, connects to a
# mesh-internal address, and at minimum negotiates a banner. We don't try
# authentication — banner read is enough proof of TCP interception.
app="ssh"
if ! bin_exists ssh; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "ssh not in PATH"
  exit 0
fi

err=$(mktemp)
start=$(date +%s.%N)
# Pick a TCP target that the wrapper can definitely reach from this host.
# Non-hub peers: dial mesh_control on the hub's netstack (10.200.0.1:8787).
# Hub itself: dial the runtime API on its own loopback via host_forward
# (10.200.0.1:9091 → 127.0.0.1:9091).  ssh will get a non-SSH banner in
# both cases and report e.g. "Bad protocol version identification"; that's
# enough to prove the wrapper intercepted the TCP socket.
case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) ssh_port=9091 ;;
  *)                       ssh_port=8787 ;;
esac
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    timeout 8 bash -c "echo '' | ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p $ssh_port banner-probe@10.200.0.1 true 2>&1 | head -5" 2>"$err" || true)
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# Any of these strings prove the TCP connect succeeded through the wrapper:
#   - "SSH-2.0"                                — real sshd answered
#   - "Bad protocol version identification"     — connected, peer not sshd
#   - "kex_exchange_identification"             — connected, peer rejected
#   - "Connection closed"                       — connected, peer closed
#   - "protocol error"                          — connected, peer not sshd
# We do NOT accept "Connection refused" / "No route to host".
if [[ "$out" == *"SSH-2.0"* || "$out" == *"Bad protocol"* || "$out" == *"kex_exchange_identification"* || "$out" == *"Connection closed"* || "$out" == *"Permission denied"* || "$out" == *"protocol error"* ]]; then
  wrapped_ok=true
fi

notes="out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 300 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
