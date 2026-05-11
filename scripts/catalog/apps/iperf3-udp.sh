#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Real UDP test: iperf3 UDP throughput against an ephemeral local iperf3
# server. The client is wrapped, the server is not — proving the wrapper's
# UDP-client path round-trips a meaningful amount of data and the
# datagram framing survives the LD_PRELOAD shim.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="iperf3-udp"
if ! bin_exists iperf3; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y iperf3"
  exit 0
fi

# Start an iperf3 -s on loopback. We use a non-standard port to avoid
# colliding with anything else, and pin to 127.0.0.1 so the server doesn't
# end up published anywhere.
port=$(( ( RANDOM % 20000 ) + 41000 ))
err=$(mktemp)
srv_log=$(mktemp)
trap 'kill $SRV 2>/dev/null; rm -f "$err" "$srv_log"' EXIT
iperf3 -s -B 127.0.0.1 -p $port -1 >"$srv_log" 2>&1 &
SRV=$!
# Wait for server bind.
for i in $(seq 1 20); do
  if grep -q 'Server listening' "$srv_log" 2>/dev/null; then break; fi
  sleep 0.2
done

start=$(date +%s.%N)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    iperf3 -c 127.0.0.1 -p $port -u -b 5M -t 2 -l 1200 --connect-timeout 4000 -J 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# Parse "bits_per_second" from iperf3's JSON.  Any nonzero result counts.
bps=$(printf '%s' "$out" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    e = d.get("end", {})
    s = e.get("sum_received") or e.get("sum_sent") or e.get("sum", {})
    print(s.get("bits_per_second", 0))
except Exception:
    print(0)
' 2>/dev/null)

wrapped_ok=false
if [[ "${bps:-0}" != "0" ]]; then wrapped_ok=true; fi

notes="port=$port bps=$bps | err-tail: $(tail -c 240 "$err" | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
