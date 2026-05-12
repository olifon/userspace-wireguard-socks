#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Real UDP test: NTP query over UDP port 123.  Uses `sntp` if available
# (small/portable), else falls back to a hand-rolled python NTP request
# so we don't depend on the host having an ntp toolchain installed.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="ntp"
err=$(mktemp)
start=$(date +%s.%N)

# Path 1: `ntpdig` (ntpsec) — one-shot SNTP query; the cleanest CLI for
# tunneling tests. Path 2: legacy `sntp`. Path 3: `ntpdate -q`. Path 4:
# hand-rolled python NTP client.
if bin_exists ntpdig; then
  out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
      ntpdig -t 4 pool.ntp.org 2>"$err") || true
  tool=ntpdig
elif bin_exists sntp; then
  out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
      sntp -K /dev/null -t 4 pool.ntp.org 2>"$err") || true
  tool=sntp
elif bin_exists ntpdate; then
  out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
      ntpdate -q -t 4 pool.ntp.org 2>"$err") || true
  tool=ntpdate
else
  # Hand-rolled python NTP client — sends a 48-byte UDP packet to NTP
  # server, parses the 32-bit seconds since 1900 from the response.
  cat > "$err.py" <<'PY'
import socket, struct, sys, time
NTP_EPOCH = 2208988800
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
pkt = bytes([0x1B]) + b"\x00" * 47
s.sendto(pkt, ("pool.ntp.org", 123))
data, _ = s.recvfrom(48)
secs = struct.unpack("!I", data[40:44])[0] - NTP_EPOCH
delta = abs(time.time() - secs)
print(f"ntp_epoch={secs} delta={delta:.1f}s")
PY
  out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
      python3 "$err.py" 2>"$err") || true
  tool=python-ntp
  rm -f "$err.py"
fi

end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# ntpdig + sntp both print "<offset> +/- <jitter> <host> <ip> s<stratum> ..."
# on a successful query.
if [[ "$out" =~ \+/-\  ]]; then wrapped_ok=true; fi
case "$tool" in
  ntpdate)     [[ "$out" == *"server"* || "$out" == *"adjust"* ]] && wrapped_ok=true ;;
  python-ntp)  [[ "$out" == *"ntp_epoch="* ]] && wrapped_ok=true ;;
esac

notes="tool=$tool | out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 240 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
