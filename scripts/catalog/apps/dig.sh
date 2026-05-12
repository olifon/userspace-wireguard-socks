#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Real UDP test: `dig` (BIND9) DNS query over UDP. Bypasses any
# system-resolver caching by querying a specific public DNS server
# (1.1.1.1) for a known-stable record.  Tests:
#   - libc UDP socket() / sendto() / recvfrom()
#   - getsockopt/setsockopt on a UDP fd
#   - that the wrapper's force-loopback-dns redirect routes the actual
#     resolution through uwgsocks (the query is observable in the
#     daemon's /v1/resolve log if logging is enabled).
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="dig"
if ! bin_exists dig; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y dnsutils"
  exit 0
fi

err=$(mktemp)
start=$(date +%s.%N)
# Query 1.1.1.1 directly to force the UDP path (avoid 127.0.0.53 stub
# resolver which the wrapper short-circuits to /v1/resolve).
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    dig +short +time=3 +tries=1 @1.1.1.1 A example.com 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# example.com resolves to a small known set; we just check we got an IPv4
# back (one or more dotted octets on the first non-empty line).
if echo "$out" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  wrapped_ok=true
fi

notes="out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 240 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
