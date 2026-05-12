#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Real QUIC (UDP) test: curl --http3 against a known-HTTP/3 endpoint.
# Cloudflare's edge serves HTTP/3 on cloudflare-quic.com. Requires a curl
# build that links libcurl-http3 (e.g., apt's curl on Ubuntu 26+ has it).
# A failed --http3 negotiation falls back silently to TCP/HTTPS; we
# disable that with --http3-only so a wrapper-side UDP rejection is
# observable.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="curl-http3"
# Prefer a side-installed HTTP/3-capable curl over the distro one — Ubuntu's
# stock curl up through 26.04 LTS doesn't ship HTTP/3 (no nghttp3 link).
# /opt/http3/bin/curl is the build artifact from the recipe documented in
# the README ("Building HTTP/3-capable curl").
CURL_BIN=""
for cand in /usr/local/bin/curl-http3 /opt/http3/bin/curl /usr/bin/curl; do
  if [[ -x "$cand" ]] && "$cand" -V 2>&1 | grep -qi 'HTTP3'; then
    CURL_BIN="$cand"
    break
  fi
done
if [[ -z "$CURL_BIN" ]]; then
  if ! bin_exists curl; then
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y curl"
    exit 0
  fi
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-http3 0 \
    "curl on this host has no HTTP/3 protocol support. Build curl with OpenSSL 3.5+ QUIC API + nghttp3 (see scripts/catalog/README.md)."
  exit 0
fi

err=$(mktemp)
start=$(date +%s.%N)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    "$CURL_BIN" --http3-only --ipv4 -sS --max-time 10 -o /dev/null -w '%{http_version}|%{http_code}\n' \
    https://cloudflare-quic.com/ 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# curl prints "3|200" if HTTP/3 negotiated to a 200 response.
if [[ "$out" == 3* && "$out" == *200* ]]; then
  wrapped_ok=true
fi

notes="out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 240 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
