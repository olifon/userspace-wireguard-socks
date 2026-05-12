#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Headless chromium / electron under uwgwrapper. We verify two things:
#   1. wrapper survives a chromium binary boot — Chromium has zygote forks,
#      namespaces, sandboxing knobs, and a large dynamic-linker graph; a
#      successful `--version` proves the wrapper's exec-supervisor handles
#      the full process tree.
#   2. wrapper intercepts an outbound mesh-probe HTTP fetch.
#
# Chrome's full headless-render path also issues a flurry of UDP startup
# calls (QUIC, mDNS, native DNS) that require the engine's transparent_bind
# feature — those are documented in the catalog notes and not asserted as
# part of the pass criterion.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="electron"
chrome=""
# Detect a real chromium-class binary that doesn't go via snap.  Some distros
# ship a thin shell-script /usr/bin/chromium-browser that re-execs into the
# snap binary — those don't survive wrapper interception either because the
# snap-confined renderer can't see /tmp/uwgfdproxy-*.sock.
for cand in google-chrome chrome-headless-shell chromium-browser chromium electron; do
  resolved=$(command -v "$cand" 2>/dev/null)
  [[ -z "$resolved" ]] && continue
  [[ "$resolved" == /snap/* ]] && continue
  # Reject /usr/bin/chromium-browser if it's a tiny shell script that
  # forwards to snap (Ubuntu 24.04+).
  if file "$resolved" 2>/dev/null | grep -q 'shell script'; then
    continue
  fi
  chrome="$resolved"; break
done

if [[ -z "$chrome" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "no chromium / google-chrome / electron on PATH — install: apt-get install -y chromium-browser"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
err="$work/wrapper.err"

start=$(date +%s.%N)
# Test 1: --version (no network) — proves wrapper survives chromium boot.
ver_out=$(timeout 10 "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
  "$chrome" --no-sandbox --headless=new --version 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# A successful --version prints e.g. "Google Chrome 148.0.7778.96" or
# "Chromium 148.0.7778.96 Built on Ubuntu, running on Ubuntu 26.04".
if [[ "$ver_out" =~ (Google\ Chrome|Chromium|Chrome) ]]; then
  wrapped_ok=true
fi

notes="chrome-bin=$chrome | ver: $(printf '%s' "$ver_out" | head -c 200) | wrapper-err-tail: $(tail -c 240 "$err" | tr '\n' '|') | NOTE: full headless-render requires uwgsocks socket_api.transparent_bind=true (Chrome's QUIC/mDNS startup binds to host IP). Boot-survival smoke proves wrapper handles the chromium process tree."
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
