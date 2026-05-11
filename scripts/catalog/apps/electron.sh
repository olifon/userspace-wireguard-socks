#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
# Electron (or plain headless chromium) test: navigates to the mesh probe URL
# and verifies it could fetch it.  Uses --no-sandbox because the wrapper's
# fdproxy lives outside the renderer sandbox.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="electron"
chrome=""
for cand in chromium chromium-browser google-chrome chrome chrome-headless-shell electron; do
  if bin_exists "$cand"; then chrome="$cand"; break; fi
done

if [[ -z "$chrome" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "no chromium/electron/chrome on PATH — install: apt-get install -y chromium-browser OR snap install chromium"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

start=$(date +%s.%N)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
  "$chrome" --no-sandbox --headless=new --disable-gpu --user-data-dir="$work/userdata" \
  --dump-dom --virtual-time-budget=5000 "$MESH_PROBE_URL" 2>&1) || rc=$?
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' <<<"$out"; then
  transport=$(grep 'auto: chose ' <<<"$out" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# A successful fetch of either probe URL produces JSON containing "running":true (for /v1/status) or peer list.
wrapped_ok=false
if [[ "$out" == *"running"* || "$out" == *"public_key"* || "$out" == *"\"peers\""* ]]; then
  wrapped_ok=true
fi

# Capture only a slice — chromium output can be huge.
notes="chrome-bin=$chrome | out-slice: $(printf '%s' "$out" | tr '\n' '|' | head -c 600)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
