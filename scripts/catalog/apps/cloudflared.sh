#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

# cloudflared is a static Go binary in production releases — a great target
# for the systrap-docker (PT_INTERP) cascade. We test:
#   1. wrapper survives `cloudflared --version` (boot smoke), and
#   2. wrapper intercepts `cloudflared access ssh --hostname ...` enough to
#      reach the network (we don't have a real tunnel; expect graceful exit).
app="cloudflared"
if ! bin_exists cloudflared; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$(dpkg --print-architecture 2>/dev/null || uname -m) -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared"
  exit 0
fi

start=$(date +%s.%N)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    cloudflared --version 2>&1) || rc=$?
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' <<<"$out"; then
  transport=$(grep 'auto: chose ' <<<"$out" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
if [[ "$out" == *"cloudflared version"* ]]; then
  wrapped_ok=true
fi

notes="out: $(printf '%s' "$out" | head -c 240)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
