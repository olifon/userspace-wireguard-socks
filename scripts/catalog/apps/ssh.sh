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
# Use hub's host-side sshd via tunnel: 10.200.0.1:22 — the hub answers with
# SSH banner on every connect. We force exit before key exchange completes.
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    timeout 8 bash -c 'echo "" | ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p 22 banner-probe@10.200.0.1 true 2>&1 | head -3' 2>"$err" || true)
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# SSH banner or "Permission denied" both mean we reached sshd through the tunnel.
if [[ "$out" == *"SSH-2.0"* || "$out" == *"Permission denied"* || "$out" == *"publickey"* || "$out" == *"protocol"* || "$out" == *"Connection closed"* ]]; then
  wrapped_ok=true
fi

notes="out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 300 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
