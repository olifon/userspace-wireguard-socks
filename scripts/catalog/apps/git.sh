#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="git"
if ! bin_exists git; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "git not in PATH"
  exit 0
fi

err=$(mktemp)
start=$(date +%s.%N)
# Clone a tiny public repo to /dev/null via wrapper. Most reliable test that
# exercises the network + sub-process tree (git launches git-remote-https,
# which launches curl).  Picks systrap-supervised because git is dynamic but
# spawns dynamic children that also need re-arming.
tmp=$(mktemp -d)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    git -c http.lowSpeedLimit=0 -c http.lowSpeedTime=0 clone --depth 1 --quiet \
    https://github.com/octocat/Hello-World.git "$tmp/repo" 2>&1) || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' <<<"$out"; then
  transport=$(grep 'auto: chose ' <<<"$out" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
if [[ -d "$tmp/repo/.git" ]]; then
  wrapped_ok=true
fi
rm -rf "$tmp"
rm -f "$err"

notes="out: $(printf '%s' "$out" | head -c 240)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
