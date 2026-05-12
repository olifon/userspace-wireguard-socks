#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="pip"
if ! bin_exists pip3 && ! bin_exists pip && ! command -v python3 >/dev/null; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "pip not available"
  exit 0
fi

pipbin=$(command -v pip3 || command -v pip || true)
if [[ -z "$pipbin" ]]; then
  pipbin="python3 -m pip"
fi

start=$(date +%s.%N)
tmp=$(mktemp -d)
# pip on Ubuntu 24.04 noble's GH runner regressed under transport=systrap-elf
# in v0.1.7 (passes under explicit --transport=systrap, passes locally on the
# dev box). Pin to plain systrap until the pip × systrap-elf interaction is
# isolated. Tracked in memory:project_pip_systrap_elf_regression.md.
# CATALOG_TRANSPORT explicit override still wins (the multi-mode matrix
# exercises pip under each explicit mode in turn).
pip_transport="${CATALOG_TRANSPORT:-systrap}"
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport="$pip_transport" -v -- \
    bash -c "$pipbin --disable-pip-version-check download --no-deps --no-binary :all: --dest=$tmp 'six==1.16.0' 2>&1" 2>&1) || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' <<<"$out"; then
  transport=$(grep 'auto: chose ' <<<"$out" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
if compgen -G "$tmp/six-*" > /dev/null; then
  wrapped_ok=true
fi
rm -rf "$tmp"

notes="out: $(printf '%s' "$out" | head -c 240)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
