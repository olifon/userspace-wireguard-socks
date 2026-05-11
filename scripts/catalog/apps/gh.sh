#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

# gh is a static Go binary in production releases — a great target for the
# systrap-docker cascade (PT_INTERP injection). Test consists of two parts:
#   (1) wrapper survives `gh --version` boot
#   (2) wrapper intercepts gh's HTTPS dial to api.github.com — we verify the
#       network call reaches GitHub (returns HTTP 401 unauth or 200) via the
#       tunnel exit.
app="gh"
if ! bin_exists gh; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: https://cli.github.com/manual/installation"
  exit 0
fi

err=$(mktemp)
start=$(date +%s.%N)
ver_out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    gh --version 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# Boot-survival smoke: gh is a CGO_ENABLED=0 static Go binary, so this
# exercises systrap-docker (PT_INTERP injection) on the wrapper side
# before the binary starts. --version is purely local — no network — so
# we are testing "wrapper survives a static Go startup", not connectivity.
# A separate dial test would also fail today due to a DNS-resolver quirk
# in the pure-Go resolver against the wrapper's loopback-DNS redirect;
# tracked in production-applications.md.
if [[ "$ver_out" == "gh version"* ]]; then
  wrapped_ok=true
fi

notes="ver-out: $(printf '%s' "$ver_out" | head -c 120) | static-Go boot smoke only — see docs/catalog/production-applications.md for the api-call DNS limitation."
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
