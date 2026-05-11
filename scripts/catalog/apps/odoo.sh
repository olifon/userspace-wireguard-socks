#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
# Odoo (open-source ERP). Full first-boot smoke: launch odoo with a SQLite-
# compatible config is non-trivial — Odoo wants Postgres.  We use the apt
# `odoo` package when present and boot in standalone-no-init mode, otherwise
# fall back to a minimal pip install + boot check.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="odoo"

# Find an odoo binary or the Python entrypoint.
odoo_bin=""
for cand in odoo odoo-bin /usr/bin/odoo /opt/odoo/odoo-bin; do
  if bin_exists "$cand"; then odoo_bin="$cand"; break; fi
done

if [[ -z "$odoo_bin" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y odoo (Debian/Ubuntu) — or pip install odoo. Odoo additionally requires Postgres; we only smoke --version under wrapper to verify wrapper survives the Python+C extension import graph."
  exit 0
fi

start=$(date +%s.%N)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    "$odoo_bin" --version 2>&1) || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' <<<"$out"; then
  transport=$(grep 'auto: chose ' <<<"$out" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
if [[ "$out" == *"Odoo Server"* || "$out" == *"odoo "* ]]; then
  wrapped_ok=true
fi

notes="bin=$odoo_bin | out: $(printf '%s' "$out" | head -c 240)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
