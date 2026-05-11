#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
# Odoo (open-source ERP). --version boot smoke through the wrapper —
# verifies the wrapper survives Odoo's heavy Python + C-extension
# import graph (lxml, gevent/greenlet, psycopg2, cryptography, pillow,
# reportlab, Babel, …) without needing Postgres / a real database.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="odoo"

# Locate odoo. Prefer the source-built /usr/local/bin/odoo-bin (a thin
# shim into /opt/odoo/venv/bin/python + /opt/odoo/odoo/odoo-bin) over
# the apt `odoo` because Ubuntu's noble repo ships Odoo 16.0, whose
# http.py imports `werkzeug.__version__` — a constant Werkzeug 3.x
# removed. See scripts/catalog/README.md "Building Odoo from source"
# for the recipe.
odoo_bin=""
for cand in /usr/local/bin/odoo-bin /opt/odoo/odoo-bin odoo-bin odoo /usr/bin/odoo; do
  if bin_exists "$cand"; then odoo_bin="$cand"; break; fi
done

if [[ -z "$odoo_bin" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: clone Odoo from github.com/odoo/odoo at branch 18.0, set up a venv, install deps from requirements.txt (modulo Python-3.14-incompatible pins — lxml etc need latest), then symlink /opt/odoo/odoo/odoo-bin via /usr/local/bin/odoo-bin. Apt's odoo package is unusable with Werkzeug 3.x."
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

# Strict success match: Odoo's --version prints "Odoo Server X.Y" on its
# own line. The looser "odoo " substring used previously matched the
# wrapper's own log lines (which carry the path `/usr/bin/odoo`), giving
# a false-positive PASS even when Odoo crashed on import.
wrapped_ok=false
if grep -qE '^Odoo Server [0-9]+\.[0-9]+' <<<"$out"; then
  wrapped_ok=true
fi

notes="bin=$odoo_bin | out: $(printf '%s' "$out" | head -c 240)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
