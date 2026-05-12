#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Odoo 18 upstream test suite — wrapped end-to-end.
#
# What this exercises:
#   odoo-bin --test-enable -i base runs the test suite shipped with
#   the `base` module + every dependency module that gets loaded.
#   Latest count is 1329 tests across ~12 modules: ORM, ACL, RPC,
#   field types, computed fields, model inheritance, the test
#   infrastructure itself. Real upstream tests, maintained by Odoo
#   SA and the community. No happy-path smoke.
#
#   The wrapper has to carry:
#     - psycopg2 binary's TCP connection pool to postgres
#     - all of Python's HTTP/ssl machinery (some tests mock these
#       in-process)
#     - subprocess.run for the test runner's own machinery
#     - threading + concurrent test execution
#     - heavy import graph (lxml, gevent, cryptography, pillow,
#       reportlab, jinja, …)
#
# Pass criterion: wrapped pass-count matches the unwrapped baseline
# exactly. Unwrapped baseline on this host is 1315 pass + 2 fail + 12
# error = 1329 total. The 14 failures/errors are env-dependent
# (mail server, browser-side tests, demo data we explicitly skip),
# NOT wrapper-caused; they happen unwrapped too. Pass iff
#
#     wrapped_total == baseline_total AND
#     wrapped_failed == baseline_failed AND
#     wrapped_errored == baseline_errored
#
# If the wrapper regresses any test that passes unwrapped, this
# trips immediately. That's the regression contract.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="test-odoo-suite"

# Odoo runs via the venv python + the real odoo-bin script (not the
# /usr/local/bin/odoo-bin shim, which is itself a shell wrapper that
# invokes python). Source-built path is /opt/odoo/odoo/odoo-bin.
odoo_py=/opt/odoo/venv/bin/python
odoo_bin=/opt/odoo/odoo/odoo-bin
if [[ ! -x "$odoo_py" || ! -f "$odoo_bin" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: see scripts/catalog/README.md 'Building Odoo from source' AND /opt/odoo/venv/bin/pip install freezegun"
  exit 0
fi
if ! pg_isready -q 2>/dev/null; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-postgres 0 "postgres not running"
  exit 0
fi
if ! /opt/odoo/venv/bin/python -c 'import freezegun' >/dev/null 2>&1; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: /opt/odoo/venv/bin/pip install freezegun"
  exit 0
fi

DB="uwgodootest$$"
work=$(mktemp -d)
out_unwrapped="$work/unwrapped.log"
out_wrapped="$work/wrapped.log"
err="$work/wrapper.err"
trap 'sudo -u postgres dropdb --if-exists "$DB" 2>/dev/null; rm -rf "$work"' EXIT

extract_counts() {
  # Returns "TOTAL FAILED ERRORED" from a single line like
  # "ERROR uwg... 2 failed, 12 error(s) of 1329 tests when loading"
  # Field map: "2 failed, 12 error(s) of 1329 tests"
  #             $1 $2     $3 $4    $5 $6   $7
  local file=$1
  grep -oE '[0-9]+ failed, [0-9]+ error\(s\) of [0-9]+ tests' "$file" 2>/dev/null \
    | head -1 \
    | awk '{print $6, $1, $3}'
}

start=$(date +%s.%N)

# 1. Unwrapped baseline (fresh DB per run so we have a deterministic
# comparison; init+test takes ~50-90s).
sudo -u postgres dropdb --if-exists "$DB" 2>/dev/null
"$odoo_py" "$odoo_bin" \
    --no-http -d "$DB" -i base --test-enable \
    --db_host 127.0.0.1 --db_port 5432 --db_user odoo --db_password odoo \
    --without-demo=all --stop-after-init >"$out_unwrapped" 2>&1 || true

baseline=$(extract_counts "$out_unwrapped")
sudo -u postgres dropdb --if-exists "$DB" 2>/dev/null

# 2. Wrapped run on a fresh DB. Combine stdout+stderr into one log —
# Odoo's INFO logger writes the "N failed, M error(s) of T tests"
# summary to stderr, and we grep for it below.
"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    "$odoo_py" "$odoo_bin" \
    --no-http -d "$DB" -i base --test-enable \
    --db_host 127.0.0.1 --db_port 5432 --db_user odoo --db_password odoo \
    --without-demo=all --stop-after-init >"$out_wrapped" 2>&1 || true
# Copy the wrapper auto-cascade line into $err so the transport-
# detection grep below still works.
grep -E '^uwgwrapper:' "$out_wrapped" >"$err" 2>/dev/null || true

wrapped=$(extract_counts "$out_wrapped")
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# Also accept the special case where Odoo logs the SUCCESS line for
# the whole test run rather than the "N failed, M error(s) of T" form
# (happens when 0 failures, 0 errors). Treat that as "T 0 0".
if [[ -z "$baseline" ]]; then
  if grep -q 'odoo.modules.loading: Modules loaded\.' "$out_unwrapped"; then
    base_total=$(grep -oE '[0-9]+ tests when' "$out_unwrapped" | head -1 | awk '{print $1}')
    if [[ -z "$base_total" ]]; then base_total="0"; fi
    baseline="$base_total 0 0"
  fi
fi
if [[ -z "$wrapped" ]]; then
  if grep -q 'odoo.modules.loading: Modules loaded\.' "$out_wrapped"; then
    w_total=$(grep -oE '[0-9]+ tests when' "$out_wrapped" | head -1 | awk '{print $1}')
    if [[ -z "$w_total" ]]; then w_total="0"; fi
    wrapped="$w_total 0 0"
  fi
fi

wrapped_ok=false
if [[ -n "$baseline" && "$baseline" == "$wrapped" ]]; then
  wrapped_ok=true
fi

notes="baseline={$baseline} wrapped={$wrapped} | wrapped-tail: $(tail -c 200 $out_wrapped 2>/dev/null | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
