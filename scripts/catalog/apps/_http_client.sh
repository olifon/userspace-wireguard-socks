# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Shared body for HTTP-client style catalog tests.
# Callers set:
#   app_name  — short slug (matches result file)
#   app_bin   — binary name on PATH (or full path)
#   build_cmd — string used to render the in-app HTTP fetch; the script
#               interpolates the probe URL and expects HTTP-200 on stdout.
# Optional:
#   install_hint — printed if app_bin not found.

set -u
cd "$(dirname "$0")/.."
. ./lib.sh

run_http_client_test() {
  local app="$1" bin="$2"; shift 2
  local cmd_template="$*"

  if ! bin_exists "$bin"; then
    record_result "$app" false true "missing-bin" 0 "binary not found in PATH ($bin); install hint: ${install_hint:-}"
    return 0
  fi

  local err
  err=$(mktemp)
  local start; start=$(date +%s.%N)
  local rendered_cmd; rendered_cmd=$(printf '%s' "$cmd_template" | sed "s|@URL@|$MESH_PROBE_URL|g")
  # shellcheck disable=SC2086
  local out
  if out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- bash -c "$rendered_cmd" 2>"$err"); then
    rc=0
  else
    rc=$?
  fi
  local end; end=$(date +%s.%N)
  local dur; dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

  # Auto cascade picks the transport; parse the "auto: chose ..." log line.
  local transport=""
  if grep -q 'auto: chose ' "$err"; then
    transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
  fi

  local wrapped_ok=false
  if [[ "$out" == *"200"* || "$out" == *"204"* ]] && [[ $rc -eq 0 ]]; then
    wrapped_ok=true
  fi

  local notes
  notes="cmd: $rendered_cmd | rc=$rc | out: $(printf '%s' "$out" | head -c 120) | stderr-tail: $(tail -c 400 "$err" | tr '\n' '|')"
  rm -f "$err"

  record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
  [[ "$wrapped_ok" == "true" ]]
}
