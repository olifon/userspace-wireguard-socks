# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# scripts/catalog/lib.sh
# Shared helpers for the production-application catalog harness.

set -u
set -o pipefail

: "${CATALOG_HOST:=$(hostname -s)}"

# Probe target — uniformly a "tunnel-only" address but the listener differs by
# host. On the hub the destination 10.200.0.1 is rewritten to 127.0.0.1 by
# `inbound.transparent:true` host_forward, so we point at the hub's runtime
# API (which is bound to 127.0.0.1:9091). On non-hub hosts the WG packet
# survives all the way to the hub's netstack listeners, so we point at the
# mesh-control endpoint (bound inside netstack on 10.200.0.1:8787). Either
# way, dialing the URL without the wrapper fails on every host.
if [[ -z "${MESH_PROBE_URL:-}" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*) MESH_PROBE_URL="http://10.200.0.1:9091/v1/status" ;;
    *)                       MESH_PROBE_URL="http://10.200.0.1:8787/v1/peers" ;;
  esac
fi
: "${RESULTS_DIR:=$(dirname "${BASH_SOURCE[0]}")/results/${CATALOG_HOST}}"
: "${UWGSOCKS_API:=http://127.0.0.1:9091}"
: "${UWGWRAPPER_BIN:=$(dirname "${BASH_SOURCE[0]}")/../../uwgwrapper}"
: "${UWGSOCKS_BIN:=$(dirname "${BASH_SOURCE[0]}")/../../uwgsocks}"
: "${PROBE_TIMEOUT:=8}"

mkdir -p "$RESULTS_DIR"

log() { printf '%s [%s] %s\n' "$(date -u +%H:%M:%SZ)" "$CATALOG_HOST" "$*" >&2; }

# wrap_cmd <cmd...> — emits the full uwgwrapper invocation we use.
wrap_cmd() {
  local args=("$UWGWRAPPER_BIN" "--api=$UWGSOCKS_API" "--transport=auto" "-v")
  printf '%q ' "${args[@]}" "$@"
}

# wrapped <cmd...> — run cmd via uwgwrapper, return its exit status.
wrapped() {
  "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto "$@"
}

# wrapped_v <cmd...> — verbose wrapper run; emits transport selection to stderr.
wrapped_v() {
  "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v "$@"
}

# probe_unwrapped — direct probe of the mesh endpoint; must FAIL on every
# host (because the WG interface lives in netstack and is not in the host
# routing table).
probe_unwrapped() {
  curl --connect-timeout "$PROBE_TIMEOUT" -sS -o /dev/null -w '%{http_code}' \
    "$MESH_PROBE_URL" 2>/dev/null
}

# probe_wrapped — same probe through uwgwrapper.
probe_wrapped() {
  wrapped curl --connect-timeout "$PROBE_TIMEOUT" -sS -o /dev/null \
    -w '%{http_code}' "$MESH_PROBE_URL" 2>/dev/null
}

# extract_transport <wrapper-stderr> — parse the auto-cascade decision.
extract_transport() {
  awk -F'[][]' '/transport:/ {
    for (i=1;i<=NF;i++) if ($i ~ /^transport:/) { sub(/^transport: */,"",$i); print $i; exit }
  } /selecting transport/ { sub(/.*selecting transport[ ]+/,""); print; exit }' "$1" 2>/dev/null \
    | head -1
}

# record_result <app> <wrapped_ok> <unwrapped_blocked> <transport> <duration_s> <notes>
record_result() {
  local app="$1" wrapped_ok="$2" unwrapped_blocked="$3" transport="$4" dur="$5" notes="$6"
  local out="$RESULTS_DIR/${app}.json"
  cat >"$out" <<EOF
{
  "host": "$CATALOG_HOST",
  "app": "$app",
  "transport": "$transport",
  "wrapped_ok": $wrapped_ok,
  "unwrapped_blocked": $unwrapped_blocked,
  "duration_seconds": $dur,
  "notes": $(printf '%s' "$notes" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
}
EOF
  log "$app -> wrapped_ok=$wrapped_ok unwrapped_blocked=$unwrapped_blocked transport=${transport:-?} ($dur s)"
}

# bin_exists <name> — does the binary exist in PATH?
bin_exists() { command -v "$1" >/dev/null 2>&1; }

# require_unwrapped_blocked — asserts the bare-host probe fails. We want the
# catalog to be a real test, not a no-op.
require_unwrapped_blocked() {
  local code
  code="$(probe_unwrapped || true)"
  if [[ "$code" != "000" && "$code" != "" ]]; then
    log "WARNING: unwrapped probe returned HTTP $code — environment may not be a clean test."
    echo "false"
  else
    echo "true"
  fi
}

# run_wrapped_capture <stderr_file> <cmd...> — run wrapper, capture stderr.
run_wrapped_capture() {
  local err="$1"; shift
  "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v "$@" 2>"$err"
}
