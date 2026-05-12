#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="node"
if ! bin_exists node; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y nodejs"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/probe.js" <<'JS'
const http = require("http");
const u = new URL(process.env.PROBE_URL);
http.get({hostname: u.hostname, port: u.port||80, path: u.pathname, timeout: 10000}, r => {
  process.stdout.write(String(r.statusCode));
  r.resume();
  r.on("end", ()=>process.exit(0));
}).on("error", e=>{ console.error(e.message); process.exit(1); });
JS

err=$(mktemp)
start=$(date +%s.%N)
out=$(PROBE_URL="$MESH_PROBE_URL" "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    node "$work/probe.js" 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$out" == *"200"* || "$out" == *"204"* ]] && wrapped_ok=true

notes="out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 300 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
