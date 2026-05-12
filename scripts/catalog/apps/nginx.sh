#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

# nginx test: launch nginx in foreground (`daemon off`) under wrapper, hit
# it with curl on loopback, verify the response comes back, then SIGTERM.
# Tests that the worker-fork model survives systrap-supervised execve.
app="nginx"
if ! bin_exists nginx; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y nginx"
  exit 0
fi

cfgdir=$(mktemp -d)
port=$(( ( RANDOM % 20000 ) + 30000 ))
err="$cfgdir/wrapper.err"
trap 'kill -9 $WPID 2>/dev/null; pkill -9 -f "nginx.*$cfgdir" 2>/dev/null; rm -rf "$cfgdir"' EXIT

cat >"$cfgdir/nginx.conf" <<EOF
worker_processes 1;
pid $cfgdir/nginx.pid;
error_log stderr;
daemon off;
events { worker_connections 64; }
http {
  access_log off;
  server {
    listen 127.0.0.1:$port;
    location = /probe { return 200 "uwgwrapper-nginx-ok\n"; }
  }
}
EOF

start=$(date +%s.%N)
"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    nginx -c "$cfgdir/nginx.conf" -p "$cfgdir/" 2>"$err" >/dev/null </dev/null &
WPID=$!

# Wait up to 8s for nginx to bind and start serving.
ok_resp=""
for i in $(seq 1 16); do
  sleep 0.5
  if ! kill -0 $WPID 2>/dev/null; then break; fi
  ok_resp=$(curl -sS --max-time 1 http://127.0.0.1:$port/probe 2>/dev/null) && break || true
done
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

# Tear down.
kill -TERM $WPID 2>/dev/null
sleep 0.5
kill -9 $WPID 2>/dev/null

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$ok_resp" == *"uwgwrapper-nginx-ok"* ]] && wrapped_ok=true

notes="port=$port resp: $(printf '%s' "$ok_resp" | head -c 80) | err-tail: $(tail -c 300 "$err" | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
