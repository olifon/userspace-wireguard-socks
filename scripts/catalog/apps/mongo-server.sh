#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Real server-side `bind()` test: launch `mongod` under uwgwrapper bound
# to the host's WG tunnel address. From a peer, wrap mongosh and dial.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="mongo-server"

MONGOD=""
for cand in /usr/bin/mongod /usr/local/bin/mongod; do
  [[ -x "$cand" ]] && { MONGOD="$cand"; break; }
done
if [[ -z "$MONGOD" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: mongodb-org server (https://www.mongodb.com/docs/manual/installation/)"
  exit 0
fi
client=$(command -v mongosh || command -v mongo || true)
if [[ -z "$client" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "mongosh missing"
  exit 0
fi

MONGO_PORT="${MONGO_PORT:-$(( ( RANDOM % 10000 ) + 50000 ))}"
case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) wg_ip="10.200.0.1" ;;
  arm64)                   wg_ip="10.200.0.3" ;;
  vast)                    wg_ip="10.200.0.5" ;;
  *)                       wg_ip="10.200.0.1" ;;
esac

work=$(mktemp -d)
trap '[[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null; pkill -9 -f "mongod.*$work" 2>/dev/null; rm -rf "$work"' EXIT

mkdir -p "$work/data"

err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
# Note: do NOT pass `-v` to the wrapper — it produces a stream of fdproxy
# diagnostics that can stall mongod's stderr drain under nohup, making
# the listener loop never wake. The catalog harness reads the wrapper's
# auto-cascade decision via the env-gated UWGS_PRELOAD_TRACE instead.
nohup "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} --allow-bind -- \
    "$MONGOD" --bind_ip "$wg_ip" --port "$MONGO_PORT" --dbpath "$work/data" \
              --noauth --nounixsocket --logpath "$log_out" \
    </dev/null >/dev/null 2>/dev/null &
SRVPID=$!

ready=false
# mongod 8.0 cold-start under wrapper takes longer than its baseline
# (WiredTiger init + FTDC init each adds latency). Probe TWO ways:
#   - the canonical "Waiting for connections" log line (the mongod log
#     is sometimes flushed late, so we can't rely on it alone);
#   - a real wrapped dial to the tunnel-bound listener (mongod is bound
#     to $wg_ip:$MONGO_PORT inside netstack, NOT to 127.0.0.1 — a bare
#     `/dev/tcp/127.0.0.1/PORT` probe always fails for the wrapped case).
for i in $(seq 1 240); do
  if grep -q 'Waiting for connections' "$log_out" 2>/dev/null; then
    ready=true; break
  fi
  # mongod's listener typically comes up BEFORE the "Waiting for
  # connections" log line is flushed to disk. From the hub itself,
  # a wrapped dial to the tunnel addr short-circuits through
  # host_forward → 127.0.0.1, where mongod ISN'T bound, so we can't
  # probe locally. Probe via the arm64 peer instead — that's the same
  # path the final mongosh test takes anyway. Every 15s.
  if [[ "$CATALOG_HOST" =~ ^(hub|.*amd64-host.*) ]] && (( i % 30 == 0 )); then
    PEER="${MONGO_PEER:-root@51.15.66.128}"
    PEER_API="${MONGO_PEER_API:-http://127.0.0.1:9092}"
    if ssh -o BatchMode=yes "$PEER" "timeout 3 /usr/local/bin/uwgwrapper --api=$PEER_API --transport=${CATALOG_TRANSPORT:-auto} -- bash -c 'exec 9<>/dev/tcp/$wg_ip/$MONGO_PORT'" >/dev/null 2>&1; then
      ready=true; break
    fi
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.5
done

mongo_out=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      PEER="${MONGO_PEER:-root@51.15.66.128}"
      PEER_API="${MONGO_PEER_API:-http://127.0.0.1:9092}"
      mongo_out=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=${CATALOG_TRANSPORT:-auto} -- mongosh --quiet 'mongodb://$wg_ip:$MONGO_PORT/test' --eval 'JSON.stringify(db.runCommand({ping:1}))' 2>&1") || true
      ;;
    *)
      mongo_out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -- \
          "$client" --quiet "mongodb://$wg_ip:$MONGO_PORT/test" --eval 'JSON.stringify(db.runCommand({ping:1}))' 2>&1) || true
      ;;
  esac
fi
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$mongo_out" == *'"ok":1'* || "$mongo_out" == *'ok: 1'* ]] && wrapped_ok=true

notes="wg_ip=$wg_ip port=$MONGO_PORT ready=$ready | out: $(printf '%s' "$mongo_out" | head -c 240) | log-tail: $(tail -c 400 $log_out 2>/dev/null | tr '\n' '|') | err-tail: $(tail -c 240 $err | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
