#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# redis-server bind() test: launch redis-server under uwgwrapper bound
# to a tunnel WG address, then dial it via wrapped redis-cli from a
# peer. Single-threaded epoll daemon — new signal vs. postgres-server
# / mongo-server / mariadb-server, which are all thread/fork-pool
# models. An epoll-on-proxied-fd bug would surface here even if the
# bigger DB daemons mask it via their per-conn fork model.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="redis-server"
if ! bin_exists redis-server || ! bin_exists redis-cli; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y redis-server redis-tools"
  exit 0
fi

REDIS_PORT="${REDIS_PORT:-$(( ( RANDOM % 10000 ) + 50000 ))}"
case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) wg_ip="10.200.0.1" ;;
  arm64)                   wg_ip="10.200.0.3" ;;
  vast)                    wg_ip="10.200.0.5" ;;
  *)                       wg_ip="10.200.0.1" ;;
esac

work=$(mktemp -d)
trap '[[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null; rm -rf "$work"' EXIT

# Avoid clashing with the system redis: redis-server takes a small
# inline config via `--option value` pairs. Disable daemonization,
# persistence, and the unix socket so we have a pure TCP-on-tunnel
# server to test.
err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
nohup "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto --allow-bind -- \
    redis-server --bind "$wg_ip" --port "$REDIS_PORT" --daemonize no \
                 --save "" --appendonly no --protected-mode no \
                 --logfile "$log_out" \
    </dev/null >/dev/null 2>"$err" &
SRVPID=$!

# Wait for the "Ready to accept connections" log line. redis prints
# this once epoll loop is running and the listener is accept(2)ing.
ready=false
for i in $(seq 1 60); do
  if grep -q 'Ready to accept connections' "$log_out" 2>/dev/null; then
    ready=true; break
  fi
  # On hub the same-host wrapped dial can't reach netstack listeners
  # (the host route to 10.200.0.1 short-circuits via host_forward to
  # 127.0.0.1 where redis isn't bound). Probe via peer ssh instead —
  # same pattern as mongo-server.sh.
  if [[ "$CATALOG_HOST" =~ ^(hub|.*amd64-host.*) ]] && (( i % 10 == 0 )); then
    PEER="${REDIS_PEER:-root@51.15.66.128}"
    PEER_API="${REDIS_PEER_API:-http://127.0.0.1:9092}"
    if ssh -o BatchMode=yes "$PEER" "timeout 3 /usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- bash -c 'exec 9<>/dev/tcp/$wg_ip/$REDIS_PORT'" >/dev/null 2>&1; then
      ready=true; break
    fi
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.3
done

redis_out=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      PEER="${REDIS_PEER:-root@51.15.66.128}"
      PEER_API="${REDIS_PEER_API:-http://127.0.0.1:9092}"
      # Send a small command sequence via wrapped redis-cli on peer.
      # Use SET then GET then DEL to actually exercise the protocol.
      redis_out=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- redis-cli -h $wg_ip -p $REDIS_PORT --no-auth-warning <<EOF
SET uwg-catalog-key hello-redis
GET uwg-catalog-key
DEL uwg-catalog-key
PING
EOF
" 2>&1) || true
      ;;
    *)
      redis_out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
          redis-cli -h "$wg_ip" -p "$REDIS_PORT" --no-auth-warning <<EOF
SET uwg-catalog-key hello-redis
GET uwg-catalog-key
DEL uwg-catalog-key
PING
EOF
) || true
      ;;
  esac
fi
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# Success = OK (SET reply) + hello-redis (GET reply) + 1 (DEL count) + PONG (PING reply)
wrapped_ok=false
if [[ "$redis_out" == *"OK"* && "$redis_out" == *"hello-redis"* && "$redis_out" == *"PONG"* ]]; then
  wrapped_ok=true
fi

notes="wg_ip=$wg_ip port=$REDIS_PORT ready=$ready | out: $(printf '%s' "$redis_out" | head -c 200) | err-tail: $(tail -c 240 $err | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
