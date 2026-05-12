#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Real server-side `bind()` test: launch a postgres daemon under uwgwrapper
# bound to the host's WireGuard tunnel address. From a peer in the mesh,
# wrap psql and run a SELECT against the listener.
#
# Tests the wrapper's TCP server-bind cascade for a real fork-worker
# daemon (postmaster forks per connection). Requires daemon-side flags
# `socket_api.bind: true` and `socket_api.transparent_bind: true` on the
# uwgsocks server.
#
# Configuration via env:
#   PG_SERVER       — postgres server binary (default: first /usr/lib/postgresql/*/bin/postgres)
#   PG_PORT         — TCP port to bind on the tunnel (default 55433)
#   PG_PEER_PROBE   — ssh target that wraps psql and dials back (default: skip; sets ENV-skip)
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="postgres-server"

PG_SERVER="${PG_SERVER:-}"
if [[ -z "$PG_SERVER" ]]; then
  PG_SERVER=$(ls /usr/lib/postgresql/*/bin/postgres 2>/dev/null | head -1)
fi
if [[ -z "$PG_SERVER" || ! -x "$PG_SERVER" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y postgresql"
  exit 0
fi
if ! bin_exists psql; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "psql missing — install postgresql-client"
  exit 0
fi

PG_PORT="${PG_PORT:-55433}"
# Pick host's WG IP — same logic as udp-echo-bind.
case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) wg_ip="10.200.0.1" ;;
  arm64)                   wg_ip="10.200.0.3" ;;
  vast)                    wg_ip="10.200.0.5" ;;
  *)                       wg_ip="10.200.0.1" ;;
esac

work=$(mktemp -d)
trap '[[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null; pkill -9 -f "postgres.*$work" 2>/dev/null; rm -rf "$work"' EXIT

# Initialize a tiny postgres datadir.  initdb is a separate binary.
INITDB=$(ls /usr/lib/postgresql/*/bin/initdb 2>/dev/null | head -1)
mkdir -p "$work/data"
# Postgres refuses to run as root. Pick the system 'postgres' user and
# chown the datadir to it. Server + wrapper also run via `sudo -u postgres`
# so the process is non-root throughout.
PG_USER="${PG_USER:-postgres}"
if ! id -u "$PG_USER" >/dev/null 2>&1; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "no-pg-user" 0 \
    "postgres unix user missing; set PG_USER or apt install postgresql-common"
  exit 0
fi
chown -R "$PG_USER" "$work"
chmod 700 "$work/data"
sudo -u "$PG_USER" "$INITDB" --auth=trust -D "$work/data" -U uwg --no-locale --encoding=UTF8 >>"$work/initdb.log" 2>&1 || {
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "initdb-failed" 0 "initdb failed; see $work/initdb.log"
  exit 0
}

# Configure: listen on the WG tunnel address; no Unix socket dir
# (avoids /var/run permission needs).
cat >>"$work/data/postgresql.conf" <<EOF
listen_addresses = '$wg_ip'
unix_socket_directories = '$work/data'
port = $PG_PORT
shared_buffers = 32MB
fsync = off
synchronous_commit = off
EOF
echo "host all all 10.200.0.0/24 trust" >> "$work/data/pg_hba.conf"

# Launch postgres under wrapper.
err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
nohup sudo -u "$PG_USER" "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v --allow-bind -- \
    "$PG_SERVER" -D "$work/data" >"$log_out" 2>"$err" &
SRVPID=$!

# Wait for "database system is ready to accept connections" line.
ready=false
for i in $(seq 1 60); do
  if grep -q 'ready to accept connections' "$log_out" "$err" 2>/dev/null; then
    ready=true; break
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.5
done

# Verify connection. On the hub itself, dialing 10.200.0.1 via wrapper
# short-circuits through host_forward (→ 127.0.0.1:PG_PORT) which is NOT
# where postgres bound (netstack-side). So on the hub we use a remote
# peer to dial back through WG. On non-hub hosts the local wrapper-side
# dial works directly.
sql_out=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      # Use arm64 by default as the peer prober (unless POSTGRES_PEER set).
      PEER="${POSTGRES_PEER:-root@51.15.66.128}"
      PEER_API="${POSTGRES_PEER_API:-http://127.0.0.1:9092}"
      sql_out=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=${CATALOG_TRANSPORT:-auto} -- psql -h $wg_ip -p $PG_PORT -U uwg -d postgres -tAc \"SELECT 'pgsrv-tunnel-ok'\" 2>&1") || true
      ;;
    *)
      sql_out=$(PGPASSWORD="" "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -- \
          psql -h "$wg_ip" -p "$PG_PORT" -U uwg -d postgres -tAc "SELECT 'pgsrv-tunnel-ok'" 2>&1) || true
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
[[ "$sql_out" == *"pgsrv-tunnel-ok"* ]] && wrapped_ok=true

notes="wg_ip=$wg_ip port=$PG_PORT ready=$ready | sql: $(printf '%s' "$sql_out" | head -c 200) | log-tail: $(tail -c 400 "$log_out" | tr '\n' '|') | err-tail: $(tail -c 240 "$err" | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
