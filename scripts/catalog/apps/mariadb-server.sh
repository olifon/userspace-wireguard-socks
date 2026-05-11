#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Real server-side `bind()` test: launch `mariadbd` under uwgwrapper bound
# to the host's WG tunnel address. From a peer, wrap mysql/mariadb client.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="mariadb-server"

MARIADBD=""
for cand in /usr/sbin/mariadbd /usr/sbin/mysqld /usr/bin/mariadbd; do
  [[ -x "$cand" ]] && { MARIADBD="$cand"; break; }
done
if [[ -z "$MARIADBD" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y mariadb-server"
  exit 0
fi
client=$(command -v mariadb || command -v mysql || true)
if [[ -z "$client" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "mariadb/mysql client missing"
  exit 0
fi

MARIA_PORT="${MARIA_PORT:-$(( ( RANDOM % 10000 ) + 50000 ))}"
case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) wg_ip="10.200.0.1" ;;
  arm64)                   wg_ip="10.200.0.3" ;;
  vast)                    wg_ip="10.200.0.5" ;;
  *)                       wg_ip="10.200.0.1" ;;
esac

# mariadb-install-db must run as the mysql user to chown the datadir.
DB_USER="${DB_USER:-mysql}"
if ! id -u "$DB_USER" >/dev/null 2>&1; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "no-mysql-user" 0 "mysql unix user missing"
  exit 0
fi

# AppArmor: Ubuntu's mariadbd ships with an AppArmor profile that denies
# read+mmap of /tmp/uwgwrapper-*/uwgpreload-*.so, so ld.so silently drops
# our LD_PRELOAD and the daemon runs unwrapped (kernel bind to a tunnel
# address quietly fails). Flip the profile to complain mode if it's in
# enforce mode and we have aa-complain available; otherwise document.
if command -v aa-status >/dev/null && command -v aa-complain >/dev/null; then
  if aa-status 2>/dev/null | awk '/profiles are in enforce mode/{enforce=1;next}/profiles are in complain mode/{enforce=0;next}enforce && /mariadbd/{print "yes"; exit}' | grep -q yes; then
    aa-complain /usr/sbin/mariadbd >/dev/null 2>&1 || true
  fi
fi

work=$(mktemp -d)
trap '[[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null; pkill -9 -f "mariadbd.*$work\|mysqld.*$work" 2>/dev/null; rm -rf "$work"' EXIT
chown -R "$DB_USER" "$work"

INSTALL=$(command -v mariadb-install-db || command -v mysql_install_db || true)
if [[ -z "$INSTALL" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "no-install-db" 0 "mariadb-install-db missing"
  exit 0
fi
sudo -u "$DB_USER" "$INSTALL" --datadir="$work/data" --auth-root-authentication-method=normal >>"$work/install.log" 2>&1 || {
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "install-db-failed" 0 "mariadb-install-db failed; see $work/install.log"
  exit 0
}

err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
nohup sudo -u "$DB_USER" "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v --allow-bind -- \
    "$MARIADBD" --datadir="$work/data" --bind-address="$wg_ip" --port="$MARIA_PORT" \
                --skip-networking=0 --skip-name-resolve --skip-grant-tables \
                --socket="$work/maria.sock" --pid-file="$work/maria.pid" \
                --log-error="$log_out" \
    >"$work/srv.stdout" 2>"$err" &
SRVPID=$!

ready=false
for i in $(seq 1 120); do
  if grep -q "ready for connections" "$log_out" 2>/dev/null; then
    ready=true; break
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.5
done

maria_out=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      PEER="${MARIA_PEER:-root@51.15.66.128}"
      PEER_API="${MARIA_PEER_API:-http://127.0.0.1:9092}"
      maria_out=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- mariadb -h $wg_ip -P $MARIA_PORT -u root -N -B -e \"SELECT 'maria-tunnel-ok'\" 2>&1") || true
      ;;
    *)
      maria_out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
          "$client" -h "$wg_ip" -P "$MARIA_PORT" -u root -N -B -e "SELECT 'maria-tunnel-ok'" 2>&1) || true
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
[[ "$maria_out" == *"maria-tunnel-ok"* ]] && wrapped_ok=true

notes="wg_ip=$wg_ip port=$MARIA_PORT ready=$ready | out: $(printf '%s' "$maria_out" | head -c 240) | log-tail: $(tail -c 400 $log_out 2>/dev/null | tr '\n' '|') | err-tail: $(tail -c 240 $err | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
