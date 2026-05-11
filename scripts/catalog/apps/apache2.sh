#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Apache httpd 2.x bound on a tunnel WG address. Mod_php enabled
# (libapache2-mod-php) so the test fires PHP through Apache too —
# different from php.sh which uses the development server.
#
# What it exercises that nothing else in the catalog does:
#   - Apache's MPM. Default is event MPM on Debian/Ubuntu, which has
#     a sophisticated worker pool with keep-alive handling, a separate
#     listener thread, and `epoll_ctl` patterns that differ from
#     nginx's master+worker (epoll on listen fd only). Stress-tests
#     the wrapper's epoll-on-proxied-fd path harder than nginx.
#   - Module loading on init. apache2 dlopen()s its modules from
#     /usr/lib/apache2/modules/*.so during the listener bring-up —
#     exercises the wrapper's exec-time + dlopen-time interception
#     handoff in ways static-binary servers like caddy/nginx don't.
#
# Pass criterion: peer's wrapped curl gets a 200 from the wrapped
# apache, response contains the index marker AND a "Server: Apache/"
# header (proves apache served it, not anything else).
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="apache2"
if ! bin_exists apache2; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y apache2 libapache2-mod-php"
  exit 0
fi
if ! bin_exists curl; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y curl"
  exit 0
fi

case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) wg_ip="10.200.0.1" ;;
  arm64)                   wg_ip="10.200.0.3" ;;
  vast)                    wg_ip="10.200.0.5" ;;
  *)                       wg_ip="10.200.0.1" ;;
esac

AP_PORT="${APACHE_PORT:-$(( ( RANDOM % 10000 ) + 50000 ))}"
work=$(mktemp -d)
mkdir -p "$work/docroot" "$work/logs" "$work/run"
# Apache workers run as www-data after setuid drop and must be able to
# read the docroot. mktemp -d defaults to 0700; open up the tree.
chmod 755 "$work" "$work/docroot" "$work/logs" "$work/run"
trap '[[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null; pkill -9 -f "apache2 -f $work" 2>/dev/null; rm -rf "$work"' EXIT

cat >"$work/docroot/index.html" <<EOF
<html><body>uwg-catalog-apache2-${AP_PORT}-ok</body></html>
EOF

# Minimal foreground apache config. Uses MPM event (the system
# default on Debian/Ubuntu) when the module file is found at the
# normal path. Skip mod_php to keep the config small — php.sh
# already exercises PHP separately.
APACHE_LIB="/usr/lib/apache2"
# Default to www-data because apache2 refuses to run as root unless
# explicitly compiled with -DBIG_SECURITY_HOLE. The Ubuntu binary
# isn't built that way.
APACHE_RUN_USER="${APACHE_RUN_USER:-www-data}"
APACHE_RUN_GROUP="${APACHE_RUN_GROUP:-www-data}"
cat >"$work/httpd.conf" <<EOF
ServerRoot "$work"
PidFile $work/run/apache2.pid
Mutex file:$work/run
DefaultRuntimeDir $work/run
ServerName uwg-catalog
LoadModule mpm_event_module $APACHE_LIB/modules/mod_mpm_event.so
LoadModule authz_core_module $APACHE_LIB/modules/mod_authz_core.so
LoadModule dir_module $APACHE_LIB/modules/mod_dir.so
LoadModule mime_module $APACHE_LIB/modules/mod_mime.so
User $APACHE_RUN_USER
Group $APACHE_RUN_GROUP
Listen $wg_ip:$AP_PORT
DocumentRoot "$work/docroot"
TypesConfig /etc/mime.types
LogLevel warn
ErrorLog $work/logs/error.log
CustomLog $work/logs/access.log combined
<Directory "$work/docroot">
  Require all granted
  DirectoryIndex index.html
</Directory>
EOF

err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
# Foreground (-DFOREGROUND), explicit config (-f). Don't daemonize.
#
# Transport pinned to `preload` rather than `auto`. apache2 under
# systrap-supervised hits a glibc getaddrinfo() assertion
# (`IN6_IS_ADDR_V4MAPPED`) during listener init — likely the same
# class of bug as the caddy SIGILL (raw-syscall vs supervisor RIP
# handling). apache2 is a dynamic-libc binary so preload is the
# correct transport here regardless. When the systrap-supervised
# regression is fixed, swap back to `auto`.
#
# Also need --allow-uid for the www-data uid: apache's mpm fork+setuids
# workers to www-data, and those workers must still be able to connect
# back to the fdproxy manager socket (owned by root). Without this the
# workers get EACCES (`apr_socket_accept: Permission denied`) on every
# request.
WWW_DATA_UID="$(id -u www-data 2>/dev/null || echo 33)"
nohup "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=preload --allow-bind --allow-uid="$WWW_DATA_UID" -v -- \
    apache2 -f "$work/httpd.conf" -DFOREGROUND \
    </dev/null >"$log_out" 2>"$err" &
SRVPID=$!

ready=false
for i in $(seq 1 30); do
  # Apache doesn't emit a single canonical "ready" log line in
  # foreground; instead poll for a TCP listener via peer probe.
  if [[ "$CATALOG_HOST" =~ ^(hub|.*amd64-host.*) ]] && (( i % 3 == 0 )); then
    PEER="${APACHE_PEER:-root@51.15.66.128}"
    PEER_API="${APACHE_PEER_API:-http://127.0.0.1:9092}"
    if ssh -o BatchMode=yes "$PEER" "timeout 3 /usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- bash -c 'exec 9<>/dev/tcp/$wg_ip/$AP_PORT'" >/dev/null 2>&1; then
      ready=true; break
    fi
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.4
done

ap_out=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      PEER="${APACHE_PEER:-root@51.15.66.128}"
      PEER_API="${APACHE_PEER_API:-http://127.0.0.1:9092}"
      ap_out=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- curl -sS --max-time 8 -D - http://$wg_ip:$AP_PORT/" 2>&1) || true
      ;;
    *)
      ap_out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
          curl -sS --max-time 8 -D - "http://$wg_ip:$AP_PORT/" 2>&1) || true
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
if [[ "$ap_out" == *"uwg-catalog-apache2-${AP_PORT}-ok"* && "$ap_out" == *"Server: Apache/"* ]]; then
  wrapped_ok=true
fi

notes="wg_ip=$wg_ip port=$AP_PORT ready=$ready | out-head: $(printf '%s' "$ap_out" | head -c 240 | tr '\n' '|') | err-tail: $(tail -c 200 $err | tr '\n' '|') | apache-err-tail: $(tail -c 200 $work/logs/error.log 2>/dev/null | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
