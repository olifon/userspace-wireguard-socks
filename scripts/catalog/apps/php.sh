#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# PHP's built-in development server bound on a tunnel WG address.
# Peer's wrapped curl fetches a script-generated response.
#
# Why it's a useful catalog row:
#   - PHP is one of the most-deployed server runtimes; the upstream
#     test suite is enormous. Catalog row first proves the wrapper
#     carries a real php.net binary (with all its libc-touching
#     extensions: openssl, libxml, libonig, sodium, pcre2, …).
#   - php -S is a synchronous single-process accept loop — a different
#     shape from nginx's master+worker, caddy's net.Listener, or
#     redis's epoll. Catches any latent regression in the simplest
#     possible accept(2) → fork-less request path.
#
# Pass criterion: peer fetches the page; response body contains both
# the script-generated content AND `PHP/8.x`-class server header
# string (proving the response came from php, not from anything else
# bound on the port).
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="php"
if ! bin_exists php; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y php-cli"
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

PHP_PORT="${PHP_PORT:-$(( ( RANDOM % 10000 ) + 50000 ))}"
work=$(mktemp -d)
trap '[[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null; rm -rf "$work"' EXIT

# Tiny script — exercises PHP's request handling + JSON encoding +
# extension loading enough to prove the runtime is alive end-to-end.
cat >"$work/index.php" <<'PHP'
<?php
header('Content-Type: application/json');
echo json_encode([
    'phpver' => PHP_VERSION,
    'sapi'   => PHP_SAPI,
    'token'  => 'uwg-catalog-php-ok',
    'now'    => time(),
    'exts'   => count(get_loaded_extensions()),
]);
PHP

err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
# php -S is foreground, prints "PHP X.Y.Z Development Server (...) started"
nohup "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto --allow-bind -v -- \
    php -S "$wg_ip:$PHP_PORT" -t "$work" \
    </dev/null >"$log_out" 2>"$err" &
SRVPID=$!

ready=false
for i in $(seq 1 30); do
  if grep -qE 'Development Server.*started' "$err" "$log_out" 2>/dev/null; then
    ready=true; break
  fi
  if [[ "$CATALOG_HOST" =~ ^(hub|.*amd64-host.*) ]] && (( i % 5 == 0 )); then
    PEER="${PHP_PEER:-root@51.15.66.128}"
    PEER_API="${PHP_PEER_API:-http://127.0.0.1:9092}"
    if ssh -o BatchMode=yes "$PEER" "timeout 3 /usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- bash -c 'exec 9<>/dev/tcp/$wg_ip/$PHP_PORT'" >/dev/null 2>&1; then
      ready=true; break
    fi
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.3
done

php_out=""
php_header=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      PEER="${PHP_PEER:-root@51.15.66.128}"
      PEER_API="${PHP_PEER_API:-http://127.0.0.1:9092}"
      php_out=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- curl -sS --max-time 8 -D - http://$wg_ip:$PHP_PORT/" 2>&1) || true
      ;;
    *)
      php_out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
          curl -sS --max-time 8 -D - "http://$wg_ip:$PHP_PORT/" 2>&1) || true
      ;;
  esac
fi
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# Both the JSON token AND a PHP-identifying response header must be
# present. php -S emits `X-Powered-By: PHP/X.Y.Z` (not `Server:`) —
# match that. Catches a regression where some other server happened
# to bind the port.
wrapped_ok=false
if [[ "$php_out" == *"uwg-catalog-php-ok"* && "$php_out" == *"X-Powered-By: PHP/"* ]]; then
  wrapped_ok=true
fi

notes="wg_ip=$wg_ip port=$PHP_PORT ready=$ready | out-head: $(printf '%s' "$php_out" | head -c 240 | tr '\n' '|') | err-tail: $(tail -c 200 $err | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
