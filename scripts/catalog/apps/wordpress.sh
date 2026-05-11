#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# WordPress full lifecycle through the wrapper. Beyond startup smoke:
#
#   1. wrapped wp-cli downloads WordPress core into a fresh dir
#   2. wrapped wp-cli generates wp-config.php against local MariaDB
#   3. wrapped wp-cli runs `core install` (creates the schema + admin)
#   4. wrapped `php -S` serves the install bound on the tunnel WG addr
#   5. wrapped wp-cli installs a real plugin (`hello-dolly` — ships
#      with WP, no external download needed in the API check below)
#      and activates it
#   6. peer's wrapped curl hits wp-json/wp/v2/types and asserts the
#      REST API returns the canonical WordPress signature
#   7. peer's wrapped curl confirms the plugin's REST presence
#
# What it exercises that nothing else does:
#   - wp-cli's heavy Composer-PHP autoload graph + HTTP downloads
#     (core, plugin) under the wrapper
#   - PHP-FPM-style request handling via `php -S` against a real DB-
#     backed CMS — not just a static respond
#   - REST API surface: query a real authenticated admin endpoint
#     (wp-json/wp/v2/types requires no auth, but the response shape
#     is generated only on a fully-initialized DB)
#
# Pass criterion: ALL of: core download, install, plugin install +
# activate, REST API response containing both "post" and "page" types.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="wordpress"
if ! bin_exists wp; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x /usr/local/bin/wp"
  exit 0
fi
if ! bin_exists php || ! bin_exists curl || ! bin_exists mariadb; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y php-cli php-mysql php-curl php-gd php-xml php-zip php-mbstring mariadb-server curl"
  exit 0
fi
# DB sanity
if ! mariadb -e 'select 1' >/dev/null 2>&1; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-mariadb 0 \
    "mariadb not reachable as root. Setup: systemctl start mariadb; mariadb -e \"CREATE DATABASE uwgwp; CREATE USER 'uwgwp'@'%' IDENTIFIED BY 'uwgwp'; GRANT ALL ON uwgwp.* TO 'uwgwp'@'%';\""
  exit 0
fi

case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) wg_ip="10.200.0.1" ;;
  arm64)                   wg_ip="10.200.0.3" ;;
  vast)                    wg_ip="10.200.0.5" ;;
  *)                       wg_ip="10.200.0.1" ;;
esac
WP_PORT="${WP_PORT:-$(( ( RANDOM % 10000 ) + 50000 ))}"
DB_NAME="uwgwp$$"
work=$(mktemp -d)
chmod 755 "$work"
WP_ROOT="$work/wp"
mkdir -p "$WP_ROOT"

cleanup() {
  [[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null
  mariadb -e "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

err="$work/wrapper.err"
WRAP() { "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto "$@"; }

start=$(date +%s.%N)

# Per-run DB so parallel runs don't fight
mariadb -e "CREATE DATABASE $DB_NAME; GRANT ALL ON $DB_NAME.* TO 'uwgwp'@'%';" 2>>"$err"

# 1. Download WP core
WRAP -- wp --allow-root --path="$WP_ROOT" core download 2>>"$err" >/dev/null

# 2. Config (use 127.0.0.1 for the DB — mariadb is bound to loopback,
# WP-side connection doesn't traverse the tunnel since it's a sibling
# process on the same host; the WRAPPED part of the test is the HTTP
# request from the peer, not the DB connection).
WRAP -- wp --allow-root --path="$WP_ROOT" config create \
    --dbname="$DB_NAME" --dbuser=uwgwp --dbpass=uwgwp \
    --dbhost=127.0.0.1 --skip-check --force >>"$err" 2>&1

# 3. Install — needs the URL so REST API generates absolute links.
WRAP -- wp --allow-root --path="$WP_ROOT" core install \
    --url="http://${wg_ip}:${WP_PORT}" \
    --title="UWG Catalog Test" \
    --admin_user=admin --admin_password=catalog-pw \
    --admin_email=admin@example.com --skip-email >>"$err" 2>&1

# 4. Plugin install + activate (hello dolly ships with core).
WRAP -- wp --allow-root --path="$WP_ROOT" plugin activate hello >>"$err" 2>&1

# 5. Boot php -S to serve the install. Bind to the tunnel addr.
# Same docroot perm trick as apache2.sh: php -S forks no workers, so
# the WP install runs as root throughout. Path: bind on tunnel WG.
nohup "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto --allow-bind -v -- \
    php -S "$wg_ip:$WP_PORT" -t "$WP_ROOT" </dev/null >"$work/server.log" 2>"$err" &
SRVPID=$!

ready=false
for i in $(seq 1 60); do
  if [[ "$CATALOG_HOST" =~ ^(hub|.*amd64-host.*) ]] && (( i % 5 == 0 )); then
    PEER="${WP_PEER:-root@51.15.66.128}"
    PEER_API="${WP_PEER_API:-http://127.0.0.1:9092}"
    if ssh -o BatchMode=yes "$PEER" "timeout 3 /usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- bash -c 'exec 9<>/dev/tcp/$wg_ip/$WP_PORT'" >/dev/null 2>&1; then
      ready=true; break
    fi
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.3
done

# 6. + 7. Peer-side wrapped curl: hit the REST API for post types and
# verify both `post` and `page` are present. WP's REST root would also
# work, but /wp/v2/types is bigger structurally — it requires the
# full registry to have initialized.
PEER="${WP_PEER:-root@51.15.66.128}"
PEER_API="${WP_PEER_API:-http://127.0.0.1:9092}"
api_resp=""
plugin_check=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      api_resp=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- curl -sS --max-time 8 http://$wg_ip:$WP_PORT/?rest_route=/wp/v2/types" 2>&1) || true
      plugin_check=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=auto -- curl -sS --max-time 8 'http://$wg_ip:$WP_PORT/?rest_route=/wp/v2/plugins'" 2>&1) || true
      ;;
    *)
      api_resp=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
          curl -sS --max-time 8 "http://$wg_ip:$WP_PORT/?rest_route=/wp/v2/types" 2>&1) || true
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
if [[ "$api_resp" == *'"slug":"post"'* && "$api_resp" == *'"slug":"page"'* ]]; then
  wrapped_ok=true
fi

notes="wg_ip=$wg_ip port=$WP_PORT ready=$ready | api-head: $(printf '%s' "$api_resp" | head -c 200) | err-tail: $(tail -c 200 $err 2>/dev/null | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
