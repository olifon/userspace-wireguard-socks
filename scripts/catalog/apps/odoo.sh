#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Odoo full-server smoke through the wrapper. Replaces the previous
# `--version` boot smoke with a real running-server test:
#
#   1. Wrapped odoo-bin starts a real Odoo server bound on a random
#      port against a local postgres (cluster:18/main, role 'odoo').
#   2. Init a fresh database (`-d uwgsmoke -i base --stop-after-init`)
#      — this exercises the bulk of Odoo's startup (ORM, modules,
#      assets compilation), running entirely inside the wrapper.
#   3. Re-launch as a server on the same DB, wait for /web/health to
#      return ready, then fetch /web/login and POST credentials.
#   4. JSON-RPC to /web/session/get_session_info — admin session
#      should authenticate.
#
# Pass criterion is the JSON-RPC step returning
# `"name": "Administrator"`. Init failure, server-bind failure, or
# unauthenticated session all surface as wrapped_ok=false.
#
# Database backing assumption: a local postgres cluster is running
# with an `odoo` role that has CREATEDB. See the README for the
# one-shot setup.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="odoo"

odoo_bin=""
for cand in /usr/local/bin/odoo-bin /opt/odoo/odoo-bin odoo-bin odoo /usr/bin/odoo; do
  if bin_exists "$cand"; then odoo_bin="$cand"; break; fi
done
if [[ -z "$odoo_bin" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: see scripts/catalog/README.md 'Building Odoo from source'. Apt's odoo package is unusable with Werkzeug 3.x."
  exit 0
fi
if ! command -v psql >/dev/null || ! pg_isready -q 2>/dev/null; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-postgres 0 \
    "postgres not running. Setup: apt-get install -y postgresql; pg_ctlcluster 18 main start; sudo -u postgres psql -c \"CREATE USER odoo WITH SUPERUSER PASSWORD 'odoo';\""
  exit 0
fi

PORT=$(( ( RANDOM % 5000 ) + 28069 ))
DB="uwgsmoke$$"
work=$(mktemp -d)
err="$work/wrapper.err"
init_log="$work/init.log"
srv_log="$work/server.log"

cleanup() {
  [[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null
  pkill -9 -P $$ 2>/dev/null
  pkill -9 -f "odoo-bin.*-d ${DB}" 2>/dev/null
  sudo -u postgres dropdb --if-exists "$DB" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

start=$(date +%s.%N)

# 1. Init the database. Odoo's --stop-after-init is the way to do this
# headless. We initialize ONLY the `base` module — full module init
# takes minutes; base is enough to prove ORM startup + module loader
# + assets compilation work under the wrapper.
# Odoo writes its INFO log to stderr; combine into init_log so the
# success grep below can see the "Modules loaded." marker.
"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    "$odoo_bin" --no-http \
                -d "$DB" -i base \
                --db_host 127.0.0.1 --db_port 5432 --db_user odoo --db_password odoo \
                --without-demo=all \
                --stop-after-init \
    >"$init_log" 2>&1 &
INITPID=$!
wait $INITPID 2>/dev/null
init_exit=$?
# Also copy the wrapper auto-cascade decision from init_log into err
# so the transport-detection grep further down still finds it.
grep -E '^uwgwrapper:' "$init_log" >>"$err" 2>/dev/null || true

if (( init_exit != 0 )) || ! grep -q 'odoo.modules.loading: Modules loaded\.' "$init_log"; then
  end=$(date +%s.%N); dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')
  notes="init_exit=$init_exit | init-tail: $(tail -c 400 $init_log 2>/dev/null | tr '\n' '|') | err-tail: $(tail -c 200 $err | tr '\n' '|')"
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" init-failed "$dur" "$notes"
  exit 1
fi

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# 2. Launch the running server on the initialized DB. Odoo writes the
# "HTTP service (werkzeug) running on" ready marker to stderr — combine
# stdout+stderr into srv_log so the ready-detect grep below works.
"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto --allow-bind -v -- \
    "$odoo_bin" \
        -d "$DB" \
        --db_host 127.0.0.1 --db_port 5432 --db_user odoo --db_password odoo \
        --http-port "$PORT" --http-interface 127.0.0.1 \
        --no-database-list \
    >"$srv_log" 2>&1 &
SRVPID=$!

# 3. Wait for the server to bind + accept HTTP. Odoo's "HTTP service
# (werkzeug) running on" log line is the canonical ready marker.
ready=false
for i in $(seq 1 60); do
  if grep -q 'HTTP service (werkzeug) running on' "$srv_log" 2>/dev/null; then
    ready=true; break
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 1
done

session_json=""
if [[ "$ready" == "true" ]]; then
  # Odoo binds 127.0.0.1 here (above) since we're hitting it directly
  # from the same host — no need to involve netstack. The test is
  # specifically of the wrapped Odoo server, not the wrapped client.
  JAR="$work/cookies.txt"
  login_html=$(curl -sS --max-time 20 -c "$JAR" -b "$JAR" \
      "http://127.0.0.1:${PORT}/web/login" 2>>"$err") || true
  csrf=$(printf '%s' "$login_html" | grep -oE 'name="csrf_token" value="[^"]+"' | head -1 | sed -E 's/.*value="//; s/"//')

  curl -sS --max-time 20 -c "$JAR" -b "$JAR" -L -X POST \
      --data-urlencode "csrf_token=$csrf" \
      --data-urlencode "login=admin" \
      --data-urlencode "password=admin" \
      --data-urlencode "type=password" \
      --data-urlencode "redirect=/odoo" \
      -o /dev/null \
      "http://127.0.0.1:${PORT}/web/login" 2>>"$err" || true

  session_json=$(curl -sS --max-time 20 -b "$JAR" -X POST \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"call","id":1,"params":{}}' \
      "http://127.0.0.1:${PORT}/web/session/get_session_info" 2>>"$err") || true
fi

end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

wrapped_ok=false
if [[ "$session_json" == *'"is_admin": true'* && "$session_json" == *'"name": "Administrator"'* ]]; then
  wrapped_ok=true
fi

notes="port=$PORT ready=$ready init_exit=$init_exit session-len=${#session_json} | init-tail: $(tail -c 200 $init_log 2>/dev/null | tr '\n' '|') | session-head: $(printf '%s' "$session_json" | head -c 240)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
