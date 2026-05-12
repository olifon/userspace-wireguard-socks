#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# helm-deployed Odoo dialed through the wrapper — composite test of
# four wrapped flows simultaneously:
#
#   1. helm/kubectl already orchestrated a real Odoo (bitnami chart) +
#      postgresql backend on the catalog's microk8s cluster. This
#      script assumes that's done (see scripts/catalog/README.md
#      "Helm-deploying Odoo"). The deploy itself is one-shot env
#      setup, not part of the per-run signal.
#   2. Wrapped curl GETs Odoo's login page and parses out the
#      CSRF token + initial session cookie.
#   3. Wrapped curl POSTs a real form-encoded login with the admin
#      credentials (read from the bitnami secret).
#   4. Wrapped curl POSTs a JSON-RPC call to
#      /web/session/get_session_info — Odoo only returns a non-public
#      `uid` here when the session cookie is genuinely authenticated.
#
# Pass criterion: the JSON-RPC response contains `"name":"Administrator"`
# AND `"is_admin": true`. Catches both a half-completed login and a
# session-cookie-handling regression in the wrapper.
#
# Env:
#   HELM_ODOO_HOST   default 10.200.0.3 (microk8s WG addr)
#   HELM_ODOO_PORT   default 30080      (NodePort)
#   HELM_ODOO_LOGIN  default user@example.com
#   HELM_ODOO_PASS   no default; must be supplied (kubectl -n odoo
#                    get secret odoo -o jsonpath='{.data.odoo-password}'
#                    | base64 -d).
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="helm-odoo"

host="${HELM_ODOO_HOST:-10.200.0.3}"
port="${HELM_ODOO_PORT:-30080}"
login_email="${HELM_ODOO_LOGIN:-user@example.com}"
password="${HELM_ODOO_PASS:-}"

if [[ -z "$password" ]]; then
  # Try to retrieve directly via wrapped kubectl if kubeconfig is set
  if bin_exists kubectl && [[ -f /root/.kube/config ]]; then
    password=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -- \
        kubectl get secret -n odoo odoo -o jsonpath='{.data.odoo-password}' 2>/dev/null | base64 -d 2>/dev/null) || true
  fi
fi
if [[ -z "$password" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-helm-odoo 0 \
    "HELM_ODOO_PASS not set and kubectl can't retrieve it. Deploy with: helm install odoo bitnami/odoo --namespace odoo --create-namespace --set service.type=NodePort --set service.nodePorts.http=30080 --set persistence.enabled=false --set postgresql.primary.persistence.enabled=false --set global.security.allowInsecureImages=true --set image.repository=bitnamilegacy/odoo --set postgresql.image.repository=bitnamilegacy/postgresql"
  exit 0
fi
if ! bin_exists curl; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y curl"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
JAR="$work/cookies.txt"
err="$work/wrapper.err"

WRAP() { "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} "$@"; }

start=$(date +%s.%N)
# 1. Initial GET — captures session cookie + csrf token
login_html=$(WRAP -- curl -sS --max-time 20 -c "$JAR" -b "$JAR" \
    "http://${host}:${port}/web/login" 2>"$err") || true
csrf=$(printf '%s' "$login_html" | grep -oE 'name="csrf_token" value="[^"]+"' | head -1 | sed -E 's/.*value="//; s/"//')

# 2. POST login (form-encoded, follow redirect to /odoo)
login_status=$(WRAP -- curl -sS --max-time 20 -c "$JAR" -b "$JAR" -L -X POST \
    --data-urlencode "csrf_token=$csrf" \
    --data-urlencode "login=$login_email" \
    --data-urlencode "password=$password" \
    --data-urlencode "type=password" \
    --data-urlencode "redirect=/odoo" \
    -o /dev/null \
    -w '%{http_code}' \
    "http://${host}:${port}/web/login" 2>>"$err") || true

# 3. JSON-RPC call that only returns authenticated user info if logged in
session_json=$(WRAP -- curl -sS --max-time 20 -b "$JAR" -X POST \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"call","id":1,"params":{}}' \
    "http://${host}:${port}/web/session/get_session_info" 2>>"$err") || true

end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
if [[ "$session_json" == *'"is_admin": true'* && "$session_json" == *'"name": "Administrator"'* ]]; then
  wrapped_ok=true
fi

notes="host=$host:$port login_status=$login_status csrf-len=${#csrf} session-len=${#session_json} | err-tail: $(tail -c 200 $err 2>/dev/null | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
