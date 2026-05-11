#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# CI-friendly catalog driver: starts a single-node uwgsocks server with
# the recommended hub config and runs the lightweight, peer-free subset
# of the production app catalog against it. Designed for release.yml's
# tag-triggered jobs (skipped on every-push CI to keep PR feedback fast).
#
# Skipped on every-push CI:
#   - java-minecraft (200MB Paper jar download, 30+s boot)
#   - electron (Chrome install)
#   - pytorch-mnist (no GPU on GH runners; the install alone takes ~1min)
#   - odoo (apt package on noble is broken with newer werkzeug)
#   - {postgres,mongo,mariadb}-server (heavy daemon install + per-uid sudo)
#   - ntp, curl-http3, udp-echo-bind (rely on specific wrapper UDP shapes
#     that have known limitations; tracked in production-applications.md)
set -euo pipefail
cd "$(dirname "$0")/../.."

CATALOG_HOST="${CATALOG_HOST:-hub}"
export CATALOG_HOST
TMPCFG=$(mktemp)
trap 'rm -f "$TMPCFG"; pkill -9 -f "uwgsocks --config $TMPCFG" 2>/dev/null || true' EXIT

# Generate ephemeral WireGuard keys for the single-node config.
# The CI runner can't actually reach external peers; this is a self-loop
# config where mesh_control + the runtime API are reachable through the
# wrapper, which is enough to exercise every app's wrapper interception.
PRIV=$(./uwgsocks generate-private-key 2>/dev/null) || PRIV=$(wg genkey 2>/dev/null) || {
  # Fall back to /dev/urandom — 32 bytes base64 — works because we don't
  # actually need a real peer.
  PRIV=$(head -c 32 /dev/urandom | base64)
}
PUB=$(echo "$PRIV" | ./uwgsocks pubkey 2>/dev/null) || PUB=$(echo "$PRIV" | wg pubkey 2>/dev/null) || {
  PUB=$(head -c 32 /dev/urandom | base64)
}

# Use random high ports for both WG and runtime API so we don't clash
# with an already-running uwgsocks on the same host.
WG_PORT=$(( ( RANDOM % 20000 ) + 41820 ))
API_PORT=$(( ( RANDOM % 20000 ) + 41091 ))
cat >"$TMPCFG" <<EOF
wireguard:
  private_key: "$PRIV"
  addresses: ["10.200.0.1/24"]
  listen_port: $WG_PORT

mesh_control:
  listen: "10.200.0.1:8787"

inbound:
  transparent: true
host_forward:
  inbound:
    enabled: true
    redirect_ip: "127.0.0.1"
socket_api:
  bind: true
  transparent_bind: true
api:
  listen: "127.0.0.1:$API_PORT"
EOF
export UWGSOCKS_API="http://127.0.0.1:$API_PORT"

./uwgsocks --config "$TMPCFG" >/tmp/uwgsocks-ci.log 2>&1 &
WGS=$!
sleep 2
if ! kill -0 $WGS 2>/dev/null; then
  echo "uwgsocks failed to start; log:" >&2
  cat /tmp/uwgsocks-ci.log >&2
  exit 1
fi
# Make sure the API is up.
for i in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:9091/v1/status >/dev/null 2>&1; then break; fi
  sleep 0.3
done

# Run only the apps known to be runner-friendly + peer-independent.
export UWGSOCKS_API="${UWGSOCKS_API:-http://127.0.0.1:9091}"
APPS=(curl wget python node ssh git pip xh gh cloudflared java-http nginx dig iperf3-udp)
pass=0; fail=0; skip=0
for a in "${APPS[@]}"; do
  s="scripts/catalog/apps/${a}.sh"
  if [[ ! -x "$s" ]]; then
    echo "skip $a — no script"; skip=$((skip+1)); continue
  fi
  if bash "$s" >/dev/null; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
  fi
done
echo "ci-selfloop summary: pass=$pass fail=$fail skip=$skip"
exit $(( fail > 0 ? 1 : 0 ))
