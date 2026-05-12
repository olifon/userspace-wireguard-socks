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
#   - ntp, curl-http3 (rely on specific wrapper UDP shapes
#     that have known limitations; tracked in production-applications.md)
set -euo pipefail
cd "$(dirname "$0")/../.."

CATALOG_HOST="${CATALOG_HOST:-hub}"
export CATALOG_HOST

# Self-contained build of the wrapper + daemon binaries the catalog
# rows need. Required when running under release.yml's "release test"
# job, where the binaries aren't otherwise built in the repo root.
# (test.yml's main path goes through compile.sh which DOES build them;
# release.yml's ci-selfloop step does go-test + then runs us, so the
# binaries are missing here.)
if [[ ! -x ./uwgsocks ]]; then
  echo "ci-selfloop: building uwgsocks…"
  go build -o uwgsocks ./cmd/uwgsocks
fi
if [[ ! -x ./uwgwrapper ]]; then
  echo "ci-selfloop: building uwgwrapper…"
  # The wrapper embeds preload/assets/uwgpreload.so via go:embed; build
  # it first if missing so the binary actually carries an interceptor.
  if [[ ! -f cmd/uwgwrapper/assets/uwgpreload.so ]]; then
    bash preload/build_phase1.sh cmd/uwgwrapper/assets/uwgpreload.so >/dev/null 2>&1 || true
  fi
  go build -o uwgwrapper ./cmd/uwgwrapper
fi

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
  udp_inbound: true
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
# Anything that needs a peer (MOSH_PEER, REDIS_PEER, etc) lives in
# the full run-suite.sh path that operators kick off across a real
# mesh — we deliberately don't fake those here.
#
# Auto-install on demand: catalog rows are responsible for printing
# "missing-bin" and exiting 0 when their target binary isn't present,
# but for the CI matrix we want best-effort coverage. The block below
# pre-installs the small/fast targets so they actually run.
export UWGSOCKS_API="${UWGSOCKS_API:-http://127.0.0.1:9091}"
install_one() {
  local pkg=$1
  if ! command -v apt-get >/dev/null; then return 0; fi
  if dpkg -s "$pkg" >/dev/null 2>&1; then return 0; fi
  sudo apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 || true
}
# Best-effort install for everything we know how to fetch quickly.
# Each row tolerates an absent binary via its own missing-bin path.
install_one curl
install_one wget
install_one python3
install_one nodejs
install_one openssh-client
install_one git
install_one python3-pip
install_one ca-certificates
install_one xh                  # apt may not have this; row will skip if missing
install_one cloudflared         # apt may not have this; row will skip if missing
install_one default-jdk-headless
install_one nginx-light
install_one dnsutils
install_one iperf3
install_one expect              # for mosh.sh, even though we don't add mosh here
install_one redis-server        # adds redis-server row below
install_one redis-tools
install_one mariadb-client
install_one php-cli
install_one apache2
install_one libapache2-mod-php
install_one qemu-system-x86
install_one qemu-utils
install_one python3-full        # for test-python-httplib

# Alpine kernel+initramfs for qemu-alpine.sh — small (~20MB combined)
# and easy to fetch. Skip if not on x86_64 (no arm64 virt kernel
# fetched here yet) or if /opt/alpine-vm/* already exists.
if [[ "$(uname -m)" == "x86_64" && ! -f /opt/alpine-vm/vmlinuz ]]; then
  sudo mkdir -p /opt/alpine-vm 2>/dev/null || mkdir -p /opt/alpine-vm
  ALPINE_BASE="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/netboot"
  sudo curl -fsSL "$ALPINE_BASE/vmlinuz-virt"    -o /opt/alpine-vm/vmlinuz   2>/dev/null \
    || curl -fsSL "$ALPINE_BASE/vmlinuz-virt"    -o /opt/alpine-vm/vmlinuz   2>/dev/null || true
  sudo curl -fsSL "$ALPINE_BASE/initramfs-virt"  -o /opt/alpine-vm/initramfs 2>/dev/null \
    || curl -fsSL "$ALPINE_BASE/initramfs-virt"  -o /opt/alpine-vm/initramfs 2>/dev/null || true
fi

# Catalog rows that work without a real WG peer. Three groups:
#  1. existing peer-free client tests (proven green)
#  2. new fast server tests added by the catalog batches — udp-echo-
#     bind is already validated by the same-host UDP loopback engine
#     code path
#  3. wrapped upstream test suites — fully self-contained, no peer
APPS=(
  # Group 1: HTTPS / TCP clients
  curl wget python node ssh git pip xh gh cloudflared java-http nginx dig
  # Group 2: peer-free UDP / loopback
  iperf3-udp udp-echo-bind
  # Group 3: wrapped upstream test suites (self-contained, no peer)
  test-python-httplib
  # Group 4: VM-under-wrapper — qemu boots Alpine kernel inside the
  # wrapper. KVM-accelerated where /dev/kvm + vmx is available
  # (GH-hosted x64 runners *do* expose /dev/kvm since 2023), TCG
  # fallback otherwise. x86_64 only — netboot/arm64 path not wired
  # yet, qemu-alpine.sh records no-alpine-image and exits 0.
  qemu-alpine
)
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
