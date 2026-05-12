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

# Use a random WG port so we don't collide with a real wg-quick on the
# same host. The API port stays FIXED at 9091 because scripts/catalog/lib.sh
# hard-codes MESH_PROBE_URL=http://10.200.0.1:9091/v1/status for the hub
# host. With inbound.transparent + host_forward.inbound, packets to
# 10.200.0.1:9091 get rewritten to 127.0.0.1:9091, which only lands a
# listener if the API is actually on 9091. A random API port silently
# breaks the 6 HTTPS-client rows that dial MESH_PROBE_URL (curl, wget,
# python, node, ssh, java-http) — they pass on the real hub VPS only
# because a long-running uwgsocks happens to occupy 9091. In CI's fresh
# runner there's nothing on 9091 so we own it.
WG_PORT=$(( ( RANDOM % 20000 ) + 41820 ))
API_PORT=9091
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

# Best-effort batch install. Each row tolerates an absent binary via
# its own missing-bin path, but pre-installing the apt-fetchable ones
# means more rows actually run.
#
# We batch ALL packages into a SINGLE `apt-get install` to amortize
# the dpkg + apt-cache + lock-acquisition cost — the prior loop of
# 24 separate `install_one` calls took ~16 minutes on the noble GH
# amd64 runner because each install_one paid the full apt setup cost.
# A single batched call resolves dependencies once and parallelizes
# downloads; ~3-4× speedup observed locally.
#
# Architecture-specific filtering: qemu-system-x86 is x86_64-only as
# an apt package. On arm64 we substitute qemu-system-arm where
# available (Alpine arm64 boot is x86-host-mode for now anyway, so
# the row records no-alpine-image — both paths skip cleanly).
batch_pkg_install() {
  if ! command -v apt-get >/dev/null; then return 0; fi
  local want=("$@")
  local pkgs=()
  local p
  for p in "${want[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 || pkgs+=("$p")
  done
  if (( ${#pkgs[@]} == 0 )); then return 0; fi
  # Try the batched install first. Some packages (xh, cloudflared) may
  # not exist in the noble repos; apt-get's all-or-nothing semantics
  # would reject the whole batch. Fall back to per-package install
  # on batch failure so the available packages still land.
  if ! sudo apt-get install -y --no-install-recommends "${pkgs[@]}" >/dev/null 2>&1; then
    for p in "${pkgs[@]}"; do
      sudo apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1 || true
    done
  fi
}

# Common subset across all architectures.
COMMON_PKGS=(
  curl wget python3 nodejs openssh-client git python3-pip ca-certificates
  xh cloudflared default-jdk-headless nginx-light dnsutils iperf3 expect
  redis-server redis-tools mariadb-client php-cli apache2 libapache2-mod-php
  qemu-utils python3-full
)
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
  COMMON_PKGS+=(qemu-system-x86)
fi
batch_pkg_install "${COMMON_PKGS[@]}"

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

# Catalog rows that work without a real WG peer. Four groups:
#  1. existing peer-free client tests (proven green)
#  2. peer-free UDP / loopback (existing)
#  3. wrapped upstream test suites — fully self-contained, no peer
#  4. VM-under-wrapper — qemu Alpine boot
#  5. server bind-only — wrapped server binds tunnel addr + reaches
#     ready signal; dial side skipped via CATALOG_BIND_ONLY=1 because
#     same-host TCP loopback is still deferred (see memory:project_
#     tcp_loopback_and_qemu_network_deferred.md). Validates the
#     wrapped-bind interception path for real db daemons.
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
  # Group 5: server bind-only (CATALOG_BIND_ONLY=1). redis-server
  # binds 10.200.0.x:$port and waits for "Ready to accept
  # connections" under the wrapper, exits 0 without dialing.
  redis-server
)
# Hint to the catalog row scripts that the dial side should be skipped
# — the bind path is the signal in CI's single-node setup. Server rows
# that don't recognize this var fall through to their normal flow.
export CATALOG_BIND_ONLY=1
pass=0; fail=0; skip=0
failed_rows=()
for a in "${APPS[@]}"; do
  s="scripts/catalog/apps/${a}.sh"
  if [[ ! -x "$s" ]]; then
    echo "skip $a — no script"; skip=$((skip+1)); continue
  fi
  if bash "$s" >/dev/null; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    failed_rows+=("$a")
  fi
done
echo "ci-selfloop summary: pass=$pass fail=$fail skip=$skip"
# On any failure, dump each failed row's recorded JSON so the next
# debugging session has the actual error message + stderr-tail in the
# CI log (instead of just the one-line summary). Without this, post-
# mortem requires reproducing locally — slow inner loop.
if (( fail > 0 )); then
  for a in "${failed_rows[@]}"; do
    for hostdir in scripts/catalog/results/*/; do
      f="${hostdir}${a}.json"
      if [[ -f "$f" ]]; then
        echo "=== failed row: $a ==="
        cat "$f"
        echo
      fi
    done
  done
fi
exit $(( fail > 0 ? 1 : 0 ))
