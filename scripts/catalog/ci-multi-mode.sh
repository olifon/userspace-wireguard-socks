#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Multi-mode catalog smoke. The auto cascade is already exercised by
# ci-selfloop.sh; this script pins that all wrapper transport modes
# (systrap-elf, systrap-supervised, ptrace-seccomp) are prod-ready on
# the same dynamic-target apps. It catches mode-specific regressions
# the auto cascade hides — e.g. the supervised SIGSYS-forward race
# that surfaced before the remoteSyscallAtSIGSYS PC-rewind fix.
#
# Modes exercised (in order):
#   - systrap-elf         PT_INTERP injection (the current auto default)
#   - systrap-supervised  ptrace+seccomp; concurrency-sensitive
#   - ptrace-seccomp      ptrace with seccomp accelerator (slowest);
#                         smaller app subset because it's slow
#
# The app subset is deliberately small + dynamic-only:
#   curl, wget, python, node, dig, nginx, iperf3-udp, udp-echo-bind
#
# Static-target rows are NOT in this matrix — the static cascade is
# already pinned by tests/preload/systrap_docker_test.go and friends,
# and a multi-mode static run would explode the CI time budget.
#
# Skipped on every-push CI; release.yml only. Budget: ~3 minutes total
# (1 minute per mode × 3 modes, with ptrace-seccomp shorter).

set -euo pipefail
cd "$(dirname "$0")/../.."

CATALOG_HOST="${CATALOG_HOST:-hub}"
export CATALOG_HOST

# Self-build binaries if missing.
if [[ ! -x ./uwgsocks ]]; then
  echo "ci-multi-mode: building uwgsocks…"
  go build -o uwgsocks ./cmd/uwgsocks
fi
if [[ ! -x ./uwgwrapper ]]; then
  echo "ci-multi-mode: building uwgwrapper…"
  if [[ ! -f cmd/uwgwrapper/assets/uwgpreload.so ]]; then
    bash preload/build_phase1.sh cmd/uwgwrapper/assets/uwgpreload.so >/dev/null 2>&1 || true
  fi
  go build -o uwgwrapper ./cmd/uwgwrapper
fi

export UWGSOCKS_API="http://127.0.0.1:9091"

# If a uwgsocks is already listening on 9091 (local dev, or a stale
# ci-selfloop daemon), reuse it. Otherwise spin up our own single-node
# instance with the same hub config ci-selfloop uses. MESH_PROBE_URL in
# scripts/catalog/lib.sh is hard-coded to expect the hub API on 9091.
if curl -fsS http://127.0.0.1:9091/v1/status >/dev/null 2>&1; then
  echo "ci-multi-mode: reusing existing uwgsocks on 9091"
else
  TMPCFG=$(mktemp)
  trap 'rm -f "$TMPCFG"; pkill -9 -f "uwgsocks --config $TMPCFG" 2>/dev/null || true' EXIT
  PRIV=$(./uwgsocks generate-private-key 2>/dev/null) || PRIV=$(head -c 32 /dev/urandom | base64)
  WG_PORT=$(( ( RANDOM % 20000 ) + 41820 ))
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
  listen: "127.0.0.1:9091"
EOF
  ./uwgsocks --config "$TMPCFG" >/tmp/uwgsocks-multi-mode.log 2>&1 &
  WGS=$!
  sleep 2
  if ! kill -0 $WGS 2>/dev/null; then
    echo "uwgsocks failed to start; log:" >&2
    cat /tmp/uwgsocks-multi-mode.log >&2
    exit 1
  fi
  for i in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:9091/v1/status >/dev/null 2>&1; then break; fi
    sleep 0.3
  done
fi

# Curated app subset per mode. systrap-elf + systrap-supervised get the
# full HTTP-client set. ptrace-seccomp is slow (each syscall round-trips
# through the ptracer) so we limit it to the most representative apps.
# dig is now included: libuv registers the DNS socket via io_uring
# IORING_OP_EPOLL_CTL (bypassing our epoll_ctl seccomp intercept), and
# we handle that via /proc/<pid>/fdinfo discovery in handleEpollWait.
APPS_FAST=(curl wget python node dig nginx iperf3-udp udp-echo-bind)
APPS_SLOW=(curl python dig udp-echo-bind iperf3-udp)

# Track pass/fail per mode.
total_pass=0
total_fail=0
mode_summaries=()

for entry in "systrap-elf:fast" "systrap-supervised:fast" "ptrace-seccomp:slow"; do
  mode="${entry%%:*}"
  bag="${entry##*:}"
  case "$bag" in
    fast) apps=("${APPS_FAST[@]}");;
    slow) apps=("${APPS_SLOW[@]}");;
  esac

  echo "=== mode: $mode ==="
  pass=0; fail=0; skip=0
  for a in "${apps[@]}"; do
    s="scripts/catalog/apps/${a}.sh"
    if [[ ! -x "$s" ]]; then
      echo "skip $a — no script"; skip=$((skip+1)); continue
    fi
    tmpout=$(mktemp)
    if CATALOG_TRANSPORT="$mode" bash "$s" >"$tmpout" 2>&1; then
      pass=$((pass+1))
    else
      fail=$((fail+1))
      echo "FAIL [$mode/$a]:"
      cat "$tmpout"
    fi
    rm -f "$tmpout"
  done
  total_pass=$((total_pass+pass))
  total_fail=$((total_fail+fail))
  mode_summaries+=("$mode: pass=$pass fail=$fail skip=$skip")
done

echo "----"
for s in "${mode_summaries[@]}"; do
  echo "ci-multi-mode $s"
done
echo "ci-multi-mode TOTAL: pass=$total_pass fail=$total_fail"
exit $(( total_fail > 0 ? 1 : 0 ))
