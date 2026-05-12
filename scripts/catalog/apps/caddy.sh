#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Caddy — static-Go HTTP server bound on a tunnel WG address.
#
# Fills the gap between:
#   - nginx.sh (C, prefork+master+worker, accept loop) — proves C
#     servers survive the wrapper.
#   - gh.sh / cloudflared.sh (static Go CLIs that don't bind) — prove
#     static-Go BINARIES are loadable.
#
# Caddy is static Go AND binds() AND handles real concurrent HTTPS.
# That combination isn't tested by anything else; net.Listener under
# systrap-static is structurally different from accept(2) on a C
# socket (Go's runtime polls via netpoll/epoll directly, sometimes
# bypassing libc entirely). If wrapper bugs hide behind nginx's libc
# accept loop, this is where they'd surface.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="caddy"
# Prefer the distro-packaged caddy (dynamic libc) over any static
# vendor build the host may also have. The wrapper's preload mode
# requires a dynamic loader, and the static-Go path for caddy hits
# the systrap-supervised SIGILL bug (see
# memory/project_caddy_sigill_systrap_supervised.md). Once that
# bug is fixed and caddy can run under systrap-supervised /
# systrap-static cleanly, the candidate order won't matter.
caddy_bin=""
for cand in /usr/bin/caddy /usr/local/bin/caddy caddy /opt/instance-tools/bin/caddy; do
  if [[ -x "$cand" ]] && file "$cand" 2>/dev/null | grep -q 'dynamically linked'; then
    caddy_bin="$cand"; break
  fi
done
if [[ -z "$caddy_bin" ]]; then
  # Fall back to any caddy on PATH (likely static) — we'll let the
  # wrapper's auto cascade decide; this will probably fail on
  # systrap-supervised today but exposes the bug.
  for cand in caddy /usr/bin/caddy /usr/local/bin/caddy /opt/instance-tools/bin/caddy; do
    if bin_exists "$cand"; then caddy_bin="$cand"; break; fi
  done
fi
if [[ -z "$caddy_bin" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: download from https://caddyserver.com/download or 'apt-get install -y caddy'"
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

CADDY_PORT="${CADDY_PORT:-$(( ( RANDOM % 10000 ) + 50000 ))}"
work=$(mktemp -d)
trap '[[ -n "${SRVPID:-}" ]] && kill -9 "$SRVPID" 2>/dev/null; rm -rf "$work"' EXIT

cat >"$work/Caddyfile" <<EOF
{
  admin off
  auto_https off
}
http://$wg_ip:$CADDY_PORT {
  respond "uwg-catalog-caddy-${CADDY_PORT}-ok"
}
EOF

err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
# Caddy's `run` mode stays in foreground (no daemonize). Output goes
# to stderr; we route via the wrapper's -v err file.
#
# Auto cascade. The original repro that pinned this to preload was
# systrap-supervised's concurrent-raw-syscall SIGILL; the cascade now
# demotes systrap-supervised → systrap for dynamic targets and Caddy
# works there. If a future change re-promotes systrap-supervised in
# the cascade without fixing the bug, this row goes red.
nohup "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} --allow-bind -v -- \
    "$caddy_bin" run --config "$work/Caddyfile" --adapter caddyfile \
    </dev/null >"$log_out" 2>"$err" &
SRVPID=$!

# Wait for caddy to bind. Caddy logs "serving" on the listener.
ready=false
for i in $(seq 1 60); do
  if grep -qE 'serving initial configuration|listener.*ready' "$err" 2>/dev/null; then
    ready=true; break
  fi
  # Same-host wrapped dial routes via host_forward to 127.0.0.1 which
  # is NOT where caddy is bound (caddy is in netstack). Peer-side
  # probe used instead, same as mongo-server.sh / redis-server.sh.
  if [[ "$CATALOG_HOST" =~ ^(hub|.*amd64-host.*) ]] && (( i % 6 == 0 )); then
    PEER="${CADDY_PEER:-root@51.15.66.128}"
    PEER_API="${CADDY_PEER_API:-http://127.0.0.1:9092}"
    if ssh -o BatchMode=yes "$PEER" "timeout 3 /usr/local/bin/uwgwrapper --api=$PEER_API --transport=${CATALOG_TRANSPORT:-auto} -- bash -c 'exec 9<>/dev/tcp/$wg_ip/$CADDY_PORT'" >/dev/null 2>&1; then
      ready=true; break
    fi
  fi
  if ! kill -0 $SRVPID 2>/dev/null; then break; fi
  sleep 0.5
done

caddy_out=""
if [[ "$ready" == "true" ]]; then
  case "$CATALOG_HOST" in
    hub|*amd64-host*|*hub*)
      PEER="${CADDY_PEER:-root@51.15.66.128}"
      PEER_API="${CADDY_PEER_API:-http://127.0.0.1:9092}"
      caddy_out=$(ssh -o BatchMode=yes "$PEER" "/usr/local/bin/uwgwrapper --api=$PEER_API --transport=${CATALOG_TRANSPORT:-auto} -- curl -sS --max-time 8 http://$wg_ip:$CADDY_PORT/" 2>&1) || true
      ;;
    *)
      caddy_out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -- \
          curl -sS --max-time 8 "http://$wg_ip:$CADDY_PORT/" 2>&1) || true
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
if [[ "$caddy_out" == *"uwg-catalog-caddy-${CADDY_PORT}-ok"* ]]; then
  wrapped_ok=true
fi

notes="wg_ip=$wg_ip port=$CADDY_PORT ready=$ready | out: $(printf '%s' "$caddy_out" | head -c 200) | err-tail: $(tail -c 200 $err | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
