#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# UDP server bind() through wrapper: spawn a single-process Python UDP
# echo server, have it bind to the host's WG tunnel address
# (`socket_api.bind: true` on the daemon is required), then dial it from
# the same wrapper as a UDP client.  Both legs are wrapped to confirm
# the netstack-side UDP listener is reachable end-to-end via the
# wrapper's socket protocol.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="udp-echo-bind"
if ! command -v python3 >/dev/null; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "python3 required"
  exit 0
fi

# Determine our own WG IP from uwgsocks API.
self_ip=$(curl -sS --max-time 4 "${UWGSOCKS_API}/v1/status" 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    # Local WG addresses are not directly in /v1/status — derive from
    # mesh advertisement: pick the engine'\''s configured local address.
    # Fall back to a config-known list.
    print("")
except Exception:
    print("")
')
case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*) self_ip="10.200.0.1" ;;
  arm64)                   self_ip="10.200.0.3" ;;
  vast)                    self_ip="10.200.0.5" ;;
  *)                       self_ip="10.200.0.3" ;;
esac

port=$(( ( RANDOM % 20000 ) + 41000 ))
work=$(mktemp -d)
trap 'kill $SRVPID 2>/dev/null; rm -rf "$work"; true' EXIT

cat >"$work/srv.py" <<'PY'
import socket, os, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((ip, port))
print(f"listening_udp {ip}:{port}", flush=True)
for _ in range(20):
    data, addr = s.recvfrom(1500)
    s.sendto(b"echo:" + data, addr)
    if data == b"quit":
        break
PY

err="$work/srv.err"
"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v --allow-bind -- \
    python3 "$work/srv.py" "$self_ip" "$port" >"$work/srv.log" 2>"$err" &
SRVPID=$!

# Wait for "listening_udp" line.
for i in $(seq 1 30); do
  grep -q 'listening_udp' "$work/srv.log" 2>/dev/null && break
  sleep 0.2
done

start=$(date +%s.%N)
# Client side — wrapped UDP send + recv.
cat >"$work/cli.py" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(b"hello-udp", (host, port))
data, _ = s.recvfrom(1500)
print(data.decode())
s.sendto(b"quit", (host, port))
PY
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -- \
    python3 "$work/cli.py" "$self_ip" "$port" 2>>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$out" == "echo:hello-udp" ]] && wrapped_ok=true

notes="self_ip=$self_ip port=$port | out: $out | srv-log: $(cat $work/srv.log 2>/dev/null | head -c 200) | err-tail: $(tail -c 240 $err | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
