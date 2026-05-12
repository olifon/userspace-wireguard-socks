#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Mosh (mobile shell) — UDP roaming-capable session protocol. New
# signal vs. udp-echo-bind / dig / iperf3-udp: mosh uses a real
# encrypted UDP datagram protocol with per-packet sequence numbers,
# heartbeats, and a key-on-the-wire handshake. The wrapper has to
# carry the protocol intact across its proxied UDP path, including
# whatever ephemeral source-port shifts mosh-client uses.
#
# Topology required:
#   - Same-host wrapped-server is impossible: mosh-server's daemonize
#     calls `clearenv()` so LD_PRELOAD vanishes in the detached child;
#     the server slips out of the wrapper sandbox entirely.
#   - Therefore: mosh-server runs unwrapped on a known peer (hub by
#     default — bind 127.0.0.1 + host_forward.inbound bridges from WG
#     into loopback). mosh-client wrapped on the local host dials the
#     peer through the WG tunnel.
#
# Catalog roles:
#   hub                — runs the test against itself only via ssh-loopback
#                        (the unwrapped server lives on hub already).
#   arm64 / vast       — wrap mosh-client locally, dial hub's WG addr.
#
# Env overrides:
#   MOSH_SERVER_HOST   — defaults: hub→127.0.0.1 (loopback unwrap),
#                        peers→10.200.0.1 (hub via tunnel).
#   MOSH_SERVER_PEER   — when running on hub, the ssh peer that holds
#                        the wrapped mosh-client. Default: root@<arm64>.
#
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="mosh"
if ! bin_exists mosh-server || ! bin_exists mosh-client || ! bin_exists expect; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y mosh expect"
  exit 0
fi

work=$(mktemp -d)
trap 'pkill -9 -P $$ 2>/dev/null; pkill -9 -f "mosh-server.*-p [0-9]*" 2>/dev/null; rm -rf "$work"' EXIT

# Random ephemeral port in mosh's recommended range.
port=$(( ( RANDOM % 5000 ) + 60100 ))

# Build a small expect driver. Same shape as the manual one used to
# bring this test up — see scripts/catalog/README.md "Mosh handshake
# probe shape".
cat >"$work/drive.exp" <<'EXP'
#!/usr/bin/expect -f
# Args: WRAPPER API HOST PORT KEY TIMEOUT
if {$argc < 6} { send_error "usage\n"; exit 5 }
set wrapper [lindex $argv 0]
set api     [lindex $argv 1]
set host    [lindex $argv 2]
set port    [lindex $argv 3]
set key     [lindex $argv 4]
set deadline [lindex $argv 5]
set timeout $deadline
set env(MOSH_KEY) $key
set env(TERM)     "xterm"
# Non-zero pty: mosh-client asserts s_height>0 and aborts otherwise.
set stty_init "rows 24 cols 80"
spawn $wrapper --api=$api --transport=${CATALOG_TRANSPORT:-auto} -- mosh-client $host $port
expect {
    "Nothing received from server"   { send_user "\nFAIL: handshake never completed\n"; exit 3 }
    "Connection refused"             { send_user "\nFAIL: connection refused\n"; exit 4 }
    "Could not connect"              { send_user "\nFAIL: connect error\n"; exit 4 }
    eof                              { send_user "\nFAIL: client exited unexpectedly\n"; exit 7 }
    timeout                          { send_user "\nOK: session alive past ${deadline}s\n" }
}
exec kill [exp_pid] 2>/dev/null
expect eof
exit 0
EXP
chmod +x "$work/drive.exp"

case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*)
    # The hub itself holds the unwrapped mosh-server. We need a wrapped
    # client on a real peer to test the WG path. SSH to arm64.
    PEER="${MOSH_PEER:-root@51.15.66.128}"
    PEER_API="${MOSH_PEER_API:-http://127.0.0.1:9092}"
    PEER_WRAPPER="${MOSH_PEER_WRAPPER:-/usr/local/bin/uwgwrapper}"
    server_host="${MOSH_SERVER_HOST:-10.200.0.1}"  # hub's WG addr, reachable from peer
    bind_ip="127.0.0.1"
    ;;
  *)
    # Wrapped client lives here. mosh-server lives on the hub.
    PEER=""
    server_host="${MOSH_SERVER_HOST:-10.200.0.1}"
    bind_ip="${MOSH_SERVER_BIND:-127.0.0.1}"
    ;;
esac

start=$(date +%s.%N)
# Start mosh-server on the hub side (unwrapped). On hub: locally;
# elsewhere: assume an external operator started it (or we ssh into
# hub — but that needs hub's ssh allowed; skip for simplicity).
if [[ "$CATALOG_HOST" =~ ^(hub|.*amd64-host.*) ]]; then
  mosh-server new -i "$bind_ip" -p "$port" -- /bin/sleep 60 >"$work/srv.out" 2>&1
fi
# Non-hub: pull the key by sshing to hub and starting mosh-server there.
if [[ -z "${PEER+x}" ]] || [[ "$CATALOG_HOST" != hub && "$CATALOG_HOST" != *amd64-host* ]]; then
  HUB="${MOSH_HUB:-root@hub.example}"  # caller must override; skipping if unset
  if [[ "$HUB" == "root@hub.example" ]]; then
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-mosh-hub 0 \
      "set MOSH_HUB=user@host to point at a host that can start mosh-server"
    exit 0
  fi
  ssh -o BatchMode=yes "$HUB" "mosh-server new -i $bind_ip -p $port -- /bin/sleep 60" >"$work/srv.out" 2>&1
fi
key=$(grep 'MOSH CONNECT' "$work/srv.out" 2>/dev/null | awk '{print $4}')
if [[ -z "$key" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-mosh-key 0 \
    "mosh-server failed to start; out: $(head -c 240 $work/srv.out)"
  exit 0
fi

err="$work/cli.err"
if [[ -n "${PEER:-}" ]]; then
  # Hub-only path: drive the wrapped client from arm64 over ssh.
  scp -q "$work/drive.exp" "$PEER:/tmp/uwg-mosh-drive.exp"
  out=$(ssh -o BatchMode=yes "$PEER" "chmod +x /tmp/uwg-mosh-drive.exp && /tmp/uwg-mosh-drive.exp '$PEER_WRAPPER' '$PEER_API' '$server_host' '$port' '$key' 5" 2>"$err") || true
else
  out=$("$work/drive.exp" "$UWGWRAPPER_BIN" "$UWGSOCKS_API" "$server_host" "$port" "$key" 5 2>"$err") || true
fi
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
if grep -q 'OK: session alive' <<<"$out"; then
  wrapped_ok=true
fi

notes="server=$bind_ip:$port via $server_host | out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 200 $err 2>/dev/null | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
