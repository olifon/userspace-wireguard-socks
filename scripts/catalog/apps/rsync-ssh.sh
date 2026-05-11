#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# rsync over ssh: wrap rsync, copy a small fixture to a peer through
# ssh (which itself is wrapped, since rsync execs `ssh` as its
# transport), verify the file arrived intact on the receiving side.
#
# Why it's a meaner test than the existing `ssh` + `git` rows:
#   - ssh.sh only opens a TCP banner read against a wrapped sshd port.
#   - git.sh fork-execs git-remote-https → curl; clean linear exec
#     chain, all over HTTPS.
#   - rsync over ssh: rsync forks an ssh child, the two communicate
#     via stdin/stdout pipes carrying rsync's incremental protocol.
#     The wrapper has to (a) trace the exec child, (b) keep the
#     in-flight pipes connected across that exec, and (c) the ssh
#     child itself opens a TCP connection through the wrapper. Three
#     things at once.
#
# Topology:
#   - Source side wraps rsync. The ssh child is wrapped by the same
#     wrapper (exec inheritance). ssh dials peer via WG addr.
#   - Destination side: the peer's existing sshd writes the file.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="rsync-ssh"
if ! bin_exists rsync || ! bin_exists ssh; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y rsync openssh-client"
  exit 0
fi

# Peer to copy to. Defaults to arm64; hub-side test ssh's to arm64.
# Non-hub hosts ssh back to hub.
case "$CATALOG_HOST" in
  hub|*amd64-host*|*hub*)
    PEER="${RSYNC_PEER:-root@10.200.0.3}"
    ;;
  *)
    PEER="${RSYNC_PEER:-root@10.200.0.1}"
    ;;
esac

work=$(mktemp -d)
# Cleanup must go through the wrapper too — peer's WG addr isn't on a host
# kernel route, so unwrapped ssh would get "Network is unreachable".
trap '"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- ssh -o BatchMode=yes "$PEER" "rm -f /tmp/uwg-rsync-recv-$$.txt" 2>/dev/null; rm -rf "$work"' EXIT

# Fixture: 16 KiB of deterministic data so rsync's delta protocol
# has actual structure to drive.
SRC="$work/src.bin"
yes "uwg-rsync-payload-line" | head -n 700 > "$SRC"
checksum=$(sha256sum "$SRC" | awk '{print $1}')
DST="/tmp/uwg-rsync-recv-$$.txt"

err="$work/wrapper.err"
start=$(date +%s.%N)
"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    rsync -e 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
          "$SRC" "${PEER}:${DST}" 2>"$err"
rsync_exit=$?
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# Verify the file made it intact. The peer's WG addr isn't on a host
# kernel route (uwgsocks is userspace), so the verification ssh must go
# through the wrapper too — same path the rsync used.
recv_sum=""
if [[ $rsync_exit -eq 0 ]]; then
  recv_sum=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
      ssh -o BatchMode=yes "$PEER" "sha256sum $DST 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || true
fi

wrapped_ok=false
if [[ -n "$recv_sum" && "$recv_sum" == "$checksum" ]]; then
  wrapped_ok=true
fi

notes="peer=$PEER size=$(stat -c %s $SRC)B rsync_exit=$rsync_exit sha-match=$([ "$recv_sum" == "$checksum" ] && echo yes || echo no) | err-tail: $(tail -c 240 $err | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
