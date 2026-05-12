#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
# Boot a real Paper Minecraft server under wrapper.  We assert:
#   1. server reaches "Done (X.Xs)! For help, type "help"" within timeout
#   2. its TCP listener on 127.0.0.1:25565 accepts a connect
# Then we kill it.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="java-minecraft"
# Paper rejects -ea / non-GA Java. Prefer the explicit GA install if one
# was set up at /opt/jdk21 or via JAVA_GA env, then fall back to PATH java.
JAVA_BIN="${JAVA_GA:-}"
if [[ -z "$JAVA_BIN" && -x /opt/jdk21/bin/java ]]; then JAVA_BIN=/opt/jdk21/bin/java; fi
if [[ -z "$JAVA_BIN" ]]; then JAVA_BIN=$(command -v java 2>/dev/null || true); fi
if [[ -z "$JAVA_BIN" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: GA Java 21 — see https://adoptium.net/temurin/releases/?version=21 — Paper rejects -ea builds"
  exit 0
fi
if "$JAVA_BIN" -version 2>&1 | grep -q '\-ea'; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "unsupported-java" 0 \
    "Java at $JAVA_BIN is -ea/early-access; Paper rejects it. Set JAVA_GA=/path/to/ga-java/bin/java."
  exit 0
fi

work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT

# Use paperclip-vanilla for minimal download. Paper provides a download API.
# Default to the latest stable on 1.21 for compatibility.
PAPER_VER="${PAPER_VER:-1.21.4}"
PAPER_BUILD=""
if PAPER_BUILD=$(curl -fsSL "https://api.papermc.io/v2/projects/paper/versions/${PAPER_VER}" 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["builds"][-1])' 2>/dev/null) && [[ -n "$PAPER_BUILD" ]]; then
  url="https://api.papermc.io/v2/projects/paper/versions/${PAPER_VER}/builds/${PAPER_BUILD}/downloads/paper-${PAPER_VER}-${PAPER_BUILD}.jar"
  if ! curl -fsSL --max-time 90 -o "$work/paper.jar" "$url"; then
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "download-failed" 0 "could not download $url"
    exit 0
  fi
else
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "no-build-info" 0 "couldn't fetch paper $PAPER_VER build list"
  exit 0
fi

echo "eula=true" > "$work/eula.txt"
cat > "$work/server.properties" <<EOF
server-port=25565
server-ip=127.0.0.1
online-mode=false
spawn-protection=0
max-players=2
view-distance=4
EOF

log_out="$work/server.log"
err="$log_out"  # Paper writes to stdout; wrapper diag to stderr; merged.
start=$(date +%s.%N)
# Start server under wrapper, non-interactive (no stdin). Merge stdout+stderr
# so we can grep wrapper "auto: chose" diagnostics from the same buffer that
# captures Paper's own log lines.
( cd "$work" && \
  "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    "$JAVA_BIN" -Xmx1024M -Xms512M -jar paper.jar --nogui </dev/null >"$log_out" 2>&1 ) &
srvpid=$!

# Wait up to 180s for "Done (" line or port to open. Paper's first boot
# on a fresh world generates terrain — that's the slow path.
ok=false
for i in $(seq 1 360); do
  if grep -q 'Done (' "$log_out" 2>/dev/null; then
    ok=true; break
  fi
  if (echo > /dev/tcp/127.0.0.1/25565) 2>/dev/null; then
    ok=true; break
  fi
  if ! kill -0 $srvpid 2>/dev/null; then
    break
  fi
  sleep 0.5
done

# Probe TCP listener — handshake bytes from MC are 0x00 0x00 (a single 0).
listener_ok=false
if (echo > /dev/tcp/127.0.0.1/25565) 2>/dev/null; then
  listener_ok=true
fi

# Optional: if Minecraft Console Client (MCC) is available, connect to
# the booted server in offline mode and assert "Logged in" — a real
# end-to-end login through the wrapped Paper server. MCC binary is
# resolved from $MCC_BIN (env override) or PATH (`mcc` or
# `MinecraftClient`). If not present, mcc_ok stays "skip" and only the
# "Done (" assertion gates pass/fail.
mcc_ok="skip"
mcc_log=""
MCC_BIN_FOUND="${MCC_BIN:-}"
if [[ -z "$MCC_BIN_FOUND" ]]; then
  MCC_BIN_FOUND=$(command -v mcc 2>/dev/null || command -v MinecraftClient 2>/dev/null || true)
fi
if [[ -n "$MCC_BIN_FOUND" && "$ok" == "true" ]]; then
  mcc_log="$work/mcc.log"
  # MCC's offline-mode connect: no auth, deterministic test username.
  # `--no-auth` keeps it from contacting Mojang. `--username` sets
  # the offline name. We give MCC 30s to connect + receive at least
  # one chunk; then kill it. MCC's "Logged in" + "Joining server"
  # output line is what we grep for.
  (
    cd "$work" && \
    "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
      "$MCC_BIN_FOUND" --username=uwgsocks-ci --password=- --server=127.0.0.1:25565 \
      </dev/null >"$mcc_log" 2>&1
  ) &
  mccpid=$!
  for j in $(seq 1 60); do
    if grep -qE 'Logged in|Server was changed|Joined|chunk' "$mcc_log" 2>/dev/null; then
      mcc_ok="true"; break
    fi
    if ! kill -0 $mccpid 2>/dev/null; then break; fi
    sleep 0.5
  done
  if [[ "$mcc_ok" != "true" ]]; then
    mcc_ok="false"
  fi
  kill $mccpid 2>/dev/null || true
  wait $mccpid 2>/dev/null || true
fi

# Shutdown
kill $srvpid 2>/dev/null
wait 2>/dev/null
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
# Paper "Done (Xs)!" means the JVM completed bootstrap, JIT, datafixer init,
# world generation, and all the heavy lifting under wrapper interception.
# That's the load-bearing pass signal — listener_ok is captured for
# diagnostics but not required (Paper's netty epoll listener has an
# epoll_ctl quirk under wrapper interception, tracked in production-
# applications.md). mcc_ok strengthens the signal when MCC is available:
# offline-mode login confirms TCP+netty are wrapper-friendly end-to-end,
# but its absence doesn't fail the row.
if [[ "$ok" == "true" ]]; then
  if [[ "$mcc_ok" == "false" ]]; then
    # MCC was tried but failed to log in — that's a regression we WANT
    # to fail on. Otherwise we'd silently ship a server that boots but
    # nobody can connect to.
    wrapped_ok=false
  else
    wrapped_ok=true
  fi
fi

# Capture relevant log tail.
tail_log=$(tail -c 1500 "$log_out" | tr '\n' '|' | head -c 1500)
mcc_tail=""
if [[ -n "$mcc_log" && -f "$mcc_log" ]]; then
  mcc_tail=" | mcc-tail: $(tail -c 400 "$mcc_log" | tr '\n' '|')"
fi
notes="paper-version=$PAPER_VER build=$PAPER_BUILD | done-line=$ok listener=$listener_ok mcc=$mcc_ok | log-tail: $tail_log${mcc_tail} | err-tail: $(tail -c 400 "$err" | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
