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

err="$work/wrapper.err"
log_out="$work/server.log"
start=$(date +%s.%N)
# Start server under wrapper, non-interactive (no stdin).
( cd "$work" && \
  "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    "$JAVA_BIN" -Xmx512M -Xms256M -jar paper.jar --nogui </dev/null >"$log_out" 2>"$err" ) &
srvpid=$!

# Wait up to 120s for "Done (" line or port to open.
ok=false
for i in $(seq 1 240); do
  if grep -q 'Done (' "$log_out" 2>/dev/null; then
    ok=true; break
  fi
  # Or accept early proof: port open
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
[[ "$ok" == "true" && "$listener_ok" == "true" ]] && wrapped_ok=true

# Capture relevant log tail.
tail_log=$(tail -c 1500 "$log_out" | tr '\n' '|' | head -c 1500)
notes="paper-version=$PAPER_VER build=$PAPER_BUILD | done-line=$ok listener=$listener_ok | log-tail: $tail_log | err-tail: $(tail -c 400 "$err" | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
