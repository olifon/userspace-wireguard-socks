#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
# Synthetic JVM HTTP probe — small, fast, covers the JIT path. The full
# minecraft-server boot test is in java-minecraft.sh.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="java-http"
if ! bin_exists java; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y default-jdk-headless"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/Probe.java" <<'JAVA'
import java.net.*; import java.io.*;
public class Probe {
  public static void main(String[] args) throws Exception {
    HttpURLConnection c = (HttpURLConnection) new URL(args[0]).openConnection();
    c.setConnectTimeout(8000); c.setReadTimeout(8000);
    System.out.println(c.getResponseCode());
  }
}
JAVA
javac "$work/Probe.java" 2>/dev/null || { record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "no-javac" 0 "javac missing"; exit 0; }

start=$(date +%s.%N)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=${CATALOG_TRANSPORT:-auto} -v -- \
    java -cp "$work" Probe "$MESH_PROBE_URL" 2>&1) || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' <<<"$out"; then
  transport=$(grep 'auto: chose ' <<<"$out" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$out" == *"200"* || "$out" == *"204"* ]] && wrapped_ok=true

notes="out: $(printf '%s' "$out" | head -c 300)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
