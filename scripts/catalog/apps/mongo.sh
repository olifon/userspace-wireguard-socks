#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# MongoDB `mongosh` client through the wrapper.  We spin up an ephemeral
# mongo:7 container, then run `db.runCommand({ping:1})` via wrapper.
# Set MONGO_TARGET=host:port to point at an existing mongo server.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="mongo"
if ! bin_exists mongosh && ! bin_exists mongo; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: https://www.mongodb.com/docs/mongodb-shell/install/"
  exit 0
fi
client=$(command -v mongosh || command -v mongo)

MONGOTARGET="${MONGO_TARGET:-}"
spun_container=""
trap '[[ -n "$spun_container" ]] && docker rm -f "$spun_container" >/dev/null 2>&1; true' EXIT

if [[ -z "$MONGOTARGET" ]]; then
  if ! command -v docker >/dev/null; then
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-docker 0 "no MONGO_TARGET and docker unavailable"
    exit 0
  fi
  spun_container="uwg-catalog-mongo-$$"
  if ! docker run -d --name "$spun_container" --rm \
        -p 127.0.0.1:57017:27017 \
        mongo:7 >/dev/null 2>&1; then
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" docker-failed 0 "docker run mongo:7 failed"
    exit 0
  fi
  MONGOTARGET="127.0.0.1:57017"
  for i in $(seq 1 60); do
    if docker exec "$spun_container" mongosh --quiet --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; then break; fi
    sleep 0.5
  done
fi

err=$(mktemp)
start=$(date +%s.%N)
# Use ping command; success returns `{ ok: 1 }`.
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    "$client" --quiet "mongodb://$MONGOTARGET/test" --eval 'JSON.stringify(db.runCommand({ping:1}))' 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$out" == *'"ok":1'* || "$out" == *'ok: 1'* ]] && wrapped_ok=true

notes="target=$MONGOTARGET (container=${spun_container:-external}) | out: $(printf '%s' "$out" | head -c 240) | err-tail: $(tail -c 240 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
