#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# PostgreSQL `psql` client through the wrapper. The test connects to a
# Postgres server reachable through the mesh and runs `SELECT 1`. We use
# a Docker-hosted Postgres instance for the server side because it's
# self-contained.  Set POSTGRES_TARGET=host:port if you already have a
# Postgres server reachable through the tunnel.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="postgres"
if ! bin_exists psql; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "install: apt-get install -y postgresql-client"
  exit 0
fi

# If no target supplied, spin up an ephemeral postgres container.
PGTARGET="${POSTGRES_TARGET:-}"
spun_container=""
trap '[[ -n "$spun_container" ]] && docker rm -f "$spun_container" >/dev/null 2>&1; true' EXIT

if [[ -z "$PGTARGET" ]]; then
  if ! command -v docker >/dev/null; then
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-docker 0 "no POSTGRES_TARGET and docker unavailable; pass POSTGRES_TARGET=host:port"
    exit 0
  fi
  spun_container="uwg-catalog-pg-$$"
  if ! docker run -d --name "$spun_container" --rm \
        -e POSTGRES_PASSWORD=uwgcatalog -e POSTGRES_USER=uwg \
        -e POSTGRES_DB=uwgdb -p 127.0.0.1:55432:5432 \
        postgres:16-alpine >/dev/null 2>&1; then
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" docker-failed 0 "docker run postgres:16-alpine failed"
    exit 0
  fi
  PGTARGET="127.0.0.1:55432"
  # Wait until psql can actually run a query (pg_isready returns ok before
  # the server finishes initdb on a cold container).  Max 30s.
  for i in $(seq 1 60); do
    if PGPASSWORD=uwgcatalog psql -h 127.0.0.1 -p 55432 -U uwg -d uwgdb -tAc 'SELECT 1' >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
fi

host="${PGTARGET%%:*}"
port="${PGTARGET#*:}"

err=$(mktemp)
start=$(date +%s.%N)
out=$(PGPASSWORD=uwgcatalog "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    psql -h "$host" -p "$port" -U uwg -d uwgdb -tAc "SELECT 'wrapper-pg-ok'" 2>"$err") || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$out" == *"wrapper-pg-ok"* ]] && wrapped_ok=true

notes="target=$PGTARGET (container=${spun_container:-external}) | out: $(printf '%s' "$out" | head -c 200) | err-tail: $(tail -c 240 "$err" | tr '\n' '|')"
rm -f "$err"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
