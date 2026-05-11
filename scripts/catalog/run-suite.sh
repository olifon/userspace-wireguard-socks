#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# scripts/catalog/run-suite.sh
# Drives every script under scripts/catalog/apps/ on the current host and
# writes per-app JSON results to scripts/catalog/results/<host>/.

set -u
cd "$(dirname "$0")"
. ./lib.sh

apps_dir="apps"
if [[ ! -d "$apps_dir" ]]; then
  echo "no apps/ dir found in $(pwd)" >&2
  exit 2
fi

# A pre-flight: assert the unwrapped probe genuinely fails before we start.
# If it does NOT fail, the test ceases to be discriminating — we still run
# but mark results unwrapped_blocked=false in every record.
log "pre-flight: unwrapped probe of $MESH_PROBE_URL ..."
unwrapped_blocked=$(require_unwrapped_blocked)
log "pre-flight: unwrapped_blocked=$unwrapped_blocked"

export UNWRAPPED_BLOCKED="$unwrapped_blocked"

declare -a sel=()
if [[ $# -gt 0 ]]; then
  for a in "$@"; do
    sel+=("$apps_dir/${a%.sh}.sh")
  done
else
  while IFS= read -r f; do sel+=("$f"); done < <(ls "$apps_dir"/*.sh 2>/dev/null | sort)
fi

pass=0; fail=0; skip=0
for app_script in "${sel[@]}"; do
  app=$(basename "$app_script" .sh)
  if [[ ! -f "$app_script" ]]; then
    log "skip $app — no script"
    skip=$((skip+1))
    continue
  fi
  log ">>> $app"
  start=$(date +%s.%N)
  if bash "$app_script"; then
    pass=$((pass+1))
    log "<<< $app PASS"
  else
    rc=$?
    fail=$((fail+1))
    log "<<< $app FAIL (rc=$rc)"
  fi
done

log "summary: pass=$pass fail=$fail skip=$skip"
