#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Run the in-process perf baseline on this host (no SSH, no real
# network — just two engines on loopback in the same process).
# Outputs to stdout in markdown row format and tee'd to a file.
#
# Usage:
#   bash tests/perf/scripts/run-loopback.sh [output-prefix]

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

OUT="${1:-/tmp/uwgs-perf-loopback}"
TS=$(date -u +"%Y-%m-%dT%H-%M-%SZ")
OUTFILE="${OUT}-${TS}.txt"

echo "perf run: $(uname -a)" | tee "$OUTFILE"
echo "go version: $(go version)" | tee -a "$OUTFILE"
echo "uwgsocks at: $(git rev-parse HEAD)" | tee -a "$OUTFILE"
echo "started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee -a "$OUTFILE"
echo | tee -a "$OUTFILE"

UWGS_PERF=1 go test -tags perf -count=1 -timeout 600s \
    -run "^TestPerf" -v ./tests/perf/ 2>&1 | \
    tee -a "$OUTFILE" | grep -E "^(=== RUN|---|PERFRESULT|MARKDOWN)"

echo | tee -a "$OUTFILE"
echo "finished: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee -a "$OUTFILE"
echo "full log: $OUTFILE"
