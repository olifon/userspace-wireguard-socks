#!/usr/bin/env bash
# coverage.sh — full coverage report including binary-instrumented child processes.
#
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# What this does
# --------------
# 1. Runs all Go tests with -coverpkg=./... so cross-package calls are counted.
# 2. On Linux with gcc available, the tests/preload/ suite builds the wrapper
#    binary with -cover (via UWGS_COVER_BINDIR) and each spawned wrapper
#    instance writes binary coverage data to a subdirectory.
# 3. go tool covdata merges those per-invocation dirs and converts to the
#    standard text profile format.
# 4. A Python snippet deduplicates both profiles (max count per location) and
#    merges them into a single file.
# 5. Prints a per-package table sorted by coverage percentage.
#
# Usage
# -----
#   bash scripts/coverage.sh              # full run (~5-10 min on linux)
#   bash scripts/coverage.sh --short      # fast run, skips integration tests
#   bash scripts/coverage.sh --html       # open HTML report after run
#
# Output files
# ------------
#   /tmp/uwg_coverage_last.out   — text profile (reusable with go tool cover)
#
# Requirements
# ------------
#   Go 1.20+  (for go tool covdata)
#   python3
#   Linux + gcc   (for binary coverage of uwgwrapper; optional, skipped on other OSes)

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

WORKDIR="$(mktemp -d /tmp/uwg_cov_XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

COV_BINDIR="$WORKDIR/binary_cov"
COV_MAIN="$WORKDIR/main.out"
COV_BINARY_TEXT="$WORKDIR/binary_text.out"
COV_MERGED="/tmp/uwg_coverage_last.out"

mkdir -p "$COV_BINDIR"

SHORT_FLAG=""
OPEN_HTML=0
for arg in "$@"; do
    case "$arg" in
        --short) SHORT_FLAG="-short" ;;
        --html)  OPEN_HTML=1 ;;
    esac
done

# Packages to test (all Go packages that have tests).
# tests/preload is linux-only; the test helpers skip gracefully on other OSes.
TEST_PKGS=(
    .
    ./internal/acl/...
    ./internal/config/...
    ./internal/engine/...
    ./internal/fdproxy/...
    ./internal/netstackex/...
    ./internal/socketproto/...
    ./internal/testconfig/...
    ./internal/transport/...
    ./internal/tun/...
    ./internal/uwgshared/...
    ./internal/uwgtrace/...
    ./internal/wgbind/...
    ./cmd/uwgsocks/...
    ./cmd/uwgwrapper/...
    ./tests/malicious/...
    ./tests/soak/...
    ./tests/preload/...
)

echo "==> uwgsocks coverage run  (workdir: $WORKDIR)"
echo "    short=$( [ -n "$SHORT_FLAG" ] && echo yes || echo no )"
echo "    binary instrumentation: $( [ "$(uname -s)" = Linux ] && echo enabled || echo disabled )"
echo ""

# Run all tests. On Linux with UWGS_COVER_BINDIR set the test helpers build
# the wrapper binary with -cover and each invocation writes to a unique subdir.
UWGS_COVER_BINDIR="$COV_BINDIR" \
go test \
    -count=1 \
    -timeout 600s \
    ${SHORT_FLAG} \
    -coverpkg=./... \
    -coverprofile="$COV_MAIN" \
    "${TEST_PKGS[@]}" \
    2>&1 | tee "$WORKDIR/test_output.log" || true   # don't abort on test failures

echo ""

# ── Binary coverage merge ──────────────────────────────────────────────────

RUN_DIRS=( "$COV_BINDIR"/run_* )
if [ -d "${RUN_DIRS[0]}" ] 2>/dev/null; then
    echo "==> Merging binary coverage from ${#RUN_DIRS[@]} wrapper invocation(s)..."
    MERGED_BINARY="$WORKDIR/merged_binary"
    mkdir -p "$MERGED_BINARY"
    # go tool covdata merge requires Go 1.20+
    go tool covdata merge -i="$COV_BINDIR" -o="$MERGED_BINARY" 2>/dev/null || {
        echo "    (go tool covdata not available — binary coverage skipped; needs Go 1.20+)"
        touch "$COV_BINARY_TEXT"
    }
    if [ ! -f "$COV_BINARY_TEXT" ]; then
        go tool covdata textfmt -i="$MERGED_BINARY" -o="$COV_BINARY_TEXT" 2>/dev/null || touch "$COV_BINARY_TEXT"
    fi
else
    echo "    (no binary coverage data written — preload tests skipped or no gcc)"
    touch "$COV_BINARY_TEXT"
fi

# ── Profile merge + report ─────────────────────────────────────────────────

python3 - "$COV_MAIN" "$COV_BINARY_TEXT" "$COV_MERGED" << 'PYEOF'
import sys, os
from collections import defaultdict

module = "github.com/reindertpelsma/userspace-wireguard-socks"

def parse(path):
    best = {}  # loc -> (numstmts, max_count)
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("mode:") or not line:
                    continue
                try:
                    loc, stmts, count = line.rsplit(" ", 2)
                    n, c = int(stmts), int(count)
                    if loc not in best or c > best[loc][1]:
                        best[loc] = (n, c)
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    return best

merged = parse(sys.argv[1])
for loc, (n, c) in parse(sys.argv[2]).items():
    if loc not in merged or c > merged[loc][1]:
        merged[loc] = (n, c)

with open(sys.argv[3], "w") as f:
    f.write("mode: set\n")
    for loc, (n, c) in merged.items():
        f.write(f"{loc} {n} {c}\n")

# Per-package stats.
pkg_stats = defaultdict(lambda: [0, 0])
for loc, (n, c) in merged.items():
    file_path = loc.split(":")[0]
    pkg = file_path.rsplit("/", 1)[0]
    pkg = pkg.replace(module + "/", "").replace(module, "(root)")
    pkg_stats[pkg][1] += n
    if c > 0:
        pkg_stats[pkg][0] += n

total_cov   = sum(v[0] for v in pkg_stats.values())
total_stmts = sum(v[1] for v in pkg_stats.values())
overall     = (total_cov / total_stmts * 100) if total_stmts else 0

BARS = 20

def bar(pct):
    filled = round(pct / 100 * BARS)
    return "█" * filled + "░" * (BARS - filled)

def label(pct):
    if pct >= 80: return " ✓"
    if pct >= 60: return "  "
    if pct >= 30: return " !"
    return " ✗"

print(f"\n{'Package':<42} {'Cov%':>6}  {'':<{BARS}}  Covered / Total")
print("─" * 85)
for pkg in sorted(pkg_stats, key=lambda p: -pkg_stats[p][0]/max(pkg_stats[p][1],1)):
    cov, tot = pkg_stats[pkg]
    pct = (cov / tot * 100) if tot else 0.0
    print(f"{pkg:<42} {pct:>5.1f}%  {bar(pct)}  {cov:>7} / {tot}{label(pct)}")
print("─" * 85)
print(f"{'TOTAL':<42} {overall:>5.1f}%  {bar(overall)}  {total_cov:>7} / {total_stmts}")
print(f"\nProfile: {sys.argv[3]}")
print(f"  go tool cover -html={sys.argv[3]}  (browse by file)")
PYEOF

if [ "$OPEN_HTML" -eq 1 ]; then
    echo ""
    echo "==> Opening HTML report..."
    go tool cover -html="$COV_MERGED"
fi

echo ""
# Summarise test failures from log.
FAILS=$(grep -c "^--- FAIL\|^FAIL\t" "$WORKDIR/test_output.log" 2>/dev/null || true)
if [ "$FAILS" -gt 0 ]; then
    echo "NOTE: $FAILS test failure line(s) detected — coverage numbers reflect passing tests only."
    echo "      Full log: $WORKDIR/test_output.log (check before relying on this run)"
fi
