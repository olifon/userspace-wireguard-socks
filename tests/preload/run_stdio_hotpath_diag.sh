#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

export UWGS_RUN_STDIO_HEAVY_DIAG=1

cd "$repo_root"
go test ./tests/preload -run TestUWGWrapperBothStdIOHeavyStaysOffPtrace -count=1 -v "$@"
