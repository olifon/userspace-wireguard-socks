#!/usr/bin/env bash
# Run go test ./... for exotic architectures locally using Docker + QEMU.
# Requires Docker Desktop (or Docker with binfmt_misc QEMU support installed).
# On macOS Apple Silicon, linux/arm64 is native; others are emulated via QEMU.
#
# Usage: ./scripts/test-exotic-arches.sh [arch...]
#   arch: riscv64 | mips | mipsle | arm64 | amd64 | all (default: all)
#
# Note: mips/mipsle are big/little-endian MIPS32. riscv64 requires a Go image
# that ships with riscv64 support (golang:1.21+ on linux/riscv64).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

GO_VERSION="$(grep '^go ' go.mod | awk '{print $2}')"

DEFAULT_ARCHES=(riscv64 mips mipsle)

ARCHES=("$@")
if [[ ${#ARCHES[@]} -eq 0 || "${ARCHES[0]}" == "all" ]]; then
  ARCHES=("${DEFAULT_ARCHES[@]}")
fi

run_tests() {
  local arch="$1"
  local platform="linux/${arch}"
  echo "==> Testing on ${platform}"
  docker run --rm \
    --platform "${platform}" \
    -v "${ROOT_DIR}:/workspace" \
    -w /workspace \
    --cap-add SYS_PTRACE \
    --security-opt seccomp=unconfined \
    "golang:${GO_VERSION}-alpine" \
    sh -c "apk add --no-cache gcc musl-dev linux-headers 2>/dev/null; go test ./..."
  echo "==> PASS: ${platform}"
}

for arch in "${ARCHES[@]}"; do
  run_tests "${arch}"
done

echo ""
echo "All requested platforms passed."
