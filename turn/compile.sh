#!/bin/sh
set -eu

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "${ROOT_DIR}"

if ! command -v go >/dev/null 2>&1; then
  if [ -x "${HOME}/sdk/go/bin/go" ]; then
    export PATH="${HOME}/sdk/go/bin:${PATH}"
  fi
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain not found on PATH. Install Go 1.24+ or add it to PATH." >&2
  exit 127
fi

go build -trimpath -ldflags='-s -w' -o turn .
