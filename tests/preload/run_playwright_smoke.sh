#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

export PLAYWRIGHT_BROWSERS_PATH="$workdir/ms-playwright"
export DEBIAN_FRONTEND=noninteractive
export UWGS_RUN_HEADLESS_CHROME_SMOKE=1

pushd "$workdir" >/dev/null
npm init -y >/dev/null 2>&1
npm install --silent playwright@1.54.2
npx playwright install-deps chromium
npx playwright install chromium-headless-shell
popd >/dev/null

export UWGS_CHROME_BIN
UWGS_CHROME_BIN=$(find "$workdir/ms-playwright" -path '*/chrome-linux/headless_shell' -print -quit)
if [[ -z "${UWGS_CHROME_BIN:-}" ]]; then
  echo "failed to locate installed headless_shell" >&2
  exit 1
fi

control_dir="$workdir/control"
mkdir -p "$control_dir"
node "$repo_root/tests/preload/testdata/node_http_server.js" 127.0.0.1 18091 "$control_dir/mark.txt" >"$control_dir/server.out" 2>"$control_dir/server.err" &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; rm -rf "$workdir"' EXIT
for _ in $(seq 1 50); do
  if grep -q '^READY$' "$control_dir/server.out" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
"$UWGS_CHROME_BIN" --headless --no-sandbox --disable-gpu --virtual-time-budget=5000 --dump-dom http://127.0.0.1:18091/ >"$control_dir/browser.out" 2>"$control_dir/browser.err"
grep -q 'script-ok:204' "$control_dir/browser.out"
grep -q 'chrome-post-ok' "$control_dir/mark.txt"
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true

cd "$repo_root"
go test ./tests/preload -run TestUWGWrapperNodeHeadlessChromeSmoke -count=1 -v
