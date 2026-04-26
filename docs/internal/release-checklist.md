<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Pre-release manual checklist

CI runs the full test matrix on every tag push (see `.github/workflows/
release.yml`), but a few things genuinely can't be exercised in CI and
need manual validation before cutting a release. Track them here.

## What CI does cover

`release.yml` runs across **linux-amd64, linux-arm64, macos, windows**:

- Plain `go test ./...`
- `go test -tags lite ./...`
- Cross-OS host-TUN smoke (per-platform variant)
- Standalone TURN tests
- 15s soak (`UWGS_SOAK=1`)
- `go test -race` on `internal/engine`, `internal/transport`,
  `internal/fdproxy`, `tests/malicious` (and `tests/preload` on Linux,
  since the preload itself is Linux-only)
- `UWGS_STRESS=1` stress tests for the fdproxy lock model
- 30s `-fuzz` runs on `FuzzMergeWGQuickStrict`, `FuzzACLParseRule`,
  `FuzzConfigParsers`
- Cross-builds for FreeBSD/OpenBSD on amd64+arm64
- Linux mips/mipsle/riscv64 (cross-build only)

If `release.yml` is green, the code is portable, race-clean (on the
runtimes CI exercises), and the documented attack surfaces are
fuzz-stable.

## What CI does NOT cover — manual validation

Every release should manually run at least the items marked **MUST**
below. Items marked **SHOULD** are best-effort but allowed to slip if
no recent change touches the relevant subsystem.

### MUST — pin behavior on real hosts at least once per release

1. **Real BSD validation (FreeBSD + OpenBSD).** CI cross-builds
   these but doesn't run-test (no GitHub-hosted BSD runners). Boot
   a VM or a real host and run:
   ```
   go test ./internal/tun
   ```
   Then start `uwgsocks` with a minimal config and verify a TCP
   round-trip works through the tunnel. The host-TUN backends
   (`internal/tun/tun_freebsd.go`, `tun_openbsd.go`) are the most
   fragile pieces because they depend on `/dev/tun*` + `ifconfig`
   conventions that vary across BSD distributions.
2. **gVisor-restricted kernel paths.** Several preload/wrapper tests
   auto-skip on gVisor (`runningRestrictedGVisor()` helper). On a
   real Linux host (a developer laptop is fine), confirm:
   ```
   go test ./tests/preload -count=1
   ```
   passes without the gVisor skips firing.
3. **24h+ soak.** CI runs a 15s soak. For a release, run a minimum
   24h soak under sustained load:
   ```
   UWGS_SOAK=1 UWGS_SOAK_SECONDS=86400 \
       go test ./tests/soak -run TestLoopbackImpairedChattySOCKSSoak \
       -count=1 -timeout 25h
   ```
   Watch for goroutine growth, file-descriptor growth, conntrack
   table growth that doesn't level off, and unexpected
   `uwgsocks_*_drops_total` increments via the metrics endpoint.

### SHOULD — when relevant subsystem changed

4. **Real-network mesh control between two hosts.** If
   `internal/engine/mesh_control.go` or any mesh-related config
   changed, set up two `uwgsocks` instances on separate machines (or
   network namespaces with simulated latency), enable mesh control,
   and verify peer discovery + ACL distribution work end-to-end. CI
   does this in-process with simulated peers, which doesn't catch
   real-network packet-loss or NAT-traversal edge cases.
5. **Real fdproxy + uwgwrapper integration.** If anything in
   `internal/fdproxy/`, `preload/`, `internal/uwgtrace/`, or
   `cmd/uwgwrapper/` changed, run the wrapper against a real
   browser (Chrome/Firefox) loading a network-heavy page through
   the tunnel. The headless-Chrome smoke
   (`tests/preload/run_playwright_smoke.sh`) covers the basic case
   but real-browser session resumption, websocket usage, and HTTP/3
   sometimes surface issues the smoke misses.
6. **Linux 32-bit (`linux/386`) runtime validation.** CI
   cross-builds 386 but doesn't run-test (Docker QEMU emulation
   crashes the Go runtime in our environment, see
   `tests/test-exotic-arches.sh` notes). If you need 386 support,
   validate on a real 32-bit host before claiming it.

### Things that look like they should be manual but aren't

- **TURN ingress under hostile load** — covered by the
  `turn_carriers.go` carrier-cap stress in `tests/malicious/` and the
  release-CI fuzz step.
- **Strict wg-quick parser** — fully covered by
  `FuzzMergeWGQuickStrict` in release CI.
- **Mesh control rate limiting** — unit-tested in
  `TestMeshControlRateLimiter`; the rate-limiter logic itself is
  pure Go and doesn't need real-network validation.

## When something breaks

If a manual check fails AND the relevant subsystem hasn't changed
since the last successful release, the failure is environmental
(BSD VM out of date, Linux kernel ABI shift, etc.) — note it but
don't block the release.

If a manual check fails AND the subsystem HAS changed, block the
release. Open a fix PR, repeat the manual check, then re-cut the
tag.
