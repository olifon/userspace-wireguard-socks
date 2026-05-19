<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Changelog

All notable changes to this project. Format follows [Keep a
Changelog](https://keepachangelog.com/) loosely. Date format is
ISO-8601.

See `STABILITY.md` for the compatibility promise that takes effect
at v1.0.0.

## Unreleased — v1.0.0 preparation

This section is the running v1.0.0 changelog. It will be split
into per-release sections as tags are cut.

### Added

- **Three-tier test cadence** documented in
  `docs/contributing/testing.md`. Pre-commit (≤10s wall) runs
  `go test -short`; tier 2 (`test.yml`) runs every push; tier 3
  (`release.yml`) runs chaos / soak / fuzz on tag push.
- **Mesh-control chaos suite** in `internal/engine/mesh_chaos_*_test.go`:
  6 tests gated `UWGS_RUN_MESH_CHAOS=1` covering 5-peer foundation,
  lossy direct path, advertised-endpoint NAT translation, 100%-drop
  relay failover, source-port rebind, and TCP-outer mid-stream drop.
- **M2 crash/recovery chaos**: hub process restart, multi-instance
  host, runtime-API mutations under load.
- **Performance baseline harness** under `tests/perf/` (gated
  `UWGS_PERF=1` + `//go:build perf`). Loopback TCP throughput +
  latency. Reference numbers and orchestrator scripts in
  `docs/operations/performance.md`.
- **Generated config reference** — `docs/reference/config-reference.md`
  is now produced from `internal/config/` struct tags + comments
  via `tools/genconfigref`. The pre-commit hook fails if the
  on-disk file drifts or if any field lacks a docstring.
- **Grafana dashboard** in `dashboards/uwgsocks-overview.json`
  covering build info, peer counts, throughput, conntrack table
  size, mesh-control request rates, and the cumulative drop /
  refusal / retransmit / roaming-change counters.
- **TURN guard fuzz target** + adversarial-flood test (`turn/`
  package, gated by build, runs in tier-3 release CI).
- **gVisor smoke step** in `release.yml` (amd64 only) — runs
  `uwgwrapper preload curl example.com` and `uwgwrapper systrap
  curl example.com` under `runsc do`.

### Changed

- **Wrapper transport names finalised**: canonical set is
  `preload`, `systrap`, `systrap-static`, `systrap-supervised`,
  `ptrace`, `ptrace-seccomp`, `ptrace-only`, `auto`. The old
  aliases `preload-static`, `preload-and-ptrace`,
  `preload-with-optional-ptrace` are **removed** (not deprecated).
  This is the last breaking rename pre-1.0.
- **Inbound default connection caps non-zero**:
  `inbound.max_connections` defaults to 16384,
  `inbound.max_connections_per_peer` to 4096. Previously both
  were 0 (unlimited), which made the engine OOM-vulnerable to
  inbound SYN floods.
- **SOCKS UDP buffer sized down**: `socksUDPSessionBufBytes`
  reduced from 64 KiB to 8 KiB; `maxSOCKSUDPSessionsPerConn` from
  256 to 64. Worst-case SOCKS5 memory bound: 16 GiB → 512 MiB.
- **Documentation reorganised** into `docs/{features, operations,
  reference, contributing, howto}/`. The old `docs/reference/{
  acls, mesh-control, metrics, proxy-routing, security-model,
  testing, transport-modes, turn, wrapper-modes}.md` files have
  been moved (see git history for redirects).
- **Mesh chaos tests gated `//go:build !race`**: gVisor's
  process-global buffer pool surfaces a race the per-tun lock
  can't cover. Chaos coverage runs without `-race`.

### Fixed

- **bind.go panic on Kind/type mismatch**: bare `ep.(*Type)` type
  assertions in `MultiTransportBind.Send` are now guarded with
  `, ok` and return an error. A future refactor or buggy transport
  can no longer take the engine process down.
- **preload `recvmmsg`/`sendmmsg` vlen unbounded loop**: caller-
  controlled `vlen` was passed directly to `for (i = 0; i < vlen;
  ++i)`. Capped at `UWG_MMSG_VLEN_CAP=1024` (matches the kernel's
  `UIO_MAXIOV`).
- **bind.go `closeOnceSession` wrapper**: defensive idempotency
  guard prevents the `updatePeerEndpoint` grace-close goroutine
  from racing the `serveConnSession` defer on the same Session.
- **bind.go `reconnectPeer` TOCTOU**: dialed sessions are now
  Closed cleanly when a concurrent runtime-API mutation
  invalidates the peer state during the dial-without-lock window.
- **Pre-commit hook config-drift check**: `tools/genconfigref
  --check` and `--audit` now run as steps 4-5 of the pre-commit
  hook, catching new config fields without docstrings.
- **gvisor netstack pool race**: the `internal/netstackex/tun.go`
  per-netTun mutex was promoted to package-level briefly, then
  reverted because cross-engine serialisation broke chaos tests
  on slow CI. Mesh chaos suite now `!race`-gated; the per-tun
  lock is sufficient for production (one engine per process).
- **`--allow-uid` shared-state file world-writable**: the shared-
  state file under `/tmp/uwgwrapper-$UID/` was `chmod 0o666` when
  any `--allow-uid` flag was set, making it writable by all users
  on the host. Fixed with `chown` to the first allowed UID; mode
  stays `0o600`. The fdproxy socket intentionally remains `0o666`
  — its real access gate is `SO_PEERCRED`.
- **`si_code` guard in SIGSYS handler**: a `kill(pid, SIGSYS)` or
  `tgkill` directed at a wrapped process hit the handler with
  `si_code = SI_USER`/`SI_TKILL`; the handler read garbage
  `si_syscall` and dispatched a nonsensical syscall number. Fixed
  with an early `si->si_code != SYS_SECCOMP` guard that terminates
  the process cleanly via `exit_group(128 + SIGSYS)`.
- **Thread table slots 256 → 4096**: under high-churn thread
  workloads the 256-slot table filled with stale-live entries from
  TID recycling; new threads silently inherited dead sigaltstacks.
  Expanded to 4096 slots.
- **x86-64 clone child path clobbered RSI and R9**: the
  `FUTEX_WAKE` call in the clone asm overwrote RSI (Go runtime uses
  `mov %rsi,%rsp` to restore the stack) and R9 (Go's nil-g guard).
  Children SIGSEGV'd at `[0xfffffffffffffff9]`. Fixed by
  saving/restoring both registers around the futex syscall.
- **aarch64 clone child path pre-placed data overwrite**: the
  child-stack guard written before `clone()` was silently
  overwritten on aarch64; children read garbage values. Fixed with
  an arch-conditional write guard.
- **sigaltstack not installed for glibc<2.34 / musl `clone` paths**:
  glibc 2.34+ unified `pthread_create` with `clone`; older glibc
  and musl still use raw `SYS_clone`. The preload now intercepts
  `SYS_clone` directly to install the per-thread sigaltstack on
  those targets.
- **glibc-2.27 / ubuntu:18.04 `clone3` compatibility**: ubuntu
  18.04's glibc predates `clone3`; the handler emitted `ENOSYS`.
  Fixed with a `clone3` → `clone` fallback that applies the same
  sigaltstack setup.
- **musl `posix_spawn` SIGSYS stack overflow**: musl uses
  `clone(CLONE_VM|CLONE_VFORK)` with a ~1 KB internal child stack.
  The `CLONE_VFORK` exclusion in `need_ss` prevented sigaltstack
  setup in the vfork child; the BPF SIGSYS handler then fell back
  to the 1 KB stack and overflowed → SIGSEGV. Fixed by removing the
  exclusion and zeroing `futex_ptr` for vfork children so the
  parent doesn't stall on a futex the exec'd child never signals.
- **fdproxy pipe-inheritance hang under `CombinedOutput`**: when
  the test harness used `CombinedOutput`, fdproxy inherited the
  pipe's write end; the pipe never closed and the parent blocked
  indefinitely. Fixed with a dedicated `os.Pipe()` for the fdproxy
  subprocess.

### Removed

- Wrapper transport aliases `preload-static`, `preload-and-ptrace`,
  `preload-with-optional-ptrace`.
- `transport.WebSocketConfig.SNIHostname` (use `tls.server_sni`).
- `proxy.type=turn` legacy form (use `base: turn`).
- `TestUWGWrapperBothMixedInterop` — the cross-tracer-cache test
  that asserted on `preload-and-ptrace` semantics; coverage moved
  to `TestSystrapSupervisedDynamicExecsStatic`.

## v0.1.0-beta.* — pre-cleanup

The beta train was the v0 development line. Many breaking changes
landed in this train; consult the git log for specific commits.
The "Unreleased" section above captures the cleanups + additions
relative to the latest beta as of writing.
