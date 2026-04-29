<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# uwgsocks coverage audit

**Scope.** Behavior coverage under production for the `uwgsocks`
runtime — does each load-bearing invariant have at least one
integration test that asserts on it under a production-shaped
load? Not statement coverage. Not "is the function called"; "is
the function correct under stress, edge cases, and adversarial
inputs."

**Status as of `eeed108` (priorities 1–3 from the original triage list have
shipped; 4 is in progress as the v1 24h soak; 5 remains open and is
blocked on engine-API surface).**

Scoring legend:

- ✅ — load-bearing invariants have integration coverage; failure
  modes covered include adversarial / fuzz / stress.
- ⚠️ — happy-path covered but specific failure modes (timeouts,
  partial sends, malformed input, resource exhaustion, race
  windows) are not asserted.
- ❌ — minimal or no behavioral coverage.

Ordering is roughly by production-blast-radius (engine /
transport / proxy / ACL first; minor utilities last).

## 1. `internal/engine/`  ✅

LoC: 12838 across 32 test files. The largest single Go package
in the repo and the one that would corrupt user data if it
breaks. Coverage is genuinely thorough.

What's covered (representative, not exhaustive):
- WireGuard tunnel bring-up + handshake (`integration_test.go`).
- Routing decision order: local-tunnel → reverse-forwards → peer
  AllowedIPs → outbound proxy → direct dial. `engine_routing_*`
  tests.
- Connection-table grace + overflow.
- Per-connection MSS clamping for inbound TCP.
- Per-peer ACL enforcement (inbound + outbound + relay).
- Userspace conntrack for relay traffic.
- ICMP errors (PMTUD, host-unreachable) translated correctly.
- DNS server (in-tunnel) + `/v1/resolve` HTTP DoH.
- Runtime API mutations (peer add/remove, ACL replace) without
  restart.
- Mesh-control client/server (peer sync, dynamic ACL projection).
- Traffic shaping (token bucket).
- Fuzz tests for the proxy and the wg-quick parser
  (`tests/malicious/fuzz_test.go`).

Gaps worth filling:
- ⚠️ **Long-running soak**: 24h/7d connection-table churn under
  many short-lived flows. We have stress tests but they're under a
  minute. A multi-hour run would surface table-eviction races
  that the current tests miss.
- ⚠️ **Mesh-control under partition**: peer-sync convergence after
  the mesh-control server briefly becomes unreachable. The current
  tests assume the control plane is always up.
- ⚠️ **Roaming endpoint update during high traffic**: WireGuard
  endpoint changes mid-session under load. Has been validated
  manually; no automated assertion.

## 2. `internal/transport/`  ⚠️

LoC: 7528 across 6 test files. Multiple outer transports
(UDP/TCP/TLS/DTLS/HTTP/HTTPS/QUIC/TURN), each with client + listener
paths.

What's covered:
- Each base transport's listener accepts a session and round-trips
  WireGuard packets.
- WebSocket framing for HTTP/HTTPS transports (frame parsing has
  explicit upper bounds — fuzz coverage exists for the parser).
- QUIC + WebTransport coexistence on the same socket (RFC 9220).
- TURN over UDP/TCP/TLS/DTLS/HTTP/HTTPS/QUIC.
- Roaming reconnect across stream-oriented transports.

Gaps worth filling:
- ✅ **Conformance matrix**: shipped in `eeed108` —
  `TestTransportConformanceMatrix` table-drives every
  connection-oriented transport (TCP/TLS/DTLS/WS-HTTP/WS-HTTPS/
  QUIC) through the same Listen+Accept+Dial+round-trip flow with
  a primer + 10 client→server + 10 reverse round-trips. UDP is
  intentionally excluded: UDP listener sessions are
  one-packet-by-design (each datagram its own session), so the
  multi-iter shape doesn't apply; UDP is covered by the existing
  `TestBindRoamingAcrossTransports`.
- ⚠️ **Adversarial transport peer**: a peer that sends malformed
  WireGuard frames at high rate. Outer-transport-layer DoS
  resistance has not been measured. The QUIC accept queue is
  protected, but TCP/TLS listener overload behaviour is unknown.
- ⚠️ **Long-soak QUIC**: QUIC sessions held open for hours, with
  occasional packet loss. We have basic QUIC tests but not the
  long-soak.

## 3. `internal/uwgtrace/`  ⚠️

LoC: 7552 across 2 test files. The Linux ptrace tracer used by
`transport=ptrace*` and (less so now) `transport=systrap*`'s
fallback paths.

What's covered:
- `tests/preload/ptrace_test.go` exercises every wrapper transport
  mode (preload, systrap, ptrace, ptrace-seccomp, ptrace-only)
  through the C stub_client + Go raw_client.
- TestPtraceNonblockConnectFlow: 5 transports × 3 socket modes.
- TestUWGWrapperBindReuseAcrossTransports: bind/listen across
  modes.
- TestUWGWrapperCurlAcrossTransports: real-world `curl` under
  each mode.

Gaps:
- ⚠️ **Multi-threaded tracee under ptrace**: We have basic tests
  but not stress. Each thread of a multi-threaded tracee gets its
  own ptrace session; thread enter/exit during heavy traffic
  could race the tracer's bookkeeping.
- ⚠️ **Tracee dies mid-syscall**: tracer behaviour when the
  tracee is killed during a traced syscall (race between
  PTRACE_CONT and SIGKILL). No deterministic assertion.

## 4. `internal/fdproxy/`  ⚠️

LoC: 1932 across 3 test files. The wrapper-side socket-bridge that
serves `/uwg/socket` (control plane) to the in-process preload .so
and to the wrapper's tracer process.

What's covered:
- Connect / listen / accept / close protocol round-trips.
- TCP listener bind + reuse semantics.
- UDP socket creation + bind.
- Stress test (`TestStress`): many concurrent flows.

Gaps:
- ⚠️ **Resource-exhaustion**: out-of-fd response when the kernel
  refuses to give us another tunnel-fd socket. Not asserted.
- ⚠️ **Authenticated control plane**: when the wrapper's API
  token is set, fdproxy must reject unauthenticated callers. The
  unauthenticated-unix path is well-covered; the rejection path
  is asserted in only one test.
- ⚠️ **/uwg/socket protocol fuzz**: line-level protocol parsing.
  We don't fuzz the socket-protocol layer the same way we fuzz
  the wg-quick parser.

## 5. `internal/config/`  ⚠️

LoC: 2128 across 3 test files. YAML parser, wg-quick parser, `#!`
directive parser, transport-tag URL splitter.

What's covered:
- YAML round-trips + validation.
- wg-quick `#!TURN=`, `#!URL=`, `#!Control=`, `#!TCP[=...]`,
  `#!SkipVerifyTLS=yes` directives.
- Tag-split scheme parsing (e.g., `turn+wss://`, `quic+ws://`).
- Fuzz coverage for the wg-quick parser.

Gaps:
- ⚠️ **Live runtime API config-replacement under load**: the
  documented "uwgsocks-ui pushes peer/ACL updates live" path. The
  unit test exists but doesn't run with concurrent traffic on
  the engine.
- ⚠️ **Malformed YAML edge cases**: deeply nested structures, very
  long strings, unicode-in-keys. We have happy-path + fuzz; the
  middle ground (production-shaped malformed input) is thin.

## 6. `internal/tun/`  ⚠️

LoC: 1090 across 8 test files. Host-TUN backend abstraction (Linux,
macOS, Windows, FreeBSD, OpenBSD).

What's covered:
- Real Linux TUN configure-small-route smoke
  (`TestRealLinuxTUNConfigureSmallRoute`, gated by env).
- Real macOS UTUN smoke (gated).
- Real Windows wintun smoke (gated).
- Cross-platform manager-abstraction unit tests.

Gaps:
- ⚠️ **BSD real-host validation**: FreeBSD/OpenBSD test code exists
  but only runs manually on a real host (we don't have a CI image).
  This was acknowledged in the user-facing docs.
- ⚠️ **DNS automation on BSD**: `tun.dns_resolv_conf` is meant to
  be the safe cross-platform mechanism; the BSD path's resolv-conf
  rewriting hasn't been asserted in a CI test.

## 7. `internal/socketproto/`  ✅

LoC: 368, 1 test file (`protocol_test.go`, 491 LoC, 21 test
functions). Direct unit tests for the wire format added in
`31935ab` after the initial audit. Closes the original ❌ gap.

## 8. `internal/acl/`  ✅

LoC: 296, 1 test file (`acl_test.go`, 637 LoC, 28 test
functions). Direct unit tests for the rule parser + matcher
added in `900e4c1` after the initial audit. Closes the original
❌ gap.

## 9. `internal/wgbind/`  ⚠️

LoC: 440, 1 test file. Bind layer between WireGuard and the
transport/dialer registry.

What's covered:
- Single test exercises the registry-based dialer-selection.

Gap: covered by integration via `internal/transport` tests
indirectly, but the bind-rebind path during roaming endpoint
updates lacks dedicated assertion.

## 10. `internal/netstackex/`  ⚠️

LoC: 1420 across 2 test files. gVisor netstack helpers (MSS
clamping, tun-integration shims).

What's covered:
- MSS-clamp tests.
- TUN-integration shim happy path.

Gap: The interaction with gVisor's connection-table eviction
under heavy churn isn't separately covered; relies on the engine
integration tests.

## 11. `internal/uwgshared/`  ⚠️

LoC: 752, 1 test file. Shared-state + lock primitives for the
preload / wrapper / tracer cross-process state.

What's covered:
- Basic store/lookup/clear round-trip.

Gap: lock primitives are exercised by the C-level fxlock stress
tests in `tests/preload/`, but the Go-side reader of the shared
state (used by the ptracer) doesn't have its own concurrent
stress test. The cross-process invariants (Go-tracer reads while
.so writes) are asserted in
`tests/preload/phase1_fxlock_test.go` only at the C level.

## Cross-cutting gaps

These don't fit a single package but matter in production:

1. **24-hour leak soak.** We have short stress tests; long
   soaks would surface goroutine leaks, fd leaks, and
   connection-table accumulation. Memory: user said "24h leak
   soak on VPSes" was post-release work.

2. **Real-world workload coverage** (some shipped):
   - ✅ Chromium under systrap-supervised against real internet
     (example.com / wikipedia.org / youtube.com).
   - ✅ Minecraft Paper server under wrapper, real WG tunnel.
   - ⚠️ Electron app — discussed but not yet wired.
   - ❌ Long-running browser session (multi-hour youtube video
     keeping a session warm).

3. **Multiple concurrent uwgsocks instances** on the same host
   sharing nothing (different config files, different ports). We
   have single-instance tests.

4. **Concurrent runtime-API mutations** (peer add + ACL replace
   + traffic-shaper update happening simultaneously while traffic
   flows). The individual mutations are tested; their
   composition isn't.

## Priority for triage

Suggested order to close the gaps, by user-impact:

1. ✅ **`internal/acl/` direct tests** — shipped in `900e4c1`.
2. ✅ **`internal/socketproto/` direct tests** — shipped in `31935ab`.
3. ✅ **Transport conformance matrix** — shipped in `eeed108`.
4. **24-hour leak soak harness** (in progress as the v1
   pre-release run; see `soak-runs.md`).
5. **Mesh-control under partition** (open; tracked as task #73,
   blocked on engine API surface for clean partition injection).

Items 1–3 landed as separate small PRs over the v0.1.x train per
the user-stated collaboration model.
