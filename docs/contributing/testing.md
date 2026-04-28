<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Testing

This project is intentionally tested without root, real `/dev/net/tun`, public
Internet dependencies, or container privileges. The tests run WireGuard, gVisor
netstack, SOCKS5/HTTP proxy paths, transparent forwarding, optional host TUN
logic through a fake TUN device, DNS, relay, and API behavior as normal Go
processes.

## Three-tier cadence

By cost. Pre-commit must stay ≤ 10s wall — anything slower drives developers
to `git commit --no-verify` reflexively, which defeats the hook.

| Tier | Trigger | Wall | Scope |
|---|---|---|---|
| 1 | `scripts/precommit.sh` (or `go test -short`) | ≤ 10s | unit + parser + ACL + protocol round-trips |
| 2 | `test.yml` per push | minutes | full `go test ./...` + lite + race + cross-arch |
| 3 | `release.yml` tag-only | up to ~30 min | chaos + soak + fuzz + multi-glibc + gVisor smoke |

Tests opt out of tier 1 with `if testing.Short() { t.Skip(...) }`. The
load-bearing helpers that gate this for entire categories of test:

| Helper | File | Effect |
|---|---|---|
| `mustStart` | `internal/engine/integration_test.go` | full WG engine; tier-1-skip |
| `mustStartMeshEngine` | `internal/engine/mesh_control_test.go` | mesh-control engine; tier-1-skip |
| `requirePhase1Toolchain` | `tests/preload/phase1_smoke_test.go` | Phase 1 wrapper build; tier-1-skip |
| `requireWrapperToolchain` | `tests/preload/ptrace_test.go` | wrapper integration; tier-1-skip |

## Build tags

Test files can be gated by Go build tags. Combine with `&&` / `!`.

| Tag | Where it's used | Effect when set |
|---|---|---|
| `lite` | `internal/transport/registry_lite.go`, `internal/engine/mesh_control_lite.go` | Compile the slim feature set: no mesh-control, no traffic shaper, no TURN, no advanced transports. `go test -tags lite ./...` exercises only what's reachable in the lite build. |
| `!lite` | most engine + transport tests | Skipped under `-tags lite`. The default build. |
| `race` | (none — used as `!race`) | `-race` enables Go's race detector. The mesh chaos suite is gated `!race` because gVisor's process-global buffer pool surfaces a third-party race that the per-tun lock can't cover; chaos coverage runs without `-race`. |
| `!race` | every `mesh_chaos_*_test.go` | The chaos suite skips under `-race` for the gVisor pool reason above. |
| `linux` | preload + ptrace + fdproxy paths | Linux-only, used everywhere wrapper integration is tested. |
| `darwin`, `freebsd`, `openbsd`, `windows` | platform-specific TUN backends | Platform-specific tests. |
| `linux && amd64`, `(linux \|\| android) && arm64` | architecture-specific assembly + ptrace ABIs | The systrap engine has arch-specific syscall numbers + register layouts. |
| `integration` | `turn/wireguard_integration_test.go` | Heavyweight TURN integration test that needs a real WG runtime. Not in the default suite. |
| `diag` | `tests/preload/*_diag_test.go` | Diagnostic-only tests that produce verbose output for debugging. Not in the default suite. |

## Environment variables

Every test gate found in the code, alphabetical. Tests check the env
var and either skip or activate.

| Variable | Tier | Default behaviour | What it does when set |
|---|---|---|---|
| `UWGS_RUN_MESH_CHAOS=1` | 3 | every chaos test skips | enables `TestMeshChaosResume_*` (`internal/engine/mesh_chaos_*_test.go`) — UDP/TCP middleman tests, hub-restart, runtime-mutation chaos, etc. Tier-3 release-only. |
| `UWGS_STRESS=1` | 3 | stress-grade tests skip | enables `TestStress*` (`internal/fdproxy/*_test.go`) lock-model stress tests + `TestMesh4PeerDynamicACLAndFallback`. |
| `UWGS_SOAK=1` | 3 | soak skips | enables `TestLoopbackImpairedChattySOCKSSoak` (`tests/soak/`). Pair with `UWGS_SOAK_SECONDS` for duration. |
| `UWGS_SOAK_SECONDS=N` | 3 | n/a | sets the soak run duration in seconds. CI uses 15; release uses 86400 (24h). |
| `UWGS_RUN_HEADLESS_CHROME_SMOKE=1` | 3 | skip | enables `TestUWGWrapperNodeHeadlessChromeSmoke` and friends (`tests/preload/`) — chromium under wrapper, real-internet. Pair with `UWGS_CHROME_BIN`. |
| `UWGS_RUN_PHASE1_HEADLESS_CHROME_SMOKE=1` | 3 | skip | Phase 1 (libc-only preload) variant of the above. |
| `UWGS_RUN_CHROMIUM_SUPERVISED=1` | 3 | skip | enables `TestPhase1HeadlessChromeSmoke` under `systrap-supervised` (chromium with execve re-arm across the zygote). |
| `UWGS_RUN_CHROMIUM_REAL_INTERNET=1` | 3 | skip | extends the chromium smokes to real-internet endpoints (`example.com`, wikipedia, youtube). |
| `UWGS_CHROME_BIN=PATH` | 3 | n/a | path to the chromium / chrome-headless-shell binary the smoke uses. |
| `UWGS_BROWSER_SMOKE_TRANSPORT=name` | 3 | n/a | which wrapper transport mode the chromium smoke runs (`systrap`, `systrap-supervised`, `preload`, etc.). Used by the multi-libc Docker matrix. |
| `UWGS_RUN_STDIO_HEAVY_DIAG=1` | 3 | skip | enables stdio-mode heavy diagnostic tests — verbose, slow. |
| `UWGS_STRICT_STDIO_HOTPATH=1` | 3 | skip | turns stdio-mode hot-path assertions from "advisory" to "fatal" — used to debug hot-path correctness regressions. |
| `UWGS_STATIC_BLOB=PATH` | 3 | n/a | path to a freestanding `uwgpreload-static-{arch}.so` blob; `tests/preload/phase2_*_test.go` use it for Phase 2 (static-binary) injection scenarios. |
| `UWGS_PERF=1` | 3 | perf scripts skip | enables `tests/perf/*_test.go` performance baseline scripts (build-tag-gated `perf` too). |
| `UWGS_TEST_DEBUG=1` | 1-3 | quiet | enables verbose engine/test logging across most suites. |
| `UWGS_TEST_DEBUG_STRESS=1` | 1-3 | quiet | same as above, scoped to stress-test paths. |
| `UWGS_FDPROXY_PEERCRED_HELPER=PATH` | 1 | n/a | path to a binary used as a fdproxy peer-cred helper in `internal/fdproxy/` tests. |
| `UWGS_FDPROXY_PEERCRED_PATH=PATH` | 1 | n/a | unix-socket path the peer-cred helper listens on. |
| `UWG_TEST_REAL_TUN=1` | 3 | skip | enables real-host TUN smokes: `TestRealLinuxTUNConfigureSmallRoute`, `TestRealUTUNConfigureSmallRoute`, `TestRealWindowsTUNConfigureSmallRoute`. Needs root or platform-equivalent. |
| `UWG_TEST_REAL_TUN_DEFAULT=1` | 3 | skip | extends the real-TUN smokes to add/remove default routes — DESTRUCTIVE on a host. |
| `UWG_TEST_EXAMPLES=1` | 2 | skip | enables tests in `examples/` that need bundled-example fixtures. |

## Useful commands

```bash
# Tier 1 — pre-commit
bash scripts/precommit.sh

# Tier 2 — per-push CI shape
go test ./...
go test -tags lite ./...
go test -race ./internal/engine ./internal/transport ./internal/fdproxy \
    ./tests/malicious ./tests/preload

# Tier 3 — release-only chaos
UWGS_RUN_MESH_CHAOS=1 go test -count=1 -timeout 900s \
    -run 'TestMeshChaosResume_' ./internal/engine/

# Tier 3 — soak
UWGS_SOAK=1 UWGS_SOAK_SECONDS=86400 go test \
    -run TestLoopbackImpairedChattySOCKSSoak \
    -count=1 -timeout 25h ./tests/soak

# Tier 3 — wrapper stress
UWGS_STRESS=1 go test -race ./internal/fdproxy -run TestStress

# Tier 3 — fuzz the untrusted-input parsers
go test ./tests/malicious -run '^$' -fuzz '^FuzzMergeWGQuickStrict$' -fuzztime 30s
go test ./tests/malicious -run '^$' -fuzz '^FuzzACLParseRule$' -fuzztime 30s
go test ./tests/malicious -run '^$' -fuzz '^FuzzConfigParsers$' -fuzztime 30s
```

## Adding a new test that costs >1s

1. Write the test as you normally would.
2. Decide which tier it belongs to:
   - **Tier 1**: it must finish in well under a second; skip everything else.
   - **Tier 2**: under 10 seconds; use `if testing.Short() { t.Skip(...) }` to keep tier 1 clean.
   - **Tier 3**: chaos / soak / fuzz / requires-special-host. Gate behind a new env var (document it in the table above) and add a tier-3 step in `release.yml`.
3. If the test brings up a full `Engine` + WireGuard, route construction through one of the existing `mustStart*` helpers — those already have the tier-1 skip wired in.

## Threat model — what tests must protect

These are the properties tests and review should protect:

- Proxy clients must not get remote code execution.
- WireGuard peers must not reach host loopback unless host forwarding is explicitly enabled for that path.
- ACL bypass must not happen for inbound, outbound, or relay traffic.
- Malformed WireGuard, IP, TCP, UDP, ICMP, DNS, SOCKS5, and HTTP proxy inputs must not panic or allocate unbounded memory.
- The API must not expose private or preshared key material and must not allow unauthenticated mutation on non-loopback sockets.
- DNS must not silently fall back to system DNS when `DNS=` is configured for tunnel resolution.
- Tables and buffers must be bounded: connection states, transparent TCP receive windows, DNS transactions, SOCKS UDP sessions, and relay/forward state.

## Current Automated Coverage

Run:

```bash
go test ./...
go test -race ./internal/config ./internal/engine ./tests/malicious ./tests/preload
go test ./internal/engine -run '^$' -bench BenchmarkLoopbackSOCKSThroughput -benchtime=3x
./tests/iperf_loopback.sh
```

Real host-TUN smoke tests are opt-in and require privileges:

```bash
UWG_TEST_REAL_TUN=1 sudo go test ./internal/tun -run 'TestReal.*SmallRoute'
UWG_TEST_REAL_TUN=1 UWG_TEST_REAL_TUN_DEFAULT=1 docker run --rm --privileged -v "$PWD":/src -w /src golang:1.25 bash -lc '/usr/local/go/bin/go test ./internal/tun -run "TestRealLinuxTUNConfigure(SmallRoute|DefaultRoutes)" -count=1'
```

Those tests intentionally separate the local-host small-route path from the
privileged-container default-route path so developers do not accidentally black
hole their own workstation traffic while still keeping `0.0.0.0/0` and `::/0`
coverage in automation.

The main suite covers:

- Two-instance WireGuard TCP/UDP data paths.
- SOCKS5 CONNECT, UDP ASSOCIATE, and BIND.
- HTTP proxy GET and CONNECT.
- IPv4 and IPv6 tunnel traffic, IPv6 outer endpoints, and ICMP/ICMPv6 ping.
- Optional host TUN TCP flows over IPv4 and IPv6 using an in-memory fake TUN
  device instead of requiring `CAP_NET_ADMIN`.
- Local forwards and reverse forwards for TCP/UDP.
- PROXY protocol v1/v2 parsing, stripping, and injection.
- Reverse-forward reachability from SOCKS clients.
- Transparent inbound TCP/UDP termination to host sockets.
- Outbound proxy fallback lists for SOCKS-originated and WireGuard-inbound traffic.
- Most-specific-prefix routing for overlapping `AllowedIPs` and outbound proxy subnets.
- Host forwarding defaults and virtual `Address=` subnet rejection.
- Reserved IPv4 and IPv6 tunnel-address filtering.
- Source IP enforcement against malicious WireGuard peers.
- Relay forwarding allow and deny ACL behavior, including stateful TCP, UDP,
  ICMP echo, ICMP error, IPv6, expiry, and conntrack limit cases.
- API peer, ACL, status, ping, and runtime forward operations.
- API mutation while traffic is flowing with many ACL rules.
- Raw socket API TCP, UDP, UDP reconnect/disconnect, TCP listener/accept, DNS frame, and malformed-frame behavior.
- Linux LD_PRELOAD managed-fd proof path for connected TCP, connected UDP, unconnected UDP, TCP listener accept, duplicated fds, fork inheritance, selected exec inheritance, and malicious manager-input rejection through `uwgfdproxy`.
- DNS-over-WireGuard resolution and tunnel-hosted DNS transaction behavior.
- Malformed parser and packet fuzz seeds.
- Packet loss, jitter, tail-drop-like queue overflow, and multi-stream transfer.
- Connection table overflow grace and transparent TCP memory budget behavior.
- Per-peer transparent connection-table isolation and traffic-shaper TCP pacing.

`tests/iperf_loopback.sh` builds `uwgsocks` when needed, writes temporary
demo WireGuard configs, starts two binaries, exposes an iperf3 server through a
server-side reverse-forward and a client-side local TCP/UDP forward, runs TCP
and UDP iperf3 clients, prints a JSON-derived summary, then cleans up.

## Coverage Plan For Remaining Gaps

Keep adding tests in this order:

1. `cmd/uwgsocks`: table-test flag combinations with `--check` through `exec.CommandContext`, especially repeated `--peer`, `--forward`, `--reverse-forward`, and `--outbound-proxy`. This is startup glue, so it is lower risk than packet handling.
2. Mixed proxy listener: one test that speaks SOCKS5 and one that speaks HTTP to the same `mixed` listener.
3. API item paths: negative tests for `/v1/peers/{public_key}`, bad peer keys, bad ACL list names, bad forward definitions, and method-not-allowed responses.
4. Transparent UDP error paths: force host dial failure and assert the ICMP unreachable packet is emitted to the tunnel path.
5. DNS TCP transaction exhaustion: mirror the existing UDP max-inflight test for TCP.
6. Static endpoint roaming fallback: make the endpoint change, stop handshakes, and assert the configured endpoint is restored without waiting for a long real timer.
7. Additional fuzz targets for HTTP CONNECT parsing and SOCKS5 UDP datagram parsing with length caps.

Very small pure helpers such as `max`, `minPositive`, and string-formatting wrappers are acceptable to leave covered indirectly unless they become security-sensitive.

## Manual Soak

For a release candidate, run two binaries for hours:

- Loopback impaired network with random latency, jitter, burst loss, and tail drops.
- Real VPS or commercial WireGuard exit with browser video, speed tests, and DNS-heavy browsing.
- Many concurrent SOCKS TCP flows and UDP ASSOCIATE flows.
- Periodic API peer, ACL, forward, and reverse-forward updates.
- Metrics collected from `/v1/status`: goroutine count from the process, heap from pprof if enabled externally, active connection table size, transfer counters, and last handshake.

Also run a real-world browser test through SOCKS5, including HTTP/3-capable
sites, because UDP behavior through SOCKS5 clients varies in practice.
