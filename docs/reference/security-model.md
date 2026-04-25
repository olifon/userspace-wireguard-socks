<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Security Model

This document describes the trust boundaries `uwgsocks`, `uwgwrapper`,
`uwgfdproxy`, and the standalone `turn` daemon are designed to enforce, the
defenses each surface relies on, and the deliberate non-goals. Read this
before extending any of those surfaces or before deploying in a multi-tenant
environment.

The security model is structural — it tells you *what* the project is
trying to protect against and *why* — not a changelog. For audit findings
and patches, see the project's git history.

## Trust boundaries

Every byte the daemon processes comes from a source with a defined trust
level. Surfaces that look similar from outside (HTTP proxy vs admin API,
WireGuard tunnel vs mesh control) have very different trust contracts.

### Untrusted sources

These produce bytes the daemon must treat as adversarial — bounds-checked,
size-capped, panic-free, race-free, and never allowed to execute code.

| Source | Where it enters | Why untrusted |
|---|---|---|
| Outer WireGuard packets (UDP, TCP, TLS, DTLS, HTTP/HTTPS, QUIC, TURN carriers) | `internal/transport/*`, `internal/wgbind/` | Anyone on the network path can send these. |
| Tunneled L4 traffic (TCP, UDP, ICMP) inside the tunnel | `internal/engine/transport.go`, `relay_conntrack.go`, `icmp_*.go` | Any peer can craft any inner packet, including malformed ICMP errors with embedded inner-headers. |
| DNS hostnames being resolved | `internal/engine/socks.go`, the DNS server, `/v1/resolve` | Hostnames come from applications using the proxy or the tunnel. |
| Application data over TCP/UDP through proxies (SOCKS5, HTTP, raw socket API) | `internal/engine/socks.go`, `proxy_protocol.go`, `socket_api.go` | Apps may be malicious or compromised. |
| SOCKS5 / HTTP proxy clients connecting to the daemon | the proxy listeners | The proxy listener is intended for *internal* use (LAN, container, host), not the wide internet. Still: hostile bytes from *internal* attackers are real. |
| Mesh control clients | `internal/engine/mesh_control.go` | Anyone who can handshake on the WireGuard tunnel can hit `/v1/challenge`, `/v1/peers`, `/v1/acls`. |
| `fdproxy` clients arriving at the `uwgsocks` API socket | `internal/engine/socket_api.go` via `fdproxy.go` | The `fdproxy` daemon is per-user, but a corrupted/buggy client still must not be able to crash `uwgsocks`. |
| `wg-quick` `.ini` configs from the network | `internal/config/config.go` (strict variants) | A user can paste a downloaded config into the runtime API. |

### Trusted sources

These have at least one credential check between them and the daemon.

| Source | Defense |
|---|---|
| YAML config (`--config`) | File on disk, supplied by the operator. |
| Runtime admin API (`/v1/*` plus `/uwg/*`) | Bearer token (`api.token`); optionally the `AllowUnauthenticatedUnix` flag declares a Unix socket trusted. |
| Application running under `uwgwrapper` / preload | Same uid as the wrapper, lives inside the wrapper sandbox. |
| `fdproxy` listener as seen by its own preload clients | Per-user Unix socket: `0o600` mode + `0o077` umask + Linux `SO_PEERCRED` check on accept (other uids rejected even if the socket file is somehow readable). |

### Explicit non-goals

- **The HTTP / SOCKS5 proxy listeners are not for the wide-open internet.**
  They are intended for internal/LAN/container use. There is no per-IP
  rate limit on the proxy listeners by design — that trades ergonomics for
  a defense the deployment doesn't need. RCE-class bugs on those surfaces
  are taken extremely seriously; DoS resistance is an explicit non-goal.
- **`uwgwrapper` is Linux-only.** Its preload + ptrace + seccomp paths
  depend on Linux ABI details. Don't assume macOS/BSD portability.
- **The mesh control plane is not a full SD-WAN controller.** It is a
  small, opt-in peer-discovery + ACL-distribution surface.

## Per-surface defenses

This section describes the load-bearing defenses on each untrusted
surface. If you change code in one of these areas, read this first; the
defenses are not always obvious from the call graph.

### Outer WireGuard transports

Every transport (UDP, TCP, TLS, DTLS, HTTP/HTTPS WebSocket and raw upgrade,
QUIC including WebTransport, TURN over each of those) terminates hostile
bytes from the public network. Concrete invariants:

- **Frame size caps before allocation.** WebSocket payload length is
  validated against `maxWireGuardPacket` *before* the buffer is
  `make([]byte, payLen)`'d (`internal/transport/websocket.go`). The same
  pattern repeats in `tcp.go`'s `streamSession.ReadPacket`. Do not allocate
  a wire-derived length without a clamp first.
- **Concurrent connection caps.** The TURN HTTP/WebSocket and WebTransport
  carriers cap their `peers` map at 4096 concurrent sessions to bound
  memory and goroutine count under upgrade floods
  (`internal/transport/turn_carriers.go`).
- **HTTP header size caps.** WebSocket / TURN HTTP listeners set
  `MaxHeaderBytes: 32 KiB` instead of Go's 1 MiB default.
- **TURN allocation cap.** The standalone TURN daemon's pending-allocation
  queue has a hard cap (`turn/open_turn_pion.go: maxPendingAllocations`).

### Tunneled L4 (gVisor netstack inbound)

Per-packet handlers parse IPv4/IPv6 headers, transport headers (TCP/UDP),
and ICMP error inner packets. Concrete invariants:

- **Header bounds checked at every layer.** `parseRelayPacket` checks
  `len==0`, `parseRelayIPv4Packet` requires `>=20`, `parseRelayIPv6Packet`
  requires `>=40`, `packetPorts` requires `>=4`, TCP flags read is gated by
  `>=14`. ICMP error inner-packet parsing reuses these checks.
- **Conntrack table cap.** `relay_conntrack.go` enforces both global
  (`relay.conntrack_max_flows`) and per-peer (`relay.conntrack_max_per_peer`)
  caps so a chatty peer can't fill the table.
- **Stateless relay fallback is gated.** The conntrack-bypass fallback for
  roaming/direct/relay transitions only runs under specific conditions
  (mesh trust mode or explicit per-peer flag). Keep that gate strict; a
  permissive fallback would let an attacker bypass relay ACLs by walking
  source ports.

### Mesh control (`/v1/challenge`, `/v1/peers`, `/v1/acls`, `/v1/resolve` aliases)

The mesh listener is reachable by any peer that successfully handshakes on
the WireGuard tunnel. Defenses:

- **Per-source-IP token bucket** (10 rps, burst 20, max 4096 buckets,
  oldest-evicted) wraps the entire mesh mux. WG peers are not trusted; a
  flooder peer cannot keep the mesh control loop hot or evict legitimate
  peer state.
- **Challenge / token (v2)** binds the server's static key into the auth
  key (defense in depth against future challenge-ephemeral compromise).
  v1 tokens are no longer accepted.
- **Constant-time secret comparison** for the bearer token and the
  ECDH-derived shared secret (`subtle.ConstantTimeCompare`).
- **Body size caps** on every JSON-decoding handler
  (`io.LimitReader`-wrapped `io.ReadAll`).
- **Dynamic peers never override static peers of the same key.** This is a
  hard invariant; `meshPeerConfig` is the one place that resolves the
  conflict and it always favors the static entry.

### Runtime admin API + `fdproxy` socket-API client

- **`AllowUnauthenticatedUnix` is the operator's explicit declaration**
  that anyone who can `connect(2)` to that socket is trusted with the
  whole admin surface — including `/v1/socket` (which can dial anywhere)
  and `/v1/resolve`. The flag is honored uniformly across endpoints; there
  are no carve-outs.
- **Token comparison is constant-time.**
- **Reading the token is dynamic** (per-request lookup against the live
  config), so rotating the token via the API takes effect immediately.

### SOCKS5 / HTTP proxy listeners (internal use)

- **`proxy.username` is optional.** When unset, only the password is
  validated; clients may present any username (or none). This makes the
  proxy usable as a password-only endpoint for newer integrations.
- **Per-conn UDP cap of 256 sessions, global SOCKS conn cap of 1024.**
  Bounds memory under abusive *internal* clients.
- **Handshake deadline (10s)** for SOCKS, request deadline (30s) for the
  request phase, idle timeouts for tunnels.
- **No per-IP rate limit by design** (see "Explicit non-goals").

### Outbound HTTP CONNECT proxy dialer

- **Fresh additive 10s deadline** around the CONNECT write+read, on top of
  whatever the caller's context deadline is. A nearly-exhausted context
  cannot leave a partial CONNECT line on a keep-alive proxy
  (request-smuggling shape).

### `uwgwrapper` + preload trust boundary

- **Preload is per-user.** The `fdproxy` Unix socket is bound under
  `umask 0o077` so the file is `0o600` from the moment it appears in the
  filesystem (closing the chmod race window) and the server enforces
  `SO_PEERCRED` on accept on Linux. Other uids are rejected even if the
  socket inode is somehow accessible.
- **Within a single user, the wrapped application is trusted.** The
  preload's shared-state region is `PROT_WRITE` mapped — that is by
  design, not a vulnerability. A malicious app can already do anything
  the user can do.
- **`uwgwrapper` is Linux-only.** macOS/BSD ports of `uwgsocks` and `turn`
  exist; the wrapper does not.

### `wg-quick` INI parsing

- **Two parser variants:** `MergeWGQuick` (lenient — operator-supplied)
  and `MergeWGQuickStrict` (drops `PreUp`/`PostUp`/`PreDown`/`PostDown`
  silently, used for hostile sources like the runtime API and YAML loads
  with `scripts.allow=false`).
- **Other wg-quick fields and `#!` directives stay accepted by design.**
  `Endpoint`, `AllowedIPs`, `#!Control`, `#!URL`, `#!TURN`,
  `#!SkipVerifyTLS` describe how to talk to a peer or where to find
  dynamic mesh information — that is under the peer's control.
- **Engine-layer guard (`scripts.allow=false`)** is the second line of
  defense even if a hook key somehow slipped through.

## Defense-in-depth conventions

Patterns to follow when adding new code in any of these areas:

1. **Size-cap before allocation.** Validate any wire-derived length
   against an explicit upper bound *before* `make([]byte, n)`. The bound
   should reference a named constant (e.g. `maxWireGuardPacket`,
   `DefaultMaxPayload`).
2. **Constant-time comparison for secrets.** Always
   `subtle.ConstantTimeCompare`; never `==` or `bytes.Equal` for
   token/HMAC/PSK material.
3. **Bound concurrent state.** A new peer/session/connection map needs an
   entry cap and an eviction policy. The mesh control rate-limiter map
   and the TURN carrier `peers` map are the working examples.
4. **Capture, don't read.** Goroutines that outlive a bind/open/close
   cycle should *capture* synchronization channels at creation time, not
   re-read them from a struct field — see `internal/transport/bind.go`'s
   `acceptLoop`.
5. **Lock-order is `s.mu → g.mu`** in the `fdproxy` package. Never the
   reverse (deadlock).
6. **Pre-existing tunables should be `atomic.*` if a test mutates them.**
   The `tunnelDNSTCPDeadline` migration is the working example. A
   package-level `var X = 10 * time.Second` that any test rewrites is a
   data race waiting to happen under `-race`.

## Reporting a security issue

Open a GitHub issue *only* for low-severity / informational findings. For
anything that looks like RCE, sandbox escape, or auth bypass, please email
the maintainer directly so a fix can ship before public disclosure.
