# userspace-wireguard-socks (uwgsocks)

## What this repository is
`uwgsocks` is a rootless userspace WireGuard gateway. It embeds WireGuard and a
userspace TCP/IP stack (gVisor netstack) so applications can use a WireGuard
tunnel without `/dev/net/tun`, root privileges, routing table changes, or a
system VPN interface.

The repository is broader than a simple SOCKS proxy:

- `uwgsocks` can act as both a WireGuard client and server.
- Applications can enter the tunnel through HTTP proxy, SOCKS5 proxy, local
  forwards, reverse forwards, the raw socket API, or the Go library surface.
- `uwgwrapper` can transparently route ordinary Linux applications through
  `uwgsocks` using `LD_PRELOAD`, fdproxy, and ptrace/seccomp-assisted tracing.
- `turn/` contains a standalone TURN relay server for relay-friendly UDP paths,
  fixed or dynamic relay-port control, and optional WireGuard-aware filtering.

The practical scope of the project is therefore:

- rootless WireGuard access for proxy-aware apps
- transparent Linux app routing without a system VPN
- pluggable transports for difficult networks
- relay / SD-WAN style peer forwarding
- local management/runtime API integration for external control planes

## Main binaries and deliverables
- `uwgsocks` — main binary: WireGuard engine, proxy server(s), raw socket API,
  DNS helper, forwarding engine, ACL engine, relay logic, and management API.
- `uwgwrapper` — Linux launcher for transparently routing existing applications
  through `uwgsocks`; embeds `uwgpreload.so` and can fall back across preload
  and ptrace modes depending on host capability.
- `turn/` — standalone TURN relay server used when peers need a deterministic
  relay-friendly UDP path or when public UDP exposure is awkward.

## Architectural model
At a high level:

1. `uwgsocks` runs WireGuard plus an embedded userspace network stack.
2. Host applications talk to it via SOCKS5, HTTP proxy, forwards, raw socket
   API, or the Linux wrapper path.
3. Packets are routed either to local tunnel addresses, reverse forwards, peer
   `AllowedIPs`, configured outbound proxy fallbacks, or direct host dials,
   depending on config and ACL policy.
4. WireGuard transport itself may be carried over plain UDP or alternative
   transports such as TCP/TLS/HTTP(S)/QUIC/DTLS/TURN.

Important behavioral properties called out in the docs:

- Destinations inside local `Address=` subnets but not covered by peer
  `AllowedIPs` are rejected instead of leaking to the host network.
- Transport config is startup-only; peer/ACL/forward changes can be updated
  live via the runtime API, but transport changes require restart.
- TLS on transports is optional convenience/obfuscation; WireGuard itself still
  provides the tunnel encryption/authentication boundary.

## Key packages and directories
- `cmd/uwgsocks` — main CLI entry point.
- `cmd/uwgwrapper` — wrapper/fdproxy launcher; embeds `assets/uwgpreload.so`.
- `internal/config/` — YAML + wg-quick parsing, normalization, `#!` directives.
- `internal/engine/` — WireGuard engine, proxies, ACLs, DNS, forwards, relay.
- `internal/transport/` — pluggable transport backends and transport registry.
- `internal/uwgtrace/` — ptrace/seccomp tracing support for wrapper modes.
- `internal/fdproxy/` — managed socket bridge used by wrapper/preload paths.
- `preload/` — `uwgpreload.c` LD_PRELOAD shim used by `uwgwrapper`.
- `tasks/` — design notes / implementation plans for larger subsystems.
- `tests/` — malicious, soak, integration-style coverage.
- `turn/` — standalone TURN relay implementation and examples.

## Feature areas
### WireGuard and routing
- rootless userspace WireGuard client/server
- IPv4 and IPv6
- peer `AllowedIPs` routing with most-specific-prefix matching
- optional host TUN mode
- traffic shaping per peer and globally

### Application access paths
- SOCKS5 CONNECT / UDP ASSOCIATE / BIND
- HTTP proxy GET / CONNECT and absolute-form HTTPS proxying
- local forwards and tunnel-side reverse forwards
- raw socket API for TCP / UDP / ping-style ICMP / listeners / DNS frames
- Linux wrapper path through preload + ptrace/fdproxy

### Network exposure and policy
- inbound/outbound/relay ACL engine
- transparent inbound termination from WireGuard peers to host sockets
- outbound proxy fallback lists for both proxy-originated and inbound traffic
- runtime management API for peers, ACLs, forwards, and status

### Transport modes
Supported `transports[].base` values:

- `udp`
- `tcp`
- `tls`
- `dtls`
- `http`
- `https`
- `quic`
- `turn`

HTTP/HTTPS carry WireGuard over WebSocket or upgrade semantics, QUIC uses
WebTransport, and TURN supports UDP/TCP/TLS/DTLS relay modes. Connection-
oriented transports reconnect automatically on handshake/session failure.

## Configuration model
`uwgsocks` merges:

1. YAML runtime config from `--config`
2. wg-quick style config from `wireguard.config_file`, `wireguard.config`,
   `--wg-config`, or `--wg-inline`
3. CLI overrides and repeated additions

Key top-level config blocks:

- `wireguard:` — keys, addresses, peers, listen settings, shapers
- `transports:` — WireGuard transport definitions
- `proxy:` — SOCKS5/HTTP listeners, mixed mode, outbound proxies
- `acl:` — inbound, outbound, and relay ACL policy
- `relay:` — WireGuard-to-WireGuard relay / SD-WAN mode
- `forwards:` / `reverse_forwards:` — host-to-tunnel and tunnel-to-host forwards
- `inbound:` — transparent inbound termination settings
- `dns_server:` — tunnel-hosted DNS listener
- `api:` — runtime HTTP/Unix management API
- `tun:` — optional host TUN integration
- legacy `turn:` — convenience wrapper for a single TURN transport

## `#!` directives in wg-quick files
`uwgsocks` also parses transport-related directives embedded in comment lines:

- `#!TURN=<url>` in `[Interface]` — synthesize TURN transport config
- `#!TCP` or `#!TCP=supported` in `[Interface]` — enable TCP listener
- `#!TCP=required` in `[Peer]` — require TCP transport for that peer
- `#!TCP=supported` in `[Peer]` — prefer TCP but allow UDP fallback
- `#!SkipVerifyTLS=yes` in `[Peer]` — disable TLS certificate verification
- `#!URL=<url>` in `[Peer]` — connect via HTTP/WS style transport URL

Directive parsing lives in `internal/config/config.go` in
`applyWGDirective` and `synthesizeDirectiveTransports`.

## Runtime API
Served on `api.listen`. Important endpoints:

- `GET /v1/status` — peer stats, counters, transport status
- `POST /v1/peers` — add or update peer config
- `DELETE /v1/peers` — remove peer
- `PUT /v1/acls` — replace ACL set
- `PUT /v1/wireguard/config` — hot-reload WireGuard peers/keys only
- socket upgrade endpoints for the raw socket API on `/v1/socket` and
  `/uwg/socket`

The runtime API is intended for control planes such as `uwgsocks-ui`, which
manages this process as a child, writes canonical YAML, and restarts only when
transport-level config changes require it.

## Routing and policy references
The routing order is important and is documented in `docs/proxy-routing.md`.
In short:

1. local tunnel addresses are handled first
2. reverse forwards win before peer routing
3. peer `AllowedIPs` win before fallback
4. `Address=` subnets reserve tunnel space to prevent traffic leaks
5. outbound proxy fallback rules are tried next
6. direct host dialing only happens when that source path allows it

This same model is reused for SOCKS/HTTP traffic, connected raw sockets,
fdproxy traffic, transparent inbound termination, and optional host TUN mode.

## Testing and platform expectations
The project is intentionally tested rootless and without real `/dev/net/tun`.
The automated suite covers:

- two-instance WireGuard data paths
- SOCKS5, HTTP proxy, forward, reverse-forward, DNS, and API behavior
- raw socket API behavior and malformed input rejection
- wrapper preload/ptrace/fdproxy paths
- relay ACLs, IPv6, ICMP, traffic shaping, and runtime updates
- malicious/fuzz-oriented tests in `tests/malicious`
- optional soak tests in `tests/soak`

Useful commands:

```bash
bash compile.sh
go test ./...
go test -race ./internal/config ./internal/engine ./tests/malicious ./tests/preload
```

Compatibility notes from `docs/compatibility.md`:

- primary tested platforms include Linux amd64/arm64 across glibc, musl,
  gVisor, Raspberry Pi, and Termux/Android
- secondary tested platforms include Windows amd64/arm64 and macOS arm64 for
  `uwgsocks`
- `uwgwrapper` is Linux/Android-oriented and not built on macOS or Windows

## Release/build expectations
- `compile.sh` builds `uwgsocks` everywhere and builds `uwgwrapper` only on
  Linux when `gcc` is available.
- `uwgsocks` is the same artifact for Linux musl and glibc; only
  `uwgwrapper` differs because it embeds a target-specific preload `.so`.
- Tagged releases are expected to publish:
  - `uwgsocks` for Linux/macOS/Windows on amd64 and arm64
  - `uwgwrapper` for Linux amd64/arm64 on both GNU libc and musl

## Documentation map
Use these docs for repo context before changing behavior:

- `README.md` — project overview, quick start, routing model, build/test entry
- `docs/configuration.md` — canonical config reference
- `docs/transport-modes.md` — transport semantics and operational tradeoffs
- `docs/proxy-routing.md` — routing order and fallback behavior
- `docs/socket-protocol.md` — raw socket API wire format
- `docs/testing.md` — threat model, automated coverage, soak guidance
- `docs/compatibility.md` — platform support expectations
- `docs/howto/README.md` — task-oriented operational walkthroughs
- `turn/README.md` — TURN relay server behavior and config model
- `tests/README.md` — malicious/fuzz/soak test intent

## Integration with uwgsocks-ui
`uwgsocks-ui` / `simple-wireguard-server` manages this binary as a child
process. It writes `uwg_canonical.yaml`, starts `uwgsocks --config
uwg_canonical.yaml`, and uses the Unix socket `uwgsocks.sock` for API calls.
Peers and ACLs are pushed live via the API; transport changes trigger restart.
