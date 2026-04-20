# Userspace WireGuard Gateway

WireGuard networking without root, without kernel modules, and without touching the host network stack.

`uwgsocks` embeds WireGuard and a userspace TCP/IP stack into a single binary. It runs anywhere: containers, CI pipelines, Android Termux, and locked-down hosts where kernel WireGuard or `/dev/net/tun` are unavailable.

## Why this exists

Standard WireGuard requires root and a kernel TUN interface. That rules it out for containers, unprivileged CI jobs, and any system where you cannot change the routing table. It also uses plain UDP, which is easily detected and blocked by firewalls and DPI.

`uwgsocks` removes both constraints — and uniquely, it works as a **server** too. You can host a WireGuard exit node or SD-WAN hub on any machine, under any account, with no installation: a Mac mini, a Termux session, a Windows desktop, a container, or an IoT device. Two binaries, no root, no kernel module.

## Looking for a VPN server with a web UI?

See [simple-wireguard-server](https://github.com/reindertpelsma/simple-wireguard-server) — a zero-install WireGuard server manager built on top of `uwgsocks`. It adds a dashboard, user management, OIDC login, and shareable client configs, and runs under any unprivileged account.

## Quick Start

```bash
bash compile.sh

# Start a rootless WireGuard client.
./uwgsocks --wg-config client.conf --socks5 127.0.0.1:1080

# Use a proxy-aware app through the tunnel.
curl --proxy socks5://127.0.0.1:1080 https://example.com

# Or transparently route any Linux app — no proxy support required.
./uwgsocks --config examples/socksify.yaml
./uwgwrapper -- curl https://example.com
```

## How apps enter the tunnel

| Method | When to use |
|---|---|
| SOCKS5 / HTTP proxy | App has built-in proxy support |
| Port forwards | Fixed ports you want mapped locally |
| `uwgwrapper` (Linux) | App has no proxy support — intercepts socket calls via LD_PRELOAD, falls back to ptrace for static Go/Rust binaries |
| Raw socket API | Embedding `uwgsocks` as a Go library |

## Surviving restrictive firewalls

Standard WireGuard UDP is easily fingerprinted and blocked. `uwgsocks` can carry WireGuard over:

`udp` · `tcp` · `tls` · `https` (WebSocket) · `quic` (WebTransport) · `dtls` · `turn`

A single `#!TCP=required` comment in your wg-quick config is enough to switch a peer to TCP transport — no YAML needed.

## vs. Alternatives

| | `uwgsocks` | Kernel WireGuard | Tailscale / Headscale | proxychains |
|---|---|---|---|---|
| Root required | No | Yes | No | No |
| Works in containers | Yes | Requires CAP_NET_ADMIN | Requires CAP_NET_ADMIN | Yes |
| **Host a server rootlessly** | **Yes** | No | No | — |
| Runs on macOS / Windows / Android as server | Yes | No | No | — |
| Survives DPI / port blocks | Yes | No | No | No |
| Routes apps without proxy support | Yes (uwgwrapper) | Via system routing | Via system routing | Partially (TCP only, no static binaries) |
| Standard WireGuard peers | Yes | Yes | No (Tailscale protocol) | — |
| Self-hosted, no SaaS dependency | Yes | Yes | Headscale (partial) | — |

## Binaries

- **`uwgsocks`** — WireGuard engine, SOCKS5/HTTP proxy, port forwards, ACL engine, DNS, relay, and runtime API. Runs on Linux, macOS, and Windows.
- **`uwgwrapper`** — Linux-only launcher that transparently routes any application through `uwgsocks`. Uses LD_PRELOAD for the fast path and ptrace/seccomp for static binaries.
- **`turn/`** — standalone TURN relay for relay-friendly UDP paths and CGNAT traversal.

## Build

```bash
bash compile.sh   # builds uwgsocks everywhere; builds uwgwrapper on Linux amd64/arm64
go test ./...
```

Requires Go. Building `uwgwrapper` additionally requires gcc on Linux. See [docs/compatibility.md](docs/compatibility.md) for supported platforms.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Transport modes](docs/transport-modes.md)
- [Proxy routing order](docs/proxy-routing.md)
- [Raw socket API](docs/socket-protocol.md)
- [Testing](docs/testing.md)
- [TURN relay](turn/README.md)
- [How-to guides](docs/howto/README.md)

## License

ISC License
