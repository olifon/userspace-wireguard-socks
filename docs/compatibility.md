
## What Works Today

- Rootless WireGuard client and server mode.
- IPv4, IPv6, TCP, UDP, DNS, and ping-style ICMP/ICMPv6.
- HTTP proxy, SOCKS5 CONNECT, SOCKS5 UDP ASSOCIATE, and SOCKS5 BIND.
- Local forwards and tunnel-side reverse forwards with optional PROXY protocol.
- Transparent inbound termination from WireGuard peers to host sockets.
- Peer-to-peer relay forwarding with ACLs and stateful conntrack.
- Runtime API for status, ping, peer updates, ACL updates, forwards, and
  WireGuard config replacement.
- Raw socket API for connected TCP/UDP/ICMP, TCP listeners, UDP listener-style
  sockets, DNS frames, and local fd bridging.
- `uwgwrapper` transport modes: preload only, preload + seccomp + ptrace,
  ptrace + simple seccomp, and ptrace without seccomp. `NO_NEW_PRIVILEGES` is
  enabled by default for launched processes.
- Per-peer and global traffic shaping for upload, download, and buffering
  latency. Runtime peer API updates can change shapers without restarting.
- Optional TURN bind mode, including `turn.include_wg_public_key` for relays
  that want the WireGuard public key embedded in the TURN username.

# Supported platforms

The following platforms are tested

Primary platforms: Both uwgsocks (wireguard server/client) and the uwgwrapper (routing any application through VPN):

- Linux amd64 on ubuntu laptop (libc)
- Linux amd64 on Digitalocean (libc)
- Linux amd64 on Alpine (musl libc)
- Linux amd64 on a Gvisor sandbox. Gvisor has some minor restrictions
- Linux arm64 on Raspberry PI (libc)
- Linux arm64 on termux on Android

All tests passed on these platforms. uwgsocks has the same binary for libc/musl libc, only uwgwrapper has a different binary since it embeds a preload library.

Secundary platforms: Then the following platforms uwgsocks worked:

- Windows amd64 desktop
- Windows arm64, arm64 VM on Raspberry PI
- Mac OS X 15.6.1 on arm64 (mac mini m1)

Limitations on secundary platforms:
- no uwgwrapper, so you cannot transperantly route existing applications that do not support SOCKS5/HTTP proxy without system VPN rootless
- tun device is not yet supported, for Windows requires wintun

Except from uwgtrace, uwgwrapper and fdproxy that were disabled, the tests passed on secundary platforms.