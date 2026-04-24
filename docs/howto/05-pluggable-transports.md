<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 05 Pluggable Transports

Previous: [04 Firewall And ACLs](04-firewall-and-acls.md)  
Next: [06 Mesh Coordination](06-mesh-coordination.md)

This is the firewall-evasion chapter.

Standard WireGuard over UDP is fast, but it is also easy to fingerprint and
easy to block on hostile networks. `uwgsocks` can wrap WireGuard in TCP, TLS,
HTTP, HTTPS, QUIC, and TURN carriers.

## TCP Meltdown In One Paragraph

Running one packet protocol inside another reliable byte stream is usually a
bad trade. When the outer TCP stream stalls, the inner WireGuard traffic piles
up behind head-of-line blocking. That is the “TCP meltdown” problem.

QUIC fixes the outer transport layer by keeping the carrier on UDP, usually
port `443`, while still looking like ordinary HTTP/3-era traffic.

## Start From The Multi-Transport Example

```bash
./uwgsocks --config ./examples/transport-http-quic.yaml --check
```

That example exposes:

- HTTPS/WebSocket on `8443`
- QUIC/WebTransport on `8443`
- optional TURN-over-HTTPS client transport

## Important Syntax Correction

This repo does not use a literal `#!transport=quic` directive.

The supported tagged syntax is:

- `#!URL=...`
- `#!TURN=...`
- tagged endpoint schemes like `quic://`, `https://`, `http+raw://`

Example `wg-quick` peer using QUIC:

```ini
[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = quic://edge.example.com:8443/wg
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Or with an explicit tagged directive:

```ini
[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = edge.example.com:8443
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
#!URL=quic://edge.example.com:8443/wg
```

## Server-Side YAML

```yaml
transports:
  - name: quic
    base: quic
    listen: true
    listen_port: 8443
    websocket:
      path: /wg
```

## Validation Note

On April 24, 2026, the config validated locally in this sandbox, but I did not
trust the sandbox for a clean end-to-end QUIC performance signal. Treat QUIC as
feature-complete in config, but verify on a real Linux host if you are tuning
it for production.

