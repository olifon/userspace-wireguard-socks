<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 01 Simple Client Proxy

Previous: [How-To Index](README.md)  
Next: [02 Server And Ingress](02-server-and-ingress.md)

This is the 60-second demo.

You will run a rootless WireGuard server on loopback, then a rootless WireGuard
client that exposes SOCKS5 and HTTP proxy listeners. No host routes. No kernel
VPN. No root.

## Start The Server

```bash
./uwgsocks --config ./examples/server.yaml
```

That loads [`examples/server.yaml`](../../examples/server.yaml) and the
matching [`examples/server.conf`](../../examples/server.conf).

## Start The Client

Open a second terminal:

```bash
./uwgsocks --config ./examples/client.yaml
```

That gives you:

- SOCKS5 on `127.0.0.1:1080`
- HTTP proxy on `127.0.0.1:8082`

## Prove It Works

SOCKS5:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
```

HTTP proxy:

```bash
curl --proxy http://127.0.0.1:8082 https://ifconfig.me
```

Check daemon status:

```bash
curl -H 'Authorization: Bearer demo-api-token-change-me' \
  http://127.0.0.1:9090/v1/status
```

## Why This Is Different

Standard WireGuard wants a kernel interface. `uwgsocks` does not. It injects
traffic into a userspace `gVisor` stack, then applies WireGuard, proxy routing,
ACLs, forwards, and optional relay logic inside one daemon.

That is why this works cleanly in:

- containers
- CI runners
- rootless dev shells
- locked-down corporate laptops

## Production Key Generation

The example files use demo keys. Generate real ones like this:

```bash
uwgsocks genkey
uwgsocks genpair --server-address 100.64.90.1/32 --client-address 100.64.90.2/32
```

