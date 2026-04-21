<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Host TUN

Use host-TUN mode only when an application needs a real kernel interface.
`uwgsocks` does not require it for SOCKS5/HTTP, forwards, raw socket API, or
`uwgwrapper`.

## Minimal Example

```yaml
wireguard:
  private_key: ...
  addresses: [10.77.0.2/32]
  peers:
    - public_key: ...
      endpoint: vpn.example.com:51820
      allowed_ips: [10.77.0.0/24]
      persistent_keepalive: 25

tun:
  enabled: true
  configure: true
  name: uwgsocks0
  route_allowed_ips: true
  routes:
    - 198.19.0.0/24
```

That creates a host TUN interface, assigns the `wireguard.addresses`, and
routes the selected prefixes into `uwgsocks`.

## What `uwgsocks` Configures

When `tun.configure: true`:

- Linux uses netlink for interface addresses and routes.
- macOS uses `utun` plus host route/interface commands.
- Windows uses Wintun plus native route/address commands.

`route_allowed_ips: true` installs peer `AllowedIPs` as host-TUN routes.
`routes:` adds extra CIDRs on top.

## DNS

`tun.dns_servers` configures the host-side DNS servers for traffic entering
through the TUN interface.

There are two DNS integration modes:

- default host integration:
  - Linux: best-effort `resolvectl` / `systemd-resolve`
  - Windows: best-effort `netsh`
  - macOS: not automated yet
- explicit resolv.conf writing with `tun.dns_resolv_conf`

Example:

```yaml
tun:
  enabled: true
  configure: true
  dns_servers: [10.77.0.1]
  dns_resolv_conf: /etc/resolv.conf
```

Use `dns_resolv_conf` only when you intentionally want `uwgsocks` to own that
file, or when another local resolver stack watches a custom file you point it
at.

## Outer Endpoint DNS

Broad host-TUN routes can break hostname resolution for the outer WireGuard
transport itself. `tun.fallback_system_dns` exists for that case.

```yaml
tun:
  fallback_system_dns:
    - 1.1.1.1
    - 8.8.8.8
```

Those resolvers are used only for resolving outer peer hostnames outside the
tunnel. If omitted, `uwgsocks` falls back to a built-in public resolver list.

## Bypass Behavior

Before TUN routes are installed, `uwgsocks` snapshots the current host egress
source addresses and reuses them for the outer WireGuard transport's direct
TCP/UDP dials. This avoids the common single-homed loop where host-TUN routes
would otherwise recurse back into the tunnel.

That is not a full Linux policy-routing mode. On multihomed systems, explicit
host routes for peer endpoints are still the safer option.

## Platform Notes

- Linux: best target for host-TUN automation.
- macOS: works with native `utun`; DNS changes are not automated yet.
- Windows: requires the official signed `wintun.dll`, either beside
  `uwgsocks.exe` or in `C:\Windows\System32`.

## Real Smoke Tests

The repo includes opt-in real host-TUN tests:

```bash
UWG_TEST_REAL_TUN=1 sudo go test ./internal/tun -run 'TestReal.*SmallRoute'
UWG_TEST_REAL_TUN=1 UWG_TEST_REAL_TUN_DEFAULT=1 docker run --rm --privileged -v "$PWD":/src -w /src golang:1.25 bash -lc '/usr/local/go/bin/go test ./internal/tun -run "TestRealLinuxTUNConfigure(SmallRoute|DefaultRoutes)" -count=1'
```

The default-route Linux test only runs in the privileged container path, not on
the local developer host.
