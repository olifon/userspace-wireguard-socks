<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Deployment

How to install and run `uwgsocks` on every supported platform.
Three install paths in increasing complexity:

| Path | Best for | Adds |
|---|---|---|
| pre-built binary | a single host, fastest | nothing — copy + run |
| install script (`install.sh` / `.ps1` / `.bat`) | reproducible, multi-host | systemd unit / launchd plist / Windows service |
| container (GHCR) | Kubernetes, Docker, container platforms | image lifecycle |

`uwgwrapper` is Linux/Android only. `turn/` is portable but is a
separate binary with its own deployment story (see
[features/turn-server.md](../features/turn-server.md)).

## Pre-built binaries (recommended)

Each release publishes signed binaries for every supported OS/arch
combination. Download from the [Releases page](https://github.com/reindertpelsma/userspace-wireguard-socks/releases).

| OS | Arch | Filename pattern |
|---|---|---|
| Linux | amd64 | `uwgsocks-linux-amd64` |
| Linux | arm64 | `uwgsocks-linux-arm64` |
| Linux | riscv64 | `uwgsocks-linux-riscv64` |
| Linux | mips, mipsle | `uwgsocks-linux-mips{le}` |
| macOS | amd64, arm64 | `uwgsocks-darwin-{amd64,arm64}` |
| Windows | amd64, arm64 | `uwgsocks-windows-{amd64,arm64}.exe` |
| FreeBSD | amd64, arm64 | `uwgsocks-freebsd-{amd64,arm64}` |
| OpenBSD | amd64 | `uwgsocks-openbsd-amd64` |

The lite-feature variant ships as `uwgsocks-lite-{os}-{arch}`. See
[contributing/testing.md](../contributing/testing.md) for what
`-tags lite` excludes.

```bash
# Linux amd64 example
curl -fsSL -o uwgsocks \
    https://github.com/reindertpelsma/userspace-wireguard-socks/releases/latest/download/uwgsocks-linux-amd64
chmod +x uwgsocks
./uwgsocks --config uwgsocks.yaml
```

## Install scripts

The repo ships `install.sh`, `install.ps1`, and `install.bat`.
They install the binary, write a systemd unit (Linux), launchd
plist (macOS), or Windows service (Windows), and start the service.

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | bash

# Windows (PowerShell, admin)
iex "& { $(irm https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.ps1) }"
```

Both scripts let you pick which binaries to install:

```bash
# install only uwgsocks (no wrapper, no TURN)
./install.sh --only uwgsocks
```

| Binary | What it does |
|---|---|
| `uwgsocks` | the main runtime (default) |
| `uwgsocks-lite` | reduced-feature build for low-attack-surface deployments |
| `uwgwrapper` | Linux transparent-app wrapper (Linux only) |
| `turn` | standalone TURN relay daemon |

## Containers

Docker / Podman / Kubernetes / Cloud Run / Fly.io.

```bash
docker run -d --name uwgsocks \
    -v $PWD/uwgsocks.yaml:/etc/uwgsocks/uwgsocks.yaml:ro \
    -p 1080:1080 -p 8080:8080 -p 9090:9090 \
    ghcr.io/reindertpelsma/uwgsocks:latest \
    --config /etc/uwgsocks/uwgsocks.yaml
```

Image tags:

| Tag | What you get |
|---|---|
| `latest` | latest stable release |
| `vX.Y.Z` | exactly that release |
| `main` | latest commit on main (NOT for production) |
| `lite-vX.Y.Z` | lite-feature variant of that release |

The image is multi-arch (amd64 + arm64). For host-TUN mode in a
container you need `--cap-add=NET_ADMIN --device=/dev/net/tun` or
equivalent.

## Building from source

Needs Go 1.25+ and a C compiler (only for `uwgwrapper`).

```bash
git clone https://github.com/reindertpelsma/userspace-wireguard-socks.git
cd userspace-wireguard-socks

# uwgsocks main runtime
bash compile.sh

# Lite-feature variant
go build -tags lite -o uwgsocks-lite ./cmd/uwgsocks

# uwgwrapper (Linux only)
gcc -shared -fPIC -O2 -o cmd/uwgwrapper/assets/uwgpreload.so preload/uwgpreload.c -ldl -pthread -lpthread
go build -o uwgwrapper ./cmd/uwgwrapper

# Cross-compile (any host, no CGO needed for uwgsocks itself)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o uwgsocks-linux-arm64 ./cmd/uwgsocks
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o uwgsocks-darwin-arm64 ./cmd/uwgsocks
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o uwgsocks-windows-amd64.exe ./cmd/uwgsocks
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -o uwgsocks-freebsd-amd64 ./cmd/uwgsocks

# Standalone TURN
cd turn && bash compile.sh
```

## Platform-specific notes

### Linux

- For host-TUN mode (`tun.enabled: true`), grant `cap_net_admin`:
  `sudo setcap cap_net_admin+ep ./uwgsocks`. Avoids running as
  root.
- Rootless mode (default) needs no capabilities — uses gVisor
  netstack instead of the kernel TUN.

### macOS

- TUN backend uses utun (system-built-in). Needs root or an
  appropriate entitlement; `sudo` is fine for development.
- macOS 13+ requires the binary to be code-signed if it's run
  outside of a Developer-mode terminal. The release artifacts
  are signed (post-v1.0.0).

### Windows

- TUN backend uses `wintun.dll` (download from
  [wintun.net](https://www.wintun.net/)). Place in
  `C:\Windows\System32\` or alongside the binary.
- Run as a service via `install.ps1` for auto-start.

### FreeBSD / OpenBSD

- `tun(4)` interface used directly. Needs `if_tap` / `if_tun`
  loaded.
- DNS automation (`tun.dns_resolv_conf`) is the simplest, most
  portable approach.

### Lite variant

If you need just SOCKS5 + WG without the advanced transport zoo
or mesh-control plane:

```bash
go build -tags lite -o uwgsocks-lite ./cmd/uwgsocks
# OR download from releases:
curl -fsSL -o uwgsocks-lite \
    https://github.com/reindertpelsma/userspace-wireguard-socks/releases/latest/download/uwgsocks-lite-linux-amd64
```

What's excluded under `-tags lite`: mesh-control, traffic shaping,
TURN, advanced transports outside the lite surface. See
[contributing/testing.md](../contributing/testing.md) for the
exact list.

## What `uwgsocks` doesn't manage

- Host network configuration (default routes, DNS, firewalls).
  When in TUN mode, you choose how to integrate.
- TLS certificate issuance for transports — bring your own,
  via `tls.cert_file` + `tls.key_file`.
- Process supervision — use systemd / launchd / a container
  orchestrator. The binary doesn't daemonize itself.

## Verifying a downloaded binary

(Post-v1.0.0 — earlier releases are unsigned.)

```bash
cosign verify-blob \
    --certificate uwgsocks-linux-amd64.pem \
    --signature uwgsocks-linux-amd64.sig \
    --certificate-identity-regexp "https://github.com/reindertpelsma/userspace-wireguard-socks/.github/workflows/release.yml@.*" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    uwgsocks-linux-amd64
```

This proves the binary was built by THIS repo's tagged release CI
job — not by anyone else, including the maintainer's laptop. SBOMs
are attached as additional release assets.
