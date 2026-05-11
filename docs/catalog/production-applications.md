<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Production application catalog — running real apps under `uwgwrapper`

This page lists real-world applications that have been verified to run under
`uwgwrapper` on the four-node test mesh (hub / arm64 VPS / Mac M1 / vast.ai),
along with the exact invocation used, which transport the `auto` cascade
selects, and any quirks worth knowing.

It is meant for people who want to use `uwgwrapper` as a drop-in replacement
for `torsocks`, `proxychains`, `socksify`, or `graftcp` against unmodified
production software.

## Test mesh

| Host    | Public IP / port | WG IP      | Arch     | OS                  | Role                |
|---------|------------------|------------|----------|---------------------|---------------------|
| hub     | 51.159.237.61    | 10.200.0.1 | amd64    | Linux 7.0 (Ubuntu)  | server / WG exit    |
| arm64   | 51.15.66.128     | 10.200.0.3 | aarch64  | Linux 7.0           | client (active P2P) |
| Mac M1  | 62.210.195.8     | 10.200.0.4 | darwin/arm64 | macOS 15.6.1    | client (active P2P) |
| vast.ai | 85.10.218.46:51277 | 10.200.0.5 | amd64  | Linux 6.8 in Docker | client (passive, NAT) |

> **macOS note.** `uwgwrapper` is Linux/Android only. On the Mac, `uwgsocks`
> itself runs (and is part of the mesh), but the wrapper does not — apps that
> need to be tunnelled on macOS must use the SOCKS5/HTTP proxy listeners
> instead. Mac rows below are therefore marked `N/A — wrapper Linux-only`.

## Universal test target

Every test in this catalog dials `http://10.200.0.1:8787/v1/peers` — the
mesh-control endpoint that lives on the hub's WireGuard side. From any host
in the mesh, host-side processes cannot reach this address directly (the
WireGuard interface lives inside the userspace netstack, not the kernel
routing table). It only becomes reachable when the process is wrapped, at
which point `uwgwrapper` redirects `connect()` through the mesh.

So the assertion is uniform: **without wrapper, the connect should fail or
time out; with wrapper, it should return the peer JSON.**

Where an app cannot be coerced into making an HTTP request, the test instead
asserts that the app boots cleanly under wrapper and that it survives wrapper
interception of whatever it does network — captured via `-v` wrapper logs
and per-app probes documented in the scripts.

## Harness

All test runs are reproducible via `scripts/catalog/`:

- `scripts/catalog/run-suite.sh` — top-level driver per host
- `scripts/catalog/apps/*.sh` — one per app
- `scripts/catalog/lib.sh` — shared helpers

Results land under `scripts/catalog/results/<host>.md` and are summarized
in this document.

## Catalog

Legend:
- ✅ runs cleanly under `uwgwrapper auto`
- ⚠️ runs with a documented flag tweak
- ❌ does not run; reason recorded
- — not applicable on this host
- ⏳ pending (build / run still in progress)

| # | App | Category | hub (amd64) | arm64 | vast.ai | mac | Notes |
|---|-----|----------|-------------|-------|---------|-----|-------|
| 1 | `curl` (libc, dynamic) | HTTPS client | ⏳ | ⏳ | ⏳ | — | Baseline. Picks `systrap-supervised` (seccomp+ptrace) on full hosts. |
| 2 | `wget` (libc, dynamic) | HTTPS client | ⏳ | ⏳ | ⏳ | — | Same as curl. |
| 3 | `ssh` (OpenSSH client) | TCP client | ⏳ | ⏳ | ⏳ | — | Dial mesh-internal sshd on `10.200.0.1:22`. |
| 4 | `git` (clone via HTTPS) | HTTPS client | ⏳ | ⏳ | ⏳ | — | Pulls small public repo via tunnel exit. |
| 5 | `pip install` (CPython) | HTTPS client | ⏳ | ⏳ | ⏳ | — | Network from `pip` + verifies CPython survives systrap. |
| 6 | `python3` (raw HTTP via stdlib) | HTTPS client | ⏳ | ⏳ | ⏳ | — | `python3 -c 'urllib.request...'`. |
| 7 | `node` (v8 JIT) | HTTPS client | ⏳ | ⏳ | ⏳ | — | Tests JIT survives seccomp+systrap. |
| 8 | `gh` (GitHub CLI, Go static) | HTTPS client | ⏳ | ⏳ | ⏳ | — | Static-Go target → exercises systrap-docker cascade. |
| 9 | `xh` (Rust HTTP client, dynamic glibc) | HTTPS client | ⏳ | ⏳ | ⏳ | — | Popular `curl` alternative in Rust. |
| 10 | Java JVM — Paper Minecraft server | server / JIT | ⏳ | ⏳ | ⏳ | — | Boots `paper.jar` and accepts a mock connect. JIT + GC + listener. |
| 11 | `nginx` | server | ⏳ | ⏳ | ⏳ | — | Worker fork model — exercises supervised execve. |
| 12 | Electron (headless chromium) | renderer | ⏳ | ⏳ | ⏳ | — | `--no-sandbox --headless=new` against tunnel endpoint. |
| 13 | `cloudflared` (Go static) | tunnel daemon | ⏳ | ⏳ | ⏳ | — | `cloudflared --version` + access tcp smoke. |
| 14 | Odoo (Python + Postgres) | ERP server | ⏳ | ⏳ | ⏳ | — | Boot smoke only; full install in soak. |
| 15 | PyTorch + MNIST on GPU | ML training | — | — | ⏳ | — | vast.ai only (GPU). |

(Result columns are filled in by the harness; this table reflects the state
of `scripts/catalog/results/`.)

## Per-app detail

See `scripts/catalog/apps/<name>.sh` for the exact commands. For each app:
- the script writes a `<host>/<app>.json` result file with transport, status,
  duration, and stderr excerpts;
- this catalog renders the summary across all hosts.

## Reproducing locally

```bash
# On a fresh Linux host with Go + gcc + make:
git clone --depth 1 https://github.com/reindertpelsma/userspace-wireguard-socks.git
cd userspace-wireguard-socks
bash compile.sh

# Bring up a uwgsocks client (or join an existing mesh — see docs/howto/01-join-a-mesh.md)
./uwgsocks --config examples/socksify.yaml &

# Then drive the catalog:
bash scripts/catalog/run-suite.sh
```

See [`scripts/catalog/README.md`](../../scripts/catalog/README.md) for the
runtime contract (env vars, exit codes, where results land).
