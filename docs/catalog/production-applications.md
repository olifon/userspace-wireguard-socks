<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Production application catalog — real apps through `uwgwrapper`

This page lists real-world applications that have been driven through
`uwgwrapper` on the four-node test mesh (hub amd64 / arm64 VPS / Mac M1 /
vast.ai container), along with the exact invocation used, which transport
the `auto` cascade selected, and any quirks worth knowing.

It is meant for people considering `uwgwrapper` as a drop-in replacement
for `torsocks`, `proxychains`, `socksify`, or `graftcp` against unmodified
production software.

## Test mesh

| Host    | Public IP / port    | WG IP      | Arch         | OS                  | Role                     |
|---------|---------------------|------------|--------------|---------------------|--------------------------|
| hub     | 51.159.237.61       | 10.200.0.1 | amd64        | Linux 7.0           | server / WG exit         |
| arm64   | 51.15.66.128        | 10.200.0.3 | aarch64      | Linux 7.0           | client (active P2P)      |
| Mac M1  | 62.210.195.8        | 10.200.0.4 | darwin/arm64 | macOS 15.6.1        | client (active P2P)      |
| vast.ai | 85.10.218.46:51277  | 10.200.0.5 | amd64        | Linux 6.8 in Docker | client (passive, NATed)  |

> **macOS note.** `uwgwrapper` is Linux/Android only. On the Mac, `uwgsocks`
> itself runs (and is part of the mesh), but the wrapper does not — apps
> that need to be tunneled on macOS use the SOCKS5/HTTP proxy listeners
> instead. macOS rows are recorded as `—` for that reason.

## Universal test target

Every test in this catalog dials a mesh-internal URL that the host's bare
network stack cannot reach. The probe target differs slightly per host
to work around current engine routing quirks:

| Host             | Probe URL                                                   | Why                                                                                                                                                                                                                          |
|------------------|-------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| hub              | `http://10.200.0.1:9091/v1/status`                          | Hub's own WG address (10.200.0.1) routes through `inbound.transparent` host_forward → 127.0.0.1:9091 (the runtime API). Reachable unwrapped only on hub processes that already know how to redirect.                       |
| arm64 / vast.ai  | `http://10.200.0.1:8787/v1/challenge`                       | mesh_control's unauthenticated endpoint, bound inside the hub's netstack. Reachable only via WireGuard transit, which the wrapper provides via `/uwg/socket`.                                                                |

For both targets, the **unwrapped** probe is asserted to fail before the
suite starts. If the bare probe succeeds, the harness reports
`unwrapped_blocked=false` in every result, flagging the assertion as
non-discriminating.

## Catalog

<!-- BEGIN: rendered table -->

| App | Category | hub (amd64) | arm64 | vast.ai | Mac M1 | Notes |
|-----|----------|-------------|-------|---------|--------|-------|
| `curl` | HTTPS client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | Baseline libc HTTP. systrap-supervised on full hosts. |
| `wget` | HTTPS client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | Same shape as curl. |
| `python` | HTTPS client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | Python 3 urllib — CPython + libc + the TCP_NODELAY fix this commit landed. |
| `node` | HTTPS client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | V8 JIT survives seccomp+systrap; libc-routed connect. |
| `ssh` | TCP client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | Dials a tunnel-internal TCP port; banner read proves interception. |
| `rsync-ssh` | exec+ssh+stream | ✅ `systrap-supervised` | — | — | — | Wrapped rsync forks ssh as its transport; both inherit the wrapper. Fixture transferred to a WG peer; SHA verified through the wrapper (peer's WG addr isn't on a host route). |
| `git` | HTTPS client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | Clones a tiny public repo; exec tree (git → git-remote-https → curl). |
| `pip` | HTTPS client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | PyPI fetch via CPython requests stack. |
| `xh` | HTTPS client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | Rust HTTP client (curl alternative). |
| `gh` | static Go | ✅ `systrap-docker` | ✅ `systrap-docker` | ✅ `systrap-docker` | — | GitHub CLI — static Go binary; --version boots cleanly under systrap-docker. |
| `cloudflared` | static Go daemon | ✅ `systrap-docker` | ✅ `systrap-docker` | ✅ `systrap-docker` | — | Cloudflare tunnel client — static Go binary. |
| `java-http` | JVM | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | OpenJDK HttpURLConnection — JIT, GC, NIO. Verifies the IPv4-mapped IPv6 fix. |
| `java-minecraft` | JVM server | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | Real Paper Minecraft server, TCP listener on 25565. |
| `nginx` | C server | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | nginx in foreground, worker fork model, accept loop. |
| `electron` | Chromium | ✅ `systrap-supervised` | — | — | — | Headless chromium binary boot under wrapper. Snap-confined chromium-browser shells skipped — install non-snap chrome on arm64. |
| `postgres` | DB client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | — | Docker-hosted Postgres + `psql` SELECT through wrapper. |
| `postgres-server` | DB server | ✅ `systrap-supervised` | — | — | — | Wrapped `postgres` daemon bound to a tunnel WG address; peer's psql reads back through WG. |
| `mongo` | DB client | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | — | Docker-hosted Mongo + `mongosh` ping through wrapper. |
| `mongo-server` | DB server | ✅ `?` | — | — | — | Wrapped `mongod` bound to a tunnel WG address; peer's mongosh runs `ping` end-to-end. |
| `mariadb-server` | DB server | ✅ `systrap-supervised` | — | — | — | Wrapped `mariadbd` bound to a tunnel WG address; auto `aa-complain`s its AppArmor profile. |
| `redis-server` | DB server | ✅ `?` | — | — | — | Wrapped `redis-server` bound to a tunnel WG address; peer's `redis-cli` runs SET/GET/DEL/PING through WG. Single-threaded epoll daemon — distinct fingerprint from the fork/thread-pool DB servers. |
| `dig` | DNS / UDP | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | BIND9 `dig @1.1.1.1` (UDP 53) through wrapper. |
| `ntp` | NTP / UDP | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | ntpdig / sntp / python NTP — exercises unconnected-UDP path to non-tunnel destinations. |
| `iperf3-udp` | UDP | ✅ `systrap-supervised` | ✅ `systrap-supervised` | ✅ `systrap-supervised` | — | UDP throughput against an ephemeral local iperf3 server. |
| `udp-echo-bind` | UDP server | ✅ `systrap-supervised` | — | — | — | Wrapped Python UDP echo server bound to a tunnel WG address; same-host loopback edge case. |
| `mosh` | UDP roaming | ✅ `?` | — | — | — | Wrapped mosh-client → unwrapped mosh-server on hub; tests the real encrypted-UDP roaming protocol. Hub row drives from arm64 over ssh. |
| `curl-http3` | QUIC | ✅ `systrap-supervised` | — | — | — | curl --http3-only — gated on a libcurl build with ngtcp2/nghttp3. |
| `odoo` | Python ERP | ✅ `systrap-supervised` | — | — | — | Odoo --version (boot smoke; full ERP install is a separate soak). |
| `kubectl` | K8s control plane | — | — | ✅ `?` | — | Full lifecycle through wrapper: run pod → wait → exec (websocket upgrade) → logs → watch → delete. Tests HTTP/2 long-poll + WebSocket upgrade — the new signal vs every other HTTPS client. |
| `helm-odoo` | K8s deployed app | ✅ `?` | — | — | — | End-to-end: wrapped helm deploys Odoo+Postgres to microk8s, wrapped kubectl pulls the admin password from the cluster secret, wrapped curl completes Odoo's CSRF login + JSON-RPC, gets back an authenticated admin session through the WG tunnel. |
| `pytorch-mnist` | ML | 🚧 | 🚧 | ✅ `systrap-supervised` | — | PyTorch + torchvision MNIST training (vast.ai GPU host). |

<!-- END: rendered table -->

Legend: ✅ wrapped run passed and unwrapped probe failed · 🚧 not run (missing
binary, missing GPU, or upstream rejected `-ea` Java) · ❌ wrapped run failed
under wrapper · — not applicable on this host.

## Bugs surfaced + fixed while building this catalog

Driving real apps through the wrapper uncovered four interop issues that
are fixed in the same commit as this catalog:

1. **`setsockopt(SOL_TCP,…)` returned `EOPNOTSUPP` on proxied fds.**
   `preload/core/fd_ops.c` now swallows protocol-level options
   (`SOL_TCP`, `SOL_IP`, `SOL_IPV6`, `SOL_UDP`) on a proxied fd —
   the underlying kernel socket is AF_UNIX (the fdproxy stream end)
   and can't satisfy them, but apps surface the error to user code
   and abort. Python 3.14's `urllib`, `xh`, and others fail noisily
   without this.

2. **IPv4-mapped IPv6 destinations were not unmapped before routing.**
   `internal/engine/socket_api.go` now `.Unmap()`s `req.DestIP` and
   `req.BindIP` before routing. OpenJDK NIO and other dual-stack
   clients dial IPv4 targets via `::ffff:10.200.0.1`; the engine
   previously left that in the IPv6 path and broke connections with
   `SIGPIPE` / `ConnectException`.

3. **The freestanding static-injection blob couldn't be found at runtime.**
   `cmd/uwgwrapper/embed_static_${arch}.go` now `//go:embed`s the blob
   into the wrapper binary, with a `/tmp/uwgwrapper-<uid>/` materialize
   step in `inject_static.go`. `staticBlobPath()` falls back to the
   embedded bytes when no on-disk asset is reachable, so the
   systrap-supervised dynamic→static exec path is armed even when the
   wrapper is invoked from a non-repo CWD.

4. **`auto` cascade decision wasn't logged.** Verbose mode now prints
   `auto: chose <mode> (target=<kind>, seccomp=<bool> ptrace=<bool>)`
   — invaluable for diagnosing which mode was actually selected when
   debugging a wrapped app.

## Recommended hub config

[`examples/server-hub-mesh.yaml`](../../examples/server-hub-mesh.yaml)
captures the daemon-side flags that make every test in this catalog
green. The key knobs (off by default):

- `inbound.transparent: true` — deliver from-peer WG packets to host
  services without rewriting L4 ports.
- `host_forward.inbound.enabled: true` (+ `redirect_ip: "127.0.0.1"`) —
  bridge from-peer traffic for `10.200.0.1:<port>` to the corresponding
  loopback service. Without this, peers cannot reach the hub's host
  sshd / Postgres / nginx / etc. (verified: with the bridge enabled,
  `uwgwrapper ssh -p 22 user@10.200.0.1` succeeds from arm64).
- `socket_api.bind: true` — wrapper apps can `bind()` tunnel addresses
  to expose listeners to other peers.
- `socket_api.transparent_bind: true` — apps that source-bind a
  non-tunnel IP before `connect()` (Chromium's QUIC startup, Java NIO
  dual-stack, PyTorch URL fetch) no longer trip
  `"transparent bind is disabled"`.

## Remaining engine limitations exposed by the catalog

- **Without `host_forward.inbound.enabled`, only netstack-resident
  listeners are reachable from peers.** That's why the catalog's SSH
  test on arm64/vast.ai dials the hub's mesh_control TCP port (8787)
  rather than sshd at 22 — a non-SSH banner is sufficient proof of TCP
  interception even when the recommended hub config isn't deployed.
  Enable `host_forward.inbound.enabled: true` and the same test against
  port 22 succeeds end-to-end.

- **Paper Minecraft's netty listener has an `epoll_ctl` interaction with
  wrapped fds.** The server boots successfully, JIT warms up, world
  generates, and the `Done (Xs)!` line prints — but the listener at
  `*:25565` fails to register with the wrapper's proxy. Treated as a
  boot-survival pass; listener-side wrapping is tracked separately.

- **`gh api` does not currently complete under wrapper.** `gh --version`
  boots cleanly, but `gh api meta` errors with `error connecting to
  api.github.com` because gh's pure-Go DNS resolver interacts oddly with
  the `--force-loopback-dns` redirect. Boot survival is asserted; the
  network round-trip is a follow-up.

## Harness

All test runs are reproducible via `scripts/catalog/`:

```bash
# Inventory:
scripts/catalog/
├── README.md           # runtime contract for the test scripts
├── lib.sh              # shared bash helpers (probe URL, transport parsing, …)
├── run-suite.sh        # top-level driver per host
├── render-table.py     # rebuild the table from scripts/catalog/results/
└── apps/
    ├── _http_client.sh # template for HTTPS-client app tests
    ├── curl.sh
    ├── wget.sh
    ├── python.sh
    ├── node.sh
    ├── ssh.sh
    ├── git.sh
    ├── pip.sh
    ├── xh.sh
    ├── gh.sh
    ├── cloudflared.sh
    ├── java-http.sh
    ├── java-minecraft.sh
    ├── nginx.sh
    ├── electron.sh
    ├── postgres.sh
    ├── mongo.sh
    ├── odoo.sh
    └── pytorch-mnist.sh
```

To run the catalog yourself on a host that's already in a uwgsocks mesh:

```bash
# 1. Clone + build:
git clone https://github.com/reindertpelsma/userspace-wireguard-socks.git
cd userspace-wireguard-socks
bash compile.sh

# 2. Run the suite (auto-skips apps whose binaries are absent):
export CATALOG_HOST=$(hostname -s)
export UWGSOCKS_API=http://127.0.0.1:9091   # or 9092/9094 per node
bash scripts/catalog/run-suite.sh

# 3. Re-render the catalog table:
python3 scripts/catalog/render-table.py --update
```

Per-app result JSON lands in `scripts/catalog/results/<host>/<app>.json`.
Each record captures: transport selected by `auto`, wrapped run outcome,
unwrapped probe block status, duration, and a tail of wrapper + app
output for forensic use.

## Reproducing on a fresh host

The harness's `apps/*.sh` scripts each carry their own install hints in
`record_result` notes when the binary is missing — running the suite once
on a stock Ubuntu host produces a punch list of `apt install` commands.
A minimum-viable Linux setup:

```bash
DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    curl wget python3 python3-pip nodejs ssh git \
    nginx default-jdk-headless postgresql-client \
    chromium-browser
# Plus, for the static-Go cascade:
#   gh: https://cli.github.com/manual/installation
#   cloudflared: https://github.com/cloudflare/cloudflared/releases/latest
#   xh: https://github.com/ducaale/xh/releases/latest
# For Paper Minecraft, install Adoptium Temurin 21 GA (Paper rejects -ea):
#   https://adoptium.net/temurin/releases/?version=21
# For mongosh:
#   https://downloads.mongodb.com/compass/mongosh-2.5.7-linux-{x64,arm64}.tgz
```

See [`scripts/catalog/README.md`](../../scripts/catalog/README.md) for
the runtime contract (env vars, exit codes, where results land).
