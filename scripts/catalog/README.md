<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# `scripts/catalog/` — production application test harness

Reproduces the runs behind
[`docs/catalog/production-applications.md`](../../docs/catalog/production-applications.md).

## What it tests

Real production applications driven through `uwgwrapper` against a real
uwgsocks instance, with assertions that the wrapped call genuinely flows
through the mesh-side socket API rather than the host network. Each
script is self-contained (downloads its own test fixtures, picks an
ephemeral port, cleans up). Tags every result with the transport the
`auto` cascade selected so regressions in transport selection surface
immediately.

## Layout

```
scripts/catalog/
├── README.md                   # this file
├── lib.sh                      # shared bash helpers (probe URL, transport parsing)
├── run-suite.sh                # driver — runs every app on the current host
├── ci-selfloop.sh              # release.yml's gate — runs the no-peer subset
├── render-table.py             # rebuild docs/catalog/production-applications.md
├── results/<host>/<app>.json   # per-app outcome
└── apps/
    ├── _http_client.sh         # shared body for HTTP-client style tests
    ├── curl.sh wget.sh xh.sh   # HTTPS clients (libc)
    ├── python.sh node.sh       # CPython + V8 HTTPS clients
    ├── ssh.sh git.sh pip.sh    # tunnel-internal TCP / exec-tree / package fetch
    ├── gh.sh cloudflared.sh    # static Go binaries (PT_INTERP path)
    ├── java-http.sh            # OpenJDK HttpURLConnection
    ├── java-minecraft.sh       # real Paper Minecraft 1.21 server boot
    ├── nginx.sh                # foreground nginx, worker fork model
    ├── electron.sh             # headless chromium / electron --version boot
    ├── dig.sh                  # BIND9 DNS query (UDP @1.1.1.1)
    ├── ntp.sh                  # ntpdig / sntp / python NTP (UDP 123)
    ├── iperf3-udp.sh           # UDP throughput
    ├── curl-http3.sh           # QUIC / HTTP/3 (libcurl with ngtcp2)
    ├── udp-echo-bind.sh        # wrapped UDP server bound to a tunnel addr
    ├── postgres.sh             # docker-hosted Postgres + psql client
    ├── postgres-server.sh      # wrapped postgres daemon bound to a tunnel addr
    ├── mongo.sh                # docker-hosted Mongo + mongosh client
    ├── mongo-server.sh         # wrapped mongod bound to a tunnel addr
    ├── mariadb-server.sh       # wrapped mariadbd bound to a tunnel addr
    ├── odoo.sh                 # Odoo --version boot smoke
    └── pytorch-mnist.sh        # PyTorch CIFAR / MNIST training (vast.ai GPU)
```

## Runtime contract

Each `apps/<name>.sh` is independent. It:

1. Locates / installs its target binary (records `missing-bin` and exits 0
   if absent, so a partial host gracefully skips rather than fails the
   suite).
2. Spawns it under `${UWGWRAPPER_BIN} --api=${UWGSOCKS_API} --transport=auto`.
3. Drives a meaningful operation through the wrapped binary — an HTTPS
   fetch, a SELECT, a `mongosh ping`, an `mc client → Done (Xs)!` boot,
   etc. Asserts the operation goes via the tunnel and not the bare host
   stack (the suite pre-flights an unwrapped probe and tags results with
   `unwrapped_blocked=true|false`).
4. Writes `results/<host>/<app>.json` with transport selected, wrapped
   outcome, duration, and a forensic tail of wrapper + app output.

The result JSON shape:

```json
{
  "host": "arm64",
  "app": "curl",
  "transport": "systrap-supervised",
  "wrapped_ok": true,
  "unwrapped_blocked": true,
  "duration_seconds": 0.10,
  "notes": "..."
}
```

`render-table.py` aggregates every host's result files back into the
catalog markdown.

## Environment

`run-suite.sh` exports these defaults (override any in the shell):

| Variable          | Default                                           | Meaning |
|-------------------|---------------------------------------------------|---------|
| `CATALOG_HOST`    | `$(hostname -s)`                                  | Logical host slug (`hub`, `arm64`, `vast`, `mac`). |
| `UWGSOCKS_API`    | `http://127.0.0.1:9091`                           | Wrapper-side API endpoint of the local uwgsocks. |
| `UWGWRAPPER_BIN`  | absolute path to `uwgwrapper` in the repo         | The wrapper binary the scripts spawn. Must be absolute — scripts `cd $work` before invocation. |
| `UWGSOCKS_BIN`    | absolute path to `uwgsocks` in the repo           | Used by `ci-selfloop.sh` to spin up a temporary daemon. |
| `MESH_PROBE_URL`  | per-host:<br>hub → `http://10.200.0.1:9091/v1/status`<br>else → `http://10.200.0.1:8787/v1/challenge` | The tunnel-only HTTP target used to assert the wrapper actually intercepts. |
| `RESULTS_DIR`     | `scripts/catalog/results/<host>`                  | Where per-app JSON lands. |
| `JAVA_GA`         | `/opt/jdk21/bin/java` if present                  | Override for Paper Minecraft (rejects `-ea` Java). |
| `PG_USER` / `DB_USER` | `postgres` / `mysql`                          | Unix users daemons drop privileges to (postgres / mariadbd refuse root). |
| `MONGO_PORT` etc. | random in `[50000, 60000)`                        | Ephemeral ports per daemon test to avoid sticky netstack state from a previous run. |

## Running

```bash
# Full suite on a host that's already in the mesh:
export CATALOG_HOST=arm64
export UWGSOCKS_API=http://127.0.0.1:9092
bash scripts/catalog/run-suite.sh

# Single app:
bash scripts/catalog/apps/postgres-server.sh

# CI's no-peer subset (used by release.yml on tag pushes):
bash scripts/catalog/ci-selfloop.sh

# Re-render the catalog table after pulling fresh results from other hosts:
rsync -aqz <other-host>:.../scripts/catalog/results/<their-host>/ \
            scripts/catalog/results/<their-host>/
python3 scripts/catalog/render-table.py --update
```

## What "pass" means

A row is green only when **both** of:

- The wrapped invocation reached its target (HTTP-200, valid SQL row,
  mongo `{"ok":1}`, "Done (Xs)!", etc).
- The unwrapped baseline probe was blocked (so a green wrapped run
  isn't an accident of host routing already covering the destination).

The pre-flight unwrapped probe runs before any apps. If it succeeds —
e.g., because the host's kernel already has a route to `10.200.0.1` —
the harness tags `unwrapped_blocked=false` in every result and the
table reader treats them with skepticism.

## `ci-selfloop.sh` vs the full suite

The full suite expects a real mesh (multi-peer; peers may need to ssh
back through to validate server-bind tests). `ci-selfloop.sh` is the
self-contained variant that release.yml runs on every tag push:

- Spins up a fresh single-node uwgsocks with the recommended hub config
  (`inbound.transparent: true`, `host_forward.inbound.enabled: true`,
  `socket_api.{bind,transparent_bind,udp_inbound}: true`) on random ports
  so it never clashes with an already-running instance.
- Generates ephemeral WireGuard keys; no real peer is needed because
  every test dials a local netstack listener through the wrapper.
- Runs 15 of the apps (curl, wget, python, node, ssh, git, pip, xh,
  gh, cloudflared, java-http, nginx, dig, iperf3-udp, udp-echo-bind).
- Deliberately skips: `java-minecraft` (~200MB Paper jar download),
  `electron` (Chrome install), `pytorch-mnist` (no GPU on runners),
  `odoo` (apt package on noble has a werkzeug regression),
  `{postgres,mongo,mariadb}-server` (heavy daemon install + sudo + apparmor),
  `ntp` (real internet pool, runner sandbox blocks),
  `curl-http3` (Ubuntu's stock curl doesn't ship HTTP/3 — see
  "Building HTTP/3-capable curl" below for the side-install recipe).

## Daemon tests — environment requirements

| Test               | What you need                            |
|--------------------|------------------------------------------|
| `postgres-server`  | `postgres` + `psql` packages. The script `sudo`s to the unix `postgres` user (daemon refuses root). |
| `mariadb-server`   | `mariadb-server` + `mariadb-install-db`. The script `aa-complain`s `/usr/sbin/mariadbd` if its AppArmor profile is in enforce mode (the default profile denies `/tmp/uwgwrapper-*/uwgpreload-*.so`, so LD_PRELOAD silently drops and the daemon runs unwrapped). |
| `mongo-server`     | `mongodb-org-server` from MongoDB's apt repo (Ubuntu doesn't ship mongod). No special profile work needed — there's no AppArmor `mongod` profile shipped by upstream. |
| `postgres` / `mongo` (client-side tests) | docker, plus `psql` / `mongosh`. Spawn ephemeral `postgres:16-alpine` / `mongo:7` containers. |

## Adding a new app

Drop `apps/<name>.sh`, follow the pattern of an existing test:

1. Source `lib.sh`.
2. Look up the binary; record `missing-bin` if absent.
3. Build a wrapped command that exercises real network behavior. For
   HTTPS clients, the `_http_client.sh` template handles the boilerplate.
4. Call `record_result <app> <wrapped_ok> "${UNWRAPPED_BLOCKED:-true}"
   <transport> <duration> <notes>` to write the result JSON.
5. Exit 0 if wrapped_ok, non-zero otherwise (drives `run-suite.sh`'s
   pass / fail counters).

Then update `render-table.py`'s `CATALOG_APPS` list with a short
display name + category, and `ci-selfloop.sh`'s `APPS=(...)` array if
the test is small/fast/peer-independent enough for CI.

## Past pitfalls baked into the harness

- **Always use absolute paths**. Scripts `cd $work` before invoking
  the wrapper, so a relative `../../uwgwrapper` resolves from `$work`
  and the wrapper exits in 0.5s, looking like the app crashed.
  `lib.sh` resolves `UWGWRAPPER_BIN` to an absolute path at source.
- **Daemon ports must be randomized.** Sticky netstack listener state
  in the engine across re-runs can hold a previous test's bind and
  make the next run hang on `LISTEN`. Each daemon test picks a fresh
  port in `[50000, 60000)` per run.
- **Server `bind()` to tunnel addresses doesn't work from the local
  hub.** A host process dialing `10.200.0.1:<port>` short-circuits
  through `inbound.transparent` host_forward → 127.0.0.1:<port> —
  which doesn't match where the wrapped daemon's listener actually
  lives (in netstack). The server-bind tests therefore have the local
  daemon launch on the hub and ssh to an arm64 peer to dial it back
  through WG. Configure the peer's API endpoint with
  `POSTGRES_PEER` / `POSTGRES_PEER_API` etc.
  - **Exception:** `udp-echo-bind` (and any wrapped-client →
    wrapped-server UDP pair on the same host) does work locally,
    via an engine-level same-host UDP loopback registry that
    short-circuits delivery between two `openUDPListener` sessions
    bound on the same NIC IP. gVisor netstack doesn't loop UDP
    between two listeners on the same NIC, so the engine maintains
    a `(bind_ap → listener)` map and emits `ActionUDPDatagram` to
    the matching session directly. Pinned by
    `internal/engine/socket_api_test.go::TestSocketAPISameHostUDPLoopback`
    and `internal/netstackex/sameniclo_test.go::TestSameNICLoopbackUDP`.
- **`socket_api.udp_inbound: true` is required** for the catalog's
  wrapped UDP server tests (udp-echo-bind, and any production
  scenario where a wrapped UDP listener receives first-contact from
  unfamiliar peers). The hub example config sets it; without it the
  engine's stateful UDP firewall drops first-contact and the
  wrapped server's `recvfrom` blocks forever.
- **Don't trust `pg_isready`-style ready signals alone.** Real daemons
  log "ready" before they accept TCP; the daemon tests poll for both
  the canonical log line AND a successful `/dev/tcp/127.0.0.1/<port>`
  probe.

## Building HTTP/3-capable curl

Ubuntu's stock `curl` (through 26.04 LTS) does not ship with HTTP/3
support — the `Features:` line of `curl -V` lacks `HTTP3` and
`--http3-only` fails at runtime. `curl-http3.sh` looks for a
side-installed HTTP/3-capable curl at `/usr/local/bin/curl-http3` or
`/opt/http3/bin/curl` before falling back to system curl.

Recipe (uses stock OpenSSL 3.5's native QUIC API + nghttp3; nothing
needs to come from quictls/BoringSSL since OpenSSL 3.5+ exposes the
necessary `OSSL_QUIC*` callbacks directly):

```bash
sudo apt-get install -y build-essential autoconf libtool-bin pkg-config \
    libssl-dev libpsl-dev libnghttp2-dev cmake git

mkdir -p /opt/http3-build && cd /opt/http3-build

# nghttp3 (HTTP/3 framing)
git clone --depth 1 --recursive --branch v1.5.0 \
    https://github.com/ngtcp2/nghttp3
( cd nghttp3 && autoreconf -i && \
  ./configure --prefix=/opt/http3 --enable-lib-only \
              --disable-shared --enable-static --with-pic && \
  make -j$(nproc) && make install )

# curl with OpenSSL-QUIC + nghttp3
git clone --depth 1 --branch curl-8_11_0 https://github.com/curl/curl
( cd curl && autoreconf -fi && \
  PKG_CONFIG_PATH=/opt/http3/lib/pkgconfig ./configure \
      --prefix=/opt/http3 \
      --with-openssl --with-openssl-quic \
      --with-nghttp3=/opt/http3 \
      --disable-shared --enable-static \
      --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt && \
  make -j$(nproc) && make install )

sudo ln -sf /opt/http3/bin/curl /usr/local/bin/curl-http3
/usr/local/bin/curl-http3 -V | grep -i HTTP3   # confirm Features: ... HTTP3
```

The script forces `--ipv4` because cloudflare-quic.com resolves to
both v4 and v6; the default uwgsocks engine config doesn't enable
IPv6 outbound through the tunnel (`engine.IPv6 disabled` error).
