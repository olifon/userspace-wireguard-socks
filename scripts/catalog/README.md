<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# `scripts/catalog/` — production application test harness

Reproduces the runs behind
[`docs/catalog/production-applications.md`](../../docs/catalog/production-applications.md).

## Layout

```
scripts/catalog/
├── README.md
├── lib.sh                # shared bash helpers
├── run-suite.sh          # top-level driver — runs every app on the current host
├── apps/                 # one script per application
│   ├── curl.sh
│   ├── wget.sh
│   ├── ssh.sh
│   ├── git.sh
│   ├── pip.sh
│   ├── python.sh
│   ├── node.sh
│   ├── gh.sh
│   ├── xh.sh
│   ├── java-minecraft.sh
│   ├── nginx.sh
│   ├── electron.sh
│   ├── cloudflared.sh
│   ├── odoo.sh
│   └── pytorch-mnist.sh
└── results/<host>/<app>.json
```

## Runtime contract

Each `apps/<name>.sh` exports:
- `app_name`, `app_category`
- function `run_test` returning 0 on success, non-zero on failure
- function `teardown` (optional) for cleanup

`run_test` is expected to:
1. install/locate the binary (call `install_app` helper if needed),
2. run it under `${UWGWRAPPER_BIN} --api=${UWGSOCKS_API} -- <app-cmd>`,
3. assert that the **wrapped** invocation reaches the tunnel-internal
   endpoint `http://10.200.0.1:8787/v1/peers`,
4. compare against the **un-wrapped** baseline (must fail/timeout).

Results are written to `results/<host>/<app>.json`:

```json
{
  "host": "arm64",
  "app": "curl",
  "transport": "systrap-supervised",
  "wrapped_ok": true,
  "unwrapped_blocked": true,
  "duration_seconds": 1.42,
  "notes": "..."
}
```

## Environment

The driver assumes these env vars, set automatically by `run-suite.sh`:

| Variable          | Meaning                                            | Default per host        |
|-------------------|----------------------------------------------------|-------------------------|
| `UWGSOCKS_BIN`    | Path to `uwgsocks` binary                          | repo `./uwgsocks` if built |
| `UWGWRAPPER_BIN`  | Path to `uwgwrapper` binary                        | repo `./uwgwrapper`     |
| `UWGSOCKS_API`    | Wrapper API endpoint                               | `http://127.0.0.1:909X` |
| `MESH_PROBE_URL`  | Tunnel-only HTTP target used as connectivity probe | `http://10.200.0.1:8787/v1/peers` |
| `RESULTS_DIR`     | Where to write per-app JSON                        | `scripts/catalog/results/<host>` |
| `CATALOG_HOST`    | Logical host name                                  | `hub`, `arm64`, `vast`, `mac` |

## Running

```bash
# On a host already in the mesh:
export CATALOG_HOST=arm64
export UWGSOCKS_API=http://127.0.0.1:9092
bash scripts/catalog/run-suite.sh

# Or one app at a time:
bash scripts/catalog/apps/curl.sh
```

Per-app scripts pick the right binaries based on `$PATH` and the env
variables above.

## What "pass" means

A row is green only when **both** of:
- the wrapped invocation reached the mesh-internal endpoint
- the un-wrapped invocation could **not** reach it

The second half is important — without it, a green wrapped run could mean
"the wrapper did nothing and the host network happened to route the address".
