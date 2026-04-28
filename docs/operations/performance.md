<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Performance baselines

`uwgsocks` ships a runnable performance harness in `tests/perf/`.
This document describes how to run it, what the workloads measure,
and the reference numbers operators can expect.

> Numbers in this doc are **reference points**, not guarantees. Real
> deployments vary by hardware, kernel, and the WG/transport
> configuration. Treat the numbers as "what the current main
> branch produces on a stock Linux x86_64 dev box" — useful as a
> regression baseline.

## How to run

The perf harness is gated behind `//go:build perf` AND
`UWGS_PERF=1` so that no normal `go test` invocation pays its cost
(see [contributing/testing.md](../contributing/testing.md)).

### Loopback (single host, two engines)

```bash
bash tests/perf/scripts/run-loopback.sh
```

Output goes to stdout in markdown row format and is also tee'd to
`/tmp/uwgs-perf-loopback-<timestamp>.txt`. Wall time ~1-2 minutes.

### Real-network (two hosts over the public internet)

```bash
LEFT=root@<server-host> RIGHT=root@<client-host> \
    bash tests/perf/scripts/run-real-network.sh
```

This is currently a guided runner — it probes both hosts and prints
the manual recipe needed to bring up uwgsocks on each side and run
iperf3 across the tunnel. Full automation is tracked as M5 follow-up.

## What the harness measures

| Workload | Test name | What it measures |
|---|---|---|
| TCP throughput | `TestPerfTunnelTCPThroughput` | sustained bytes/sec for a 256 MiB blob across A→hub→B (relay path) |
| TCP latency | `TestPerfTunnelTCPLatency` | per-RTT p50/p95/p99 for 1000 round-trips of 100-byte ping/pong |

Both run 5 passes and report median + min + max so transient
scheduler noise is visible.

## Reference numbers (loopback)

These are the numbers we observe on a stock dev box on a recent
build. Replace with your own when you run the harness.

| Host | Workload | Size | Median | Range | OS/arch |
|---|---|---|---|---|---|
| dev linux/amd64 | Tunnel TCP throughput (loopback, 2-peer) | 256 MiB | 33 MiB/s | 33-34 MiB/s | linux/amd64 |
| dev linux/amd64 | Tunnel TCP latency (loopback, 100 B ping) | 1000 iters | p50 ~70 µs | p95 ~110 µs, p99 ~150 µs | linux/amd64 |

Throughput is dominated by:
1. WireGuard ChaCha20-Poly1305 cost (~70-80% of CPU per byte at
   loopback rates).
2. gVisor netstack copy + segment-reassembly cost.
3. UDP outer transport syscall + sendmsg/recvmsg cost.

Latency is dominated by:
1. Go scheduler quanta — sub-100µs floor on most kernels.
2. WG handshake state checks per packet.
3. gVisor's TCP MSS clamp + window updates.

## Three-tier hardware reference

| Tier | Hardware | Sustained TCP through tunnel | Memory @ 256 connections |
|---|---|---|---|
| 1 | small VPS (Hetzner CX21, 2 vCPU, 4 GB) | run the harness yourself; insert here | (run + insert) |
| 2 | ARM box (mid-tier ARM server) | run the harness yourself; insert here | (run + insert) |
| 3 | desktop / dev box | run the harness yourself; insert here | (run + insert) |

Filling these in is part of the v1.0.0 release checklist. Numbers
collected against the same git commit on each tier — when an
operator runs the harness on their hardware they can compare to the
table directly. Diffs > 30% from this table are interesting; diffs
within 10% are noise.

## Workload assumptions documented

- The relay path goes A → hub → B over WireGuard outer UDP. There
  is no NAT, no real-network loss, no jitter. Loopback throughput
  is therefore an upper bound on what real-network deployments
  achieve.
- The blob is randomly-content-keyed so gVisor's TCP can't
  optimise via repeated patterns; this is closer to a real
  workload than a constant-byte stream would be.
- WG handshakes complete BEFORE the timing window starts. We don't
  measure handshake throughput here — see the chaos suite for
  that (`TestMeshChaosResume_HubProcessRestart` measures
  re-handshake latency under restart).

## What the harness does NOT measure

- HTTP-level latency through the SOCKS5 proxy. (Not yet — perf
  workload #3 candidate.)
- Multi-flow concurrent throughput. (Loopback TCP can saturate one
  CPU; multi-flow tells you scaling.)
- Ramp-up cost (handshake + first-packet latency). The harness
  warms up before measuring; an end-user-visible "time to first
  byte" is a separate workload.
- TURN-relayed throughput. (The TURN client is much slower than
  bare UDP — measuring that is its own follow-up.)

If you need any of the above, contributing a new
`TestPerf<workload>` in `tests/perf/throughput_test.go` is the
expected path. Follow the existing pattern: bring up the topology,
warm up, measure 5 passes, emit a `MARKDOWN:` row.

## Adding a new workload

1. Open `tests/perf/throughput_test.go` (or add a new
   `tests/perf/<workload>_test.go`).
2. Use `bringUpTwoPeerLoopback(t)` to get a hub + 2 clients.
3. Run your workload, collect timing + bytes counters.
4. Call `emitMarkdownRow(t, ...)` to print a stable result row.
5. The Python regex on the orchestrator scripts already greps
   `^MARKDOWN:` from the test output — no script change needed.
