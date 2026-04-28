<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# uwgsocks Grafana dashboards

`uwgsocks-overview.json` — single overview panel set covering the
metric surface exposed by `uwgsocks --config ... metrics.listen=...`.

## Panels

| Panel | Source metric(s) | What to watch for |
|---|---|---|
| Build info | `uwgsocks_build_info` | version, lite=true/false, Go version |
| Static peers | `uwgsocks_peers` | count of configured peers |
| Handshaked peers | `uwgsocks_peers_handshaked` | < `uwgsocks_peers` ⇒ at least one peer not connected |
| Dynamic peers | `uwgsocks_dynamic_peers` | mesh-control discovered peers |
| Active connections | `uwgsocks_active_connections` | live tunnel-side TCP/UDP flows |
| Tunnel throughput | `rate(uwgsocks_bytes_{transmitted,received}_total[1m])` | sustained Bps in / out |
| Relay conntrack table size | `uwgsocks_relay_conntrack_flows` | should level off; growth-without-bound is a leak |
| Mesh-control requests/s by result | `rate(uwgsocks_mesh_requests_total[1m])` | `auth_failed` should be ~0; `rate_limited` non-zero ⇒ rogue peer |
| Drops + refusals | `uwgsocks_*_total` counters | each spike correlates with a real event |

## Quick install

The repo's reference Grafana setup lives on the mac-mini operator
host (loopback only, SSH-port-forwarded for access). To bring it
up locally, copy `uwgsocks-overview.json` into your Grafana's
provisioning directory or import it via the UI:

```
# manual (browser):
#   Grafana → Dashboards → Import → upload uwgsocks-overview.json
```

```yaml
# provisioning (file-based):
# /var/lib/grafana/provisioning/dashboards/uwgsocks.yaml
apiVersion: 1
providers:
  - name: uwgsocks
    type: file
    folder: uwgsocks
    options:
      path: /var/lib/grafana/dashboards
```

## Required Prometheus scrape config

```yaml
scrape_configs:
  - job_name: uwgsocks
    static_configs:
      - targets: ['127.0.0.1:9100']
        labels:
          instance: <hostname>
```

with `metrics.listen: "127.0.0.1:9100"` in your `uwgsocks.yaml`.
The default port the dashboard expects is `9100`; change it
consistently in both the scrape config and `metrics.listen` if
you need a different port.
