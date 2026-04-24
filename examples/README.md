# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC

# Examples

These examples are runnable demonstration patterns, not production configs.
They ship with fixed local-demo keys and placeholder secrets so they can be
loaded and tested out of the box. Replace keys, addresses, endpoints, and
tokens before real deployment.

- `client.yaml` / `client.conf`: simple outbound client
- `server.yaml` / `server.conf`: basic server / exit-node shape
- `exit-client.yaml` / `exit-server.yaml`: rootless exit-node pair
- `forwarding.yaml`: local forwards and reverse forwards
- `unix-forwarding.yaml`: Unix socket forwards and reverse forwards
- `ingress-client.yaml`: reverse-forward demo for local app ingress
- `socksify.yaml`: `uwgwrapper` / proxy-oriented local app routing
- `turn-server.yaml`: WireGuard server that binds through a TURN relay
- `turn-client.yaml` / `turn-client.conf`: client for the TURN-backed server
- `turn-relay-local.yaml`: local standalone TURN relay for the TURN how-to
- `mesh-control-hub.yaml`: hub/server with tunnel-only mesh control enabled
- `mesh-control-peer.yaml`: client/peer that learns discovered peers from a parent
- `transport-http-quic.yaml`: multi-transport edge using HTTPS, QUIC, TURN, and fronting knobs
- `relay-acls.yaml`: relay server with explicit relay ACL policy

See also:

- `docs/howto/README.md`
- `docs/howto/07-turn-relay-ingress.md`
- `docs/reference/transport-modes.md`
- `docs/reference/config-reference.md`
