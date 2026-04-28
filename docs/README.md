<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# uwgsocks documentation

For the quickstart (install + first connection in three commands)
see the project's top-level [README.md](../README.md).

## Documentation map

### Features — what `uwgsocks` does and how

- [tunneling.md](features/tunneling.md) — WireGuard sessions, gVisor
  netstack, what gets tunneled and what doesn't.
- [transports.md](features/transports.md) — UDP / TCP / TLS / DTLS /
  HTTP / HTTPS / QUIC / TURN as outer carriers for WireGuard.
- [proxies-and-forwards.md](features/proxies-and-forwards.md) — SOCKS5
  + HTTP proxy, host forwards, reverse forwards, routing decisions.
- [transparent-wrapper.md](features/transparent-wrapper.md) —
  `uwgwrapper` modes (preload / systrap / systrap-static /
  systrap-supervised / ptrace), Phase 1.5/2 details.
- [relay-and-acls.md](features/relay-and-acls.md) — peer-to-peer
  forwarding, the three ACL planes, conntrack semantics.
- [mesh-coordination.md](features/mesh-coordination.md) — peer
  discovery, dynamic ACL projection, the `/v1/peers` and
  `/v1/acls` mesh-control plane.
- [host-tun.md](features/host-tun.md) — optional host-TUN backend
  (Linux, macOS, Windows, FreeBSD, OpenBSD).
- [turn-server.md](features/turn-server.md) — the standalone TURN
  daemon in `turn/`.

### Operations — running it in production

- [deployment.md](operations/deployment.md) — install paths
  (binary, install script, container) for every supported OS/arch.
- [observability.md](operations/observability.md) — `/metrics`
  endpoint, format reference, dashboard authoring, alerting
  recipes.
- [runbook.md](operations/runbook.md) — what to do when X breaks.
  Common-first ordering: misconfiguration → permission → kernel.

### Reference — the YAML schema, the API, the wire formats

- [config-reference.md](reference/config-reference.md) — every YAML
  key, type, default. **Generated** from struct tags + comments.
- [api-reference.md](reference/api-reference.md) — every `/v1/*`
  endpoint shape and auth requirement.
- [socket-protocol.md](reference/socket-protocol.md) — wire format
  for `/v1/socket` and `/uwg/socket`.
- [compatibility.md](reference/compatibility.md) — supported
  platforms, glibc baselines, breaking-change history.
- [configuration.md](reference/configuration.md) — broader
  behavioral guide (less authoritative than config-reference;
  read the reference first).

### Contributing — for people who edit the code

- [architecture.md](contributing/architecture.md) — high-level
  component map.
- [testing.md](contributing/testing.md) — three-tier cadence,
  build tags, env vars, every gate documented.
- [security-conventions.md](contributing/security-conventions.md)
  — what tests must protect, the documented hardening posture.

### How-tos — task-shaped recipes

The [`howto/`](howto/) directory has task-oriented walkthroughs:

- [01-simple-client-proxy.md](howto/01-simple-client-proxy.md)
- [02-server-and-ingress.md](howto/02-server-and-ingress.md)
- [03-wrapper-interception.md](howto/03-wrapper-interception.md)
- [04-firewall-and-acls.md](howto/04-firewall-and-acls.md)
- [05-mesh-coordination.md](howto/05-mesh-coordination.md)
- [06-pluggable-transports.md](howto/06-pluggable-transports.md)
- [07-turn-relay-ingress.md](howto/07-turn-relay-ingress.md)
- [08-reference-map.md](howto/08-reference-map.md)
- [09-unix-socket-forwards.md](howto/09-unix-socket-forwards.md)
- [10-minecraft-soak.md](howto/10-minecraft-soak.md)

### Internal — agent + maintainer docs

The [`internal/`](internal/) directory holds materials that aren't
end-user documentation: maintainer release checklists, security-
review notes, coverage audits, lock-protocol diagrams.

## What goes where (rule of thumb for contributors)

| You're writing about… | Put it in |
|---|---|
| A new feature, what it does behaviourally | `features/` |
| A new operational task or failure-mode | `operations/` |
| A new YAML key, API endpoint, or wire field | `reference/` |
| A maintainer-facing process or design doc | `internal/` |
| A walkthrough that ends with a working setup | `howto/` |
| Build/test/CI mechanics | `contributing/` |

If a new doc could fit two places, prefer `features/` — it's the
section a first-time reader hits.
