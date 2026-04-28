<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 08 Reference Map

Previous: [07 TURN Relay Ingress](07-turn-relay-ingress.md)  
Next: [09 Unix Socket Forwards](09-unix-socket-forwards.md)

Use the how-to guides to get moving. Use these reference docs when you need the
full behavioral contract.

## Core References

- [Configuration behavior](../reference/configuration.md)
- [Full config map](../reference/config-reference.md)
- [ACL model](../features/relay-and-acls.md)
- [Mesh control](../features/mesh-coordination.md)
- [Proxy routing order](../features/proxies-and-forwards.md)
- [Socket protocol](../reference/socket-protocol.md)
- [Transport modes](../features/transports.md)
- [TURN integration and relay modes](../features/turn-server.md)
- [Compatibility matrix](../reference/compatibility.md)
- [Testing notes](../contributing/testing.md)
- [Security model](../contributing/security-conventions.md)
- [Metrics](../operations/observability.md)
- [Standalone TURN daemon](../../turn/README.md)

## What To Read For Specific Jobs

- Tuning routing decisions: [Proxy routing order](../features/proxies-and-forwards.md)
- Editing YAML safely: [Full config map](../reference/config-reference.md)
- Understanding policy and mesh-distributed ACLs: [ACL model](../features/relay-and-acls.md)
- Understanding controller auth and peer distribution: [Mesh control](../features/mesh-coordination.md)
- Building custom clients or sidecars: [Socket protocol](../reference/socket-protocol.md)
- Understanding transport tradeoffs: [Transport modes](../features/transports.md)
- Running hidden servers behind a TURN edge: [TURN integration and relay modes](../features/turn-server.md)
- Platform caveats: [Compatibility matrix](../reference/compatibility.md)
- Trust boundaries, untrusted/trusted sources, and explicit non-goals: [Security model](../contributing/security-conventions.md)

## For contributors changing the code

Operator docs above describe behavior; the docs below describe how that
behavior is implemented. Read them before opening a PR that touches a
network-reachable surface, an auth path, or any mutex.

- [Internal docs overview](../internal/README.md)
- [Per-surface defenses + defense-in-depth conventions](../internal/security-conventions.md)
- [Lock map for `internal/fdproxy` + preload](../internal/lock-map-fdproxy.md)
