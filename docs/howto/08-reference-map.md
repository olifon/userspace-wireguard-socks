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
- [Proxy routing order](../reference/proxy-routing.md)
- [Socket protocol](../reference/socket-protocol.md)
- [Transport modes](../reference/transport-modes.md)
- [Compatibility matrix](../reference/compatibility.md)
- [Testing notes](../reference/testing.md)
- [Standalone TURN daemon](../../turn/README.md)

## What To Read For Specific Jobs

- Tuning routing decisions: [Proxy routing order](../reference/proxy-routing.md)
- Editing YAML safely: [Full config map](../reference/config-reference.md)
- Building custom clients or sidecars: [Socket protocol](../reference/socket-protocol.md)
- Understanding transport tradeoffs: [Transport modes](../reference/transport-modes.md)
- Platform caveats: [Compatibility matrix](../reference/compatibility.md)

## Final Advice

If the goal is “make one app or one service reachable fast,” stay in the how-to
flow.

If the goal is “change routing policy, mesh behavior, transport negotiation, or
runtime API semantics,” switch to the reference docs before editing config or
code.
