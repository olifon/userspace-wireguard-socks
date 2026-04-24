<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 06 Mesh Coordination

Previous: [05 Pluggable Transports](05-pluggable-transports.md)  
Next: [07 TURN Relay Ingress](07-turn-relay-ingress.md)

`mesh_control` is the small tunnel-only coordination plane that lets peers:

- discover other peers
- learn projected ACL state
- attempt direct UDP paths
- fall back to relayed paths when direct P2P is unavailable

## Validate The Hub And Peer Examples

Hub:

```bash
./uwgsocks --config ./examples/mesh-control-hub.yaml --check
```

Peer:

```bash
./uwgsocks --config ./examples/mesh-control-peer.yaml --check
```

## Hub Config

The hub exposes a tunnel-only controller:

```yaml
mesh_control:
  listen: 100.64.80.1:8787
  active_peer_window_seconds: 120
```

## Peer Config

The child peer points back to the parent:

```yaml
control_url: http://100.64.80.1:8787
mesh_enabled: true
```

## Roaming Story

When a laptop switches from Wi-Fi to 4G, the parent peer remains the stable
anchor. If a direct UDP-capable path becomes available, `uwgsocks` can prefer
it. If not, traffic keeps flowing over the relayed parent path.

That gives you:

- stable parent connectivity
- opportunistic P2P
- graceful fallback

## TURN And Mesh

Only UDP-capable outer transports are valid direct-path candidates. HTTP-only
and TLS-only transports can still participate in peer sync, but they are not
advertised as direct P2P endpoints.

That is why TURN matters here too:

- direct UDP when possible
- TURN relay when necessary
- one control plane for both

