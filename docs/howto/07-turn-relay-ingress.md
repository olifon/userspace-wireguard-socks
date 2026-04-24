<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 07 TURN Relay Ingress

Previous: [06 Mesh Coordination](06-mesh-coordination.md)  
Next: [08 Reference Map](08-reference-map.md)

This is the “my WireGuard server is behind NAT and I still want inbound
connectivity” pattern.

The idea is simple:

1. Run a small TURN daemon on a reachable host.
2. Let your `uwgsocks` server allocate a stable relay port there.
3. Point clients at that mapped relay port.

## Start A Local TURN Relay

```bash
turn -config ./examples/turn-relay-local.yaml
```

That example binds loopback TURN on `127.0.0.1:3478` and reserves relay port
`127.0.0.1:40000` for username `wireguard`.

## Start The TURN-Backed WireGuard Server

```bash
./uwgsocks --config ./examples/turn-server.yaml
```

The key bit is:

```yaml
turn:
  server: 127.0.0.1:3478
  realm: local-turn.example
  username: wireguard
  password: super-secret-turn-password
```

That means the WireGuard server itself does not need a public UDP socket. It
binds through the TURN allocation.

## Start A Client

```bash
./uwgsocks --config ./examples/turn-client.yaml
```

The paired [`examples/turn-client.conf`](../../examples/turn-client.conf) uses:

```ini
Endpoint = 127.0.0.1:40000
```

That endpoint is the TURN relay's mapped port, not the private server host.

## Production Version

In a real deployment:

- run `turn` on a small VPS or public edge box
- keep the private WireGuard server behind NAT
- publish one mapped relay port per server identity
- optionally enable TURN-side WireGuard filtering

This is the cleanest way to expose a server that cannot port-forward its own
UDP listener.

## Validation Note

The local relay config and the TURN-backed `uwgsocks` server both validated in
this sandbox. The full loopback client data path was not a trustworthy success
signal here, so verify the end-to-end relay flow on a real host if TURN ingress
is the feature you are betting on.
