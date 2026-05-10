<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Mesh Control

`mesh_control` is the small coordination plane that lets `uwgsocks` peers learn
about each other without turning the project into a heavy external control
system.

The practical jobs it does are:

- publish a peer list inside the tunnel
- distribute projected ACL state
- help peers find direct paths when the outer transport supports it
- let more than one server share peer information instead of each relay becoming
  its own island

## Where It Listens

`mesh_control.listen` binds an HTTP server inside the userspace WireGuard
network, not on the host network:

```yaml
mesh_control:
  listen: 100.64.80.1:8787
```

That means only already-connected WireGuard peers can even reach the controller
address in the first place.

## Peer Settings That Matter

On a peer, mesh behavior is driven from the normal peer entry:

```yaml
wireguard:
  peers:
    - public_key: HUB_PUBLIC_KEY
      endpoint: 203.0.113.10:51820
      allowed_ips:
        - 100.64.80.1/32
        - 100.64.80.0/24
      control_url: http://100.64.80.1:8787
      mesh_enabled: true
      mesh_accept_acls: true
```

Useful fields:

- `control_url`: where this peer polls for controller data
- `mesh_enabled`: opt into discovery for this parent peer
- `mesh_accept_acls`: say that this peer can enforce distributed ACLs
- `mesh_disable_acls`: opt out of distributed ACL enforcement locally
- `mesh_trust`: how much fallback behavior the relay should allow when direct
  and relayed paths mix
- `mesh_advertise`: explicitly suppress advertising of a peer when needed

## What The Controller Returns

### `/v1/challenge`

Used to start authenticated polling. Returns:

- controller WireGuard public key
- short-lived challenge public key
- token version
- expiry time

### `/v1/peers`

Returns discovered peers that the caller is allowed to learn about. For each
peer, the useful fields are:

- `public_key`
- `endpoint` when the peer is a direct-path candidate
- `allowed_ips`
- `psk`
- `mesh_accept_acls`
- `mesh_trust`

### `/v1/acls`

Returns the projected ACL subset the caller should enforce locally:

- default action
- inbound rules
- outbound rules

## How Authentication Works

From a user point of view, the important fact is simple: only real WireGuard
participants in the mesh can fetch the peer list.

At a high level:

1. the controller publishes a short-lived X25519 challenge key
2. the client builds a bearer token from:
   - an ephemeral X25519 key
   - its real WireGuard identity
   - the controller's challenge key
   - the remote source address
   - the pairwise PSK material, if present
3. the controller verifies that:
   - the caller is a configured mesh-enabled peer
   - the caller's source IP matches that peer's routed address
4. the peer list and ACL payloads are returned encrypted with the derived
   shared secret

Current default token behavior is version `v2`, which binds the auth flow more
tightly to the controller's static WireGuard identity.

## Direct Paths Versus Relay Paths

Mesh control does not replace the stable parent path. It improves on top of it.

The normal sequence is:

1. a peer connects through a known parent or hub
2. it learns about other peers from the controller
3. if both sides have UDP-capable outer transports, they may try a more direct path
4. if that fails, traffic keeps flowing through the stable relay path

So the user-facing promise is not “always peer-to-peer.” It is “stable mesh
first, direct path when possible.”

## Multi-Server Use

You can run more than one relay site and still keep one shared peer inventory.

That is the main operational reason this feature exists: a team can have more
than one reachable server, but peers still discover each other through a common
controller instead of being stranded per site.

## Example

```yaml
mesh_control:
  listen: 100.64.80.1:8787
  active_peer_window_seconds: 120
```

```yaml
wireguard:
  peers:
    - public_key: HUB_PUBLIC_KEY
      control_url: http://100.64.80.1:8787
      mesh_enabled: true
      mesh_accept_acls: true
```

For a runnable walkthrough, see [../howto/05-mesh-coordination.md](../howto/05-mesh-coordination.md).

## Peer Type System (P2P Mode)

Each node in the mesh can declare its own P2P capability to the hub via
`mesh_control.p2p_mode` in its config. The hub stores the declaration and
reflects it in the `type` field of `/v1/peers` responses. Other clients use
this to decide how aggressively to maintain direct paths.

### Modes

| Config value | `/v1/peers` type | Meaning |
|---|---|---|
| `""` or `passive` | `p2p-maybe` | Can receive connections but does not aggressively maintain them |
| `active` | `p2p` | Actively maintains keepalive probes; hub uses 3s dead-path timeout |
| `remote` or `server` | `remote` | Stable public endpoint; hub treats as always active |
| `disable` | _(requester only)_ | Does not want P2P; hub returns only `remote` peers |

### Client config

```yaml
mesh_control:
  p2p_mode: "active"   # or: passive, remote, disable
```

### Hub-side filtering

When a client declared `disable` polls `/v1/peers`, the hub filters the
response to only include peers with `type: remote`. This prevents a peer
that explicitly opted out of P2P from receiving peer addresses it cannot
use.

## Keepalive Probe Mechanism

When a peer has type `p2p` or `p2p-maybe` and an active direct WireGuard
session, the hub-side keepalive goroutine monitors TX/RX byte counters
per peer.

Probe logic (mirrors WireGuard KEEPALIVE_TIMEOUT semantics):
- A probe fires when: `last_rx > last_tx AND now - last_tx >= 10s`
- Probes send a single UDP byte to the peer's allocated keepalive IP
  (a /32 in `mesh_control.keepalive_subnet`, default `250.0.0.0/8`)
- That IP routes through the WireGuard tunnel; the remote peer's IP
  layer discards the packet (no route for 250.x.x.x) but the WireGuard
  session remains alive
- Setting `last_tx = now` before sending prevents back-to-back probes
- Dead-path detection (`refreshDynamicPeerActivity`) runs independently
  in the 15s poll loop; the probe goroutine never deactivates peers

### Keepalive subnet allocation

Each active peer gets a deterministic IP derived from its WireGuard public
key bytes. The first host address in `keepalive_subnet` is the probe source.
On collision, a linear scan finds the next available address. If the subnet
is exhausted, allocation returns zero (logged as a warning, no crash).

```yaml
mesh_control:
  keepalive_subnet: "250.0.0.0/8"  # default; set to "" to disable probing
```
