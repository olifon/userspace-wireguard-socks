<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Mesh P2P State Machine — Internal Design

## Overview

The mesh P2P subsystem has two distinct state machines: one on the **hub**
(server-side, per peer) and one on each **client** (local, per direct peer).

---

## Hub-side: per-peer declaration state

The hub tracks the declared `p2p_mode` for each authenticated peer in memory.
There is no persistent storage — the mode is re-declared on every client poll
cycle.

### Mode values

```
"active"   → PeerTypeActive
"passive"  → PeerTypePassive
"remote"   → PeerTypeRemote
"disable"  → PeerTypeDisable
""         → PeerTypeUnset  (peer has not declared yet; treated as remote)
```

### Declaration flow

```
Client                              Hub
  |                                  |
  |  POST /v1/challenge              |
  |--------------------------------->|
  |  <-- challenge bytes             |
  |                                  |
  |  POST /v1/p2p  {p2p: "active"}  |  ← authenticated with bearer token
  |  Authorization: Bearer <tok>     |
  |--------------------------------->|
  |  <-- 204 No Content              |
  |  hub stores p2p=active for peer  |
  |                                  |
  |  POST /v1/peers  (fetch)         |
  |--------------------------------->|
  |  <-- peer list filtered by mode  |
```

The declaration happens **before** `fetchPeers` in `runMeshPolling`.  This
ensures that hub-side filtering is correct from the very first poll — a
`disable` peer does not see a brief window of undeclared (unfiltered) peers.

### Hub peer-list projection rules

| Requester mode | Peers returned |
|---------------|----------------|
| `active`      | all `active` + all `passive` + all `remote` |
| `passive`     | all `active` + all `passive` + all `remote` |
| `remote`      | all peers (no filter — relay peers need full visibility) |
| `disable`     | only `remote`-mode peers |
| unset         | all peers (safe default until first declaration) |

The `PeerType` field on each returned peer reflects the **target peer's
declared mode**, not the requester's mode.  Clients use this to decide whether
to attempt a direct-path handshake (`active`) or wait for the far side to
initiate (`passive`).

---

## Client-side: per-dynamic-peer activity state

Each dynamic peer learned from the hub goes through an activity lifecycle
on the client.

### States

```
PENDING   → peer received from hub, no WG handshake yet
ACTIVE    → recent handshake and/or RX bytes observed
INACTIVE  → handshake aged out or dead-path detected
REMOVED   → peer pruned (no longer returned by hub, or explicitly removed)
```

### Transition triggers

**PENDING → ACTIVE**

Triggered by `refreshDynamicPeerActivity`:
- `LastHandshakeTime` is recent (within `wgDeadPathTimeout`), or
- RX bytes have grown since the previous poll

**ACTIVE → INACTIVE** (fast path — dead-path detection)

Checked in `refreshDynamicPeerActivity` on each poll:
- TX grew since last poll (we are trying to send), AND
- RX has not grown (nothing coming back), AND
- handshake age ≥ `wgDeadPathTimeout` (15 s = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)

This fast detection is independent of `ActivePeerWindowSeconds` and fires in
~15–20 s, not 120 s.

**ACTIVE → INACTIVE** (slow path — window expiry)

`MeshControl.ActivePeerWindowSeconds` (default 120, minimum safe value ~120)
governs how long a peer stays active after its last observed handshake.  This
must stay ≥ 120 s because WireGuard's rekey interval is 180 s — a shorter
window would cause intermittent peer drops between rekeys.

**INACTIVE → ACTIVE**

Any successful handshake or RX growth restores the peer to active.

**Any → REMOVED**

Hub stops returning the peer (peer count trim, hub config change, or the
dynamic peer's parent `AllowedIPs` no longer covers it).

---

## Keepalive probe state machine

The hub maintains a keepalive probe IP table in `keepaliveIPs` (map from
WireGuard public key bytes to `netip.Addr`).

### IP allocation

Probe IPs are allocated deterministically from the peer's public key:

```
ip = keepalive_subnet.Addr + (key[0]<<8 | key[1]) % subnet_size
```

Collision resolution: linear probe forward through the subnet until an
unoccupied slot is found (or the subnet is exhausted, in which case no probe IP
is assigned for that peer).

The same key always maps to the same starting candidate, so probe IPs are
stable across hub restarts as long as the set of active peers does not change.

### Probe cadence

A probe packet (1-byte UDP to the assigned IP on port 1) is sent when:

```
lastRx > lastTx   (peer is sending to us but we haven't sent recently)
  AND
now - lastTx ≥ 10 s
```

The probe is intentionally cheap: a single zero-byte UDP datagram routed
through the gVisor netstack to the keepalive subnet address.  It does not use
`PersistentKeepalive` at the WireGuard level.

---

## Concurrency notes

### `Normalize()` on shared Rule copies

`meshProjectRelayRuleForSource` and `meshProjectRelayRuleForDestination` both
take an `acl.Rule` by value.  Before the fix, `Normalize()` used
`r.sourcePrefixes = r.sourcePrefixes[:0]` — keeping the shared backing array
from the original rule.  Two concurrent HTTP handler goroutines normalizing
value copies of the same rule would race on that backing array.

Fix: `r.sourcePrefixes = nil` and `r.destPrefixes = nil` force a fresh
allocation on every `Normalize()` call.  The allocation cost is negligible
because `Normalize()` is called at ACL-update time, not per-packet.

### Hub mesh state lock

All hub-side p2p declaration reads and writes are protected by
`Engine.meshMu`.  The `meshPeerTypes` map is written under write-lock during
POST /v1/p2p and read under read-lock during GET /v1/peers.

### Client activity map

`dynamicPeerActivity` on the client side is accessed only from the single
`runMeshPolling` goroutine — no lock required there.  The `dynamicPeers` map
(shared with the WireGuard peer install path) is protected by
`Engine.dynPeerMu`.
