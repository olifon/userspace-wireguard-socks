<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Runbook

What to do when something breaks. Ordered by frequency in real
deployments — common operator mistakes first, kernel/library edges
near the bottom.

## "I started uwgsocks but the tunnel isn't up"

This is the most common first-deployment problem. Walk this list in
order; stop at the first hit.

### 1. The peer's `Endpoint=` is wrong, missing, or unreachable

```bash
# What is your peer endpoint?
grep -i Endpoint /etc/wireguard/wg0.conf
# Or in YAML form:
yq '.wireguard.peers[].endpoint' uwgsocks.yaml

# Can you reach it?
nc -uvz <ip> <port>     # for plain UDP
curl -sS https://<endpoint>/  # for URL transports
```

A peer with no `Endpoint=` is **valid** WG syntax but means "wait for
them to dial me." If both ends are configured this way, no tunnel
ever forms. At least one side must have the other's endpoint.

### 2. Wrong `PrivateKey` / `PublicKey` pairing

```bash
# Re-derive the public key from your private key:
echo "<your private key in base64>" | wg pubkey
# This must equal what the OTHER side has as your peer's PublicKey.
```

Symmetric error: you set up wg0 once, regenerated keys, copied the
new public key to the server but kept the old private key locally
(or vice versa). The handshake will silently fail forever.

### 3. PresharedKey mismatch

PSKs are tested AFTER the cryptographic handshake. A wrong PSK looks
identical to a wrong key pair from the wire — silent rejection.

### 4. AllowedIPs doesn't cover the destination you're trying to reach

The most common "tunnel works but I can't ping anything" mistake.

```bash
# Check what AllowedIPs your peer advertises:
yq '.wireguard.peers[] | "\(.public_key)  \(.allowed_ips)"' uwgsocks.yaml

# If you're trying to reach 100.64.0.5 but no peer has 100.64.0.0/24
# or 100.64.0.5/32 in their AllowedIPs, that destination is
# unreachable through the tunnel.
```

### 5. Listen-mode peer has no public reachable IP

If you set `wireguard.listen_port` and expect peers to dial in, the
host needs an externally-reachable IP on that port. NAT, host
firewalls, and cloud-provider security groups all gate this.

```bash
# Test from a remote host:
nc -uvz <your-public-ip> <listen-port>
```

### 6. Wrong `wireguard.private_key` format (NOT the wg-quick form)

`uwgsocks.yaml` takes a base64 private key. wg-quick takes the same
format. **`wg genkey`** produces it. Don't paste a hex key, an SSH
key, or "PRIVATE KEY" PEM. Length is 44 characters, ends in `=`.

### Tunnel-up debug command sequence

```bash
# 1. Engine status (shows configured peers + handshake state):
curl -sS http://127.0.0.1:9090/v1/status | jq

# Look for, per peer:
#   "has_handshake": true       ← key pair correct, endpoint reachable
#   "last_handshake_time": "…"  ← recent (≤120s ago) ⇒ session alive
#   "transmit_bytes": 1234      ← > 0 means we sent something
#   "receive_bytes": 1234       ← > 0 means we got something back

# 2. If has_handshake=false: the cryptographic handshake hasn't
#    completed. Check #1-#3 above.

# 3. If has_handshake=true but bytes are 0: keys are right but the
#    AllowedIPs route isn't matching. Check #4 above.

# 4. Run with verbose logging to see WG-go's handshake decisions:
uwgsocks --config uwgsocks.yaml --log-verbose 2>&1 | grep -i "handshake\|peer"
```

## "I started uwgsocks but `proxy.socks5` won't accept connections"

### Most common: you didn't set `proxy.socks5` at all

```yaml
proxy:
  socks5: "127.0.0.1:1080"   # required to enable the SOCKS5 listener
```

A missing or empty value means no listener. There's no default port.

### Wrong format: must be `host:port`

```yaml
proxy:
  socks5: ":1080"             # ✓ all interfaces
  socks5: "127.0.0.1:1080"    # ✓ loopback only
  socks5: "1080"              # ✗ this is interpreted as a hostname
```

### Auth required but no credentials configured

If you set `proxy.username` and `proxy.password`, SOCKS5 clients MUST
authenticate. Curl with `--socks5 user:pass@host:port`. If you
forgot, the handshake will close immediately on first byte.

## "Container can't reach the tunnel"

Containers don't share the host's loopback. If `proxy.socks5:
"127.0.0.1:1080"`, Docker containers on a bridge network cannot reach
that port. Either:
- Bind to `0.0.0.0:1080` (any interface) and rely on container-network
  isolation.
- Bind to the docker bridge IP (`172.17.0.1:1080` typically) and
  reach it from the container.
- Use `--network=host` on the container.

## "DNS doesn't resolve through the tunnel"

```yaml
wireguard:
  dns: ["100.64.0.1"]   # configured DNS server inside the tunnel
```

`uwgsocks` will use this DNS server for all resolutions when the
client is configured to use it. Common mistakes:
- The DNS server isn't actually running at the tunnel address.
- The host's `/etc/resolv.conf` overrides it (uwgsocks doesn't
  modify the host's resolver — that's intentional, see `tun.dns_*`
  for opt-in).
- The proxy client (curl etc.) is doing its own DNS using the
  host's resolver before connecting.

## "Engine OOMs / memory grows without bound"

```bash
# Check goroutine + heap stats live:
curl -sS http://127.0.0.1:9100/metrics | \
    grep -E "^go_(goroutines|memstats_heap_alloc_bytes|memstats_heap_inuse_bytes)"

# Watch the relay conntrack table:
curl -sS http://127.0.0.1:9100/metrics | grep uwgsocks_relay_conntrack_flows
```

If the relay conntrack flows count grows without bound:
- A peer is creating + abandoning flows faster than they expire.
  Check `inbound.connection_table_grace_seconds` (default brief).
- Set `inbound.max_connections` to a sane cap (default 0 = no cap)
  and `inbound.max_connections_per_peer` to throttle abusive peers.

If goroutines grow without bound: file an issue with a goroutine
profile (`curl http://localhost:9091/debug/pprof/goroutine?debug=2 >
goroutines.txt`) and the soak workload that produced it.

## "TUN device can't be opened" / "TUN permission denied"

Host TUN mode (`tun.enabled: true`) needs the userspace process to
be allowed to open `/dev/net/tun`. Three viable approaches:

```bash
# Linux — capability-based (preferred):
sudo setcap cap_net_admin+ep /usr/local/bin/uwgsocks

# Linux — root (works but heavy):
sudo uwgsocks --config uwgsocks.yaml

# macOS — utun is auto-allocated; needs root:
sudo uwgsocks --config uwgsocks.yaml

# Windows — install Wintun.dll (see operations/deployment.md).
```

If you don't need host TUN, leave `tun.enabled: false`. The proxy +
SOCKS5 + raw socket API paths all work without root.

## "uwgwrapper exits with `ld: error / preload not loaded`"

The wrapper extracts an embedded `uwgpreload.so` to `/tmp` and sets
`LD_PRELOAD`. Failure modes:

- `/tmp` mounted `noexec`. Use a writable + exec mount: `--preload
  /path/to/your/copy/uwgpreload.so` to point elsewhere.
- glibc baseline mismatch. The published preload is compiled
  against glibc 2.17 (Ubuntu 18.04 baseline). Older systems should
  build their own — see `preload/build_phase1.sh`.
- musl libc — the published `.so` is glibc-only. Use the musl
  variant in `preload/build_static.sh` for static-binary targets,
  or the wrapper auto-cascade selects the right mode.

## "Mesh-control isn't discovering peers"

```bash
# 1. Confirm the hub is exposing /v1/peers:
curl -sS http://<tunnel-addr>:8800/v1/peers
# Expected: 401 (auth required) or a peer list. 404 means the
# listener isn't bound; check mesh_control.listen.

# 2. Confirm clients have ControlURL set on the parent peer:
yq '.wireguard.peers[] | select(.mesh_enabled == true) | .control_url' uwgsocks.yaml

# 3. Confirm clients have mesh_enabled and mesh_accept_acls:
yq '.wireguard.peers[] | {key: .public_key, mesh: .mesh_enabled, accept: .mesh_accept_acls}' uwgsocks.yaml

# 4. Watch the polling cycle (every 15s):
journalctl -fu uwgsocks | grep mesh
```

A client without `MeshEnabled = true` and `MeshAcceptACLs = true` on
the parent peer's config will never poll, so it never discovers
peers and never appears in OTHER peers' /v1/peers either.

## "TURN allocation fails / 401 from TURN server"

```bash
# Check the server URL + creds match:
yq '.transports[] | select(.base == "turn")' uwgsocks.yaml

# Test with `turncat` or `pion-turn-cli` — these are independent of
# uwgsocks and isolate the TURN auth from the tunnel layer:
turncat --proto udp --turn-url turn://<server> --turn-username u --turn-password p \
        --target-port 12345 -- 8.8.8.8 53
```

Common: TURN realm is wrong (some servers require it explicitly,
some derive it from the URL). `realm:` in the YAML overrides the
default.

## Compatibility breakages — what you can expect to break across versions

This section will fill in as we ship versions. Reference: [docs/reference/compatibility.md](../reference/compatibility.md).

Until v1.0.0 there is no compatibility promise. From v1.0.0 onward,
breaking changes to YAML schema or `/v1/*` endpoints require a
major version bump.

Things that have already changed pre-1.0 that we won't change again:

- Wrapper transport names: `preload`, `systrap`, `systrap-static`,
  `systrap-supervised`, `ptrace`, `ptrace-seccomp`, `ptrace-only`.
  Old aliases (`preload-static`, `preload-and-ptrace`) are removed.
  See [features/transparent-wrapper.md](../features/transparent-wrapper.md).
- `proxy.type=turn` is removed; use `base: turn` directly.
- `transport.WebSocketConfig.SNIHostname` is removed; use
  `tls.server_sni`.

## "Mesh-control rate-limited me at 429"

You've hit `mesh_control.rate_limit_per_second_per_peer` (default 10
RPS / 20 burst). This is usually a misconfigured client polling
faster than the 15s tick — check your client's `runMeshPolling`
cadence isn't being driven by an outer loop.

## "I see `connection refused` on a peer that's clearly up"

ACL block. Check the relay/inbound/outbound ACLs:

```bash
curl -sS http://127.0.0.1:9090/v1/acls | jq
```

Default deny on relay (`acl.relay_default: deny`) is the most common
trip. New peers added at runtime won't get relay traffic until you
add an explicit `allow` rule (or temporarily flip the default).

## Rare: kernel-specific edges

Listed last because most operators won't see these.

- **gVisor (`runsc`) hosts**: the wrapper's `systrap-supervised` and
  `ptrace-seccomp` modes need `ptrace(2)` and `RET_TRAP`/`RET_TRACE`,
  which gVisor sandboxes vary on. Auto-cascade detects and falls
  back to `preload`. Force a mode if needed.
- **Apple Silicon macOS**: utun device numbers are sparse — the
  wrapper picks the first free `utunN`. If you see `device or
  resource busy`, raise `tun.utun_max_attempts`.
- **OpenBSD `pf` interaction**: `tun(4)` on OpenBSD doesn't bind
  /etc/pf.conf rules cleanly; expect to manually add `pass` rules
  for the tunnel interface. The host-TUN backend is still
  community-validated, not internally-tested.
- **Linux 5.4 kernels**: pre-AF_VSOCK seccomp interactions can make
  `systrap` flaky inside very old containerd. Use `preload` mode
  on these hosts.
