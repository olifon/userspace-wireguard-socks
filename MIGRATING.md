<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Migrating between versions

This file documents user-visible breaking changes. Each release
that introduces breaking changes gets a section here with the
exact diff your config needs.

For the compatibility commitment from v1.0.0 onward, see
[STABILITY.md](STABILITY.md).

## v0.x → v1.0.0

This is the largest migration the project will ever ship — the
v0.x train iterated freely on the surface, and v1.0.0 freezes it.
Everything below was either renamed or removed pre-1.0; the
v1.0.0 release won't break any of these again.

### Wrapper transport names

The mode list is now: `preload`, `systrap`, `systrap-static`,
`systrap-supervised`, `ptrace`, `ptrace-seccomp`, `ptrace-only`,
`auto`. The auto cascade order is documented in
`docs/features/transparent-wrapper.md`.

Removed aliases (the wrapper rejects these now — no transparent
fall-back):

| Old | New |
|---|---|
| `--transport=preload-static` | `--transport=systrap-static` |
| `--transport=preload-and-ptrace` | `--transport=systrap` |
| `--transport=preload-with-optional-ptrace` | `--transport=auto` |

### Transport `WebSocketConfig.SNIHostname`

```yaml
# OLD — removed
transports:
  - name: wss-edge
    base: https
    websocket:
      sni_hostname: front.example.com

# NEW — equivalent
transports:
  - name: wss-edge
    base: https
    tls:
      server_sni: front.example.com
```

### Transport `proxy.type=turn`

```yaml
# OLD — removed (the rewrite shim is gone)
transports:
  - name: turn-relay
    base: udp
    proxy:
      type: turn
      turn:
        server: turn.example.com:3478

# NEW — direct
transports:
  - name: turn-relay
    base: turn
    turn:
      server: turn.example.com:3478
```

### `inbound.max_connections` default

The default went from `0` (unlimited) to `16384`. If you need
unlimited, set it explicitly:

```yaml
inbound:
  max_connections: 0          # explicit unlimited
  max_connections_per_peer: 0 # explicit unlimited
```

If you don't have an `inbound:` block at all, you're already on
the new defaults — most configs don't need any change.

### SOCKS UDP buffer + session caps

The internal `socksUDPSessionBufBytes` (per-session receive buffer)
dropped from 64 KiB to 8 KiB; `maxSOCKSUDPSessionsPerConn` from
256 to 64. These are NOT user-tunable knobs — no config change
needed. If your SOCKS5 client uses jumbo UDP frames > 8 KiB
through the proxy, file an issue; we haven't seen one.

### Removed test-helper

If you were running `TestUWGWrapperBothMixedInterop` directly,
it's gone. Its coverage moved to
`TestSystrapSupervisedDynamicExecsStatic` in
`tests/preload/systrap_supervised_test.go`.

### Documentation paths moved

Mostly cosmetic — the doc-link checker in the pre-commit hook
auto-rewrote internal links. External links that pointed at the
old paths need updating:

| Old path | New path |
|---|---|
| `docs/reference/mesh-control.md` | `docs/features/mesh-coordination.md` |
| `docs/reference/transport-modes.md` | `docs/features/transports.md` |
| `docs/reference/turn.md` | `docs/features/turn-server.md` |
| `docs/reference/acls.md` | `docs/features/relay-and-acls.md` |
| `docs/reference/proxy-routing.md` | `docs/features/proxies-and-forwards.md` |
| `docs/reference/wrapper-modes.md` | `docs/features/transparent-wrapper.md` |
| `docs/reference/metrics.md` | `docs/operations/observability.md` |
| `docs/reference/testing.md` | `docs/contributing/testing.md` |
| `docs/reference/security-model.md` | `docs/contributing/security-conventions.md` |

### Verifying release artifacts (new)

From v1.0.0, release binaries and container images are signed
via Sigstore (cosign keyless, OIDC-bound to this repo's release
workflow). Verify with:

```bash
cosign verify-blob \
    --certificate uwgsocks-linux-amd64.pem \
    --signature uwgsocks-linux-amd64.sig \
    --certificate-identity-regexp \
       "https://github.com/reindertpelsma/userspace-wireguard-socks/.github/workflows/release.yml@.*" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    uwgsocks-linux-amd64
```

If you were pulling pre-1.0 binaries unchecked, this is the
upgrade path. SBOMs are attached as additional release assets.

## Future migrations

Each future major-version migration will add a section here with
the same shape: old key → new key + the rationale.
