<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Stability promise

This file describes the compatibility commitment for `uwgsocks`,
`uwgwrapper`, `uwgfdproxy`, and the standalone `turn` daemon.

## Pre-1.0.0 (current state)

**No compatibility promise.** YAML keys, `/v1/*` endpoints,
wrapper transport names, mesh-control protocol versions, and
metric names may change between releases. Read the `CHANGELOG.md`
between versions; expect breakage.

## From v1.0.0 onward

Breaking changes to the surfaces below require a **major version
bump** (v1 → v2). Within a major version, the listed surfaces are
compatible — old configs and clients keep working.

### Stable surfaces

| Surface | What's stable |
|---|---|
| YAML config schema | every key in `docs/reference/config-reference.md`: name, type, semantics. New keys with new defaults are additive — old configs keep validating. Removing a key is a breaking change. |
| Runtime API | every `/v1/*` endpoint documented in `docs/reference/api-reference.md`: URL, request body shape, response body shape, status codes. Adding new endpoints + new optional fields is additive. |
| `#!` directives in wg-quick configs | `#!TURN=`, `#!URL=`, `#!Control=`, `#!TCP[=...]`, `#!SkipVerifyTLS=` syntax + semantics. |
| Socket protocol | wire format documented in `docs/reference/socket-protocol.md`. Frame layout, command shapes, response codes. |
| Mesh-control protocol | `/v1/challenge`, `/v1/peers`, `/v1/acls` endpoint shapes, auth-token version negotiation. The current default version is `v2`; the server accepts old versions for compatibility. |
| Metrics names | every `uwgsocks_*` metric in `docs/operations/observability.md`: name, labels, semantics. Adding new metrics is additive. Renaming or repurposing one is breaking. |
| Wrapper transport names | `preload`, `systrap`, `systrap-static`, `systrap-supervised`, `ptrace`, `ptrace-seccomp`, `ptrace-only`, `auto`. New modes can be added; old ones won't be removed within a major version. |
| Build flags | `-tags lite` excludes the same feature set across a major version. |
| Test env-var contracts | `UWGS_*` and `UWG_*` env vars documented in `docs/contributing/testing.md` keep their meaning. Test-only contracts; not for production use. |

### Explicitly NOT stable

| Surface | Why |
|---|---|
| Internal Go packages (`internal/...`) | not importable from external code; breakage doesn't affect consumers. |
| Wire format of WireGuard outer transports | UDP/TCP/QUIC/etc. — these are WireGuard's protocol, not ours. We track upstream wireguard-go. |
| Internal goroutine scheduling, lock ordering, conntrack table layout, eviction policies | all observable only via metrics or logs; we adjust freely. |
| Logging format and content | logs are for humans, not for programmatic consumption. Use metrics for monitoring. |
| Pre-built binary artifact paths | release.yml may rename/restructure release assets; pin by file content (cosign verification) rather than path. |

### Deprecation path within a major version

When a stable surface is replaced (e.g. a config key renamed):

1. The new surface is added in version N.
2. The old surface keeps working alongside it, with a runtime
   warning, for at least one minor-version cycle (one release
   train).
3. The `CHANGELOG.md` entry for the version that adds the new
   surface tells operators to migrate.
4. Removal of the old surface is a major-version bump.

## Reading this file

- **You're a developer/operator on a v0.x build**: nothing here
  binds the project to backward compatibility. Read `CHANGELOG.md`
  for what changed.
- **You're on a v1.x build**: the surfaces in the "Stable
  surfaces" table won't break across v1.x. Pin to the major
  version in your dependency manager.
- **You're considering depending on uwgsocks for a product**:
  wait for v1.0.0 if you need the compatibility commitment. The
  v0.x train is still iterating freely.
