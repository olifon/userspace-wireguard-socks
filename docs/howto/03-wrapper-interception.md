<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 03 Wrapper Interception

Previous: [02 Server And Ingress](02-server-and-ingress.md)  
Next: [04 Firewall And ACLs](04-firewall-and-acls.md)

`uwgwrapper` forces unmodified Linux applications through the mesh, including
programs that do not speak SOCKS5 or HTTP and even statically linked binaries
that bypass libc fast paths.

## Start The Wrapper-Friendly Daemon

```bash
./uwgsocks --config ./examples/socksify.yaml
```

The example is [`examples/socksify.yaml`](../../examples/socksify.yaml):

```yaml
wireguard:
  config_file: ./examples/client.conf

api:
  listen: unix:/tmp/uwgsocks-api.sock
  allow_unauthenticated_unix: true

proxy:
  http_listeners:
    - unix:/tmp/uwgsocks-http.sock

socket_api:
  bind: true
  transparent_bind: false
  udp_inbound: false
```

That gives you two local control points:

- a management API socket at `unix:/tmp/uwgsocks-api.sock`
- an HTTP upgrade listener at `unix:/tmp/uwgsocks-http.sock`

`uwgwrapper` uses the HTTP upgrade listener, not a separate daemon protocol.
That listener can live on a Unix socket file or on a loopback HTTP address.

## Wrap An Unmodified Linux App

```bash
./uwgwrapper --api unix:/tmp/uwgsocks-http.sock -- curl https://ifconfig.me
```

That is the common case: same host, Unix socket transport, and no extra TCP
listener.

## Unix Socket Or HTTP URL

Use a Unix socket when the daemon is local and you want filesystem-scoped
access:

```bash
./uwgwrapper --api unix:/tmp/uwgsocks-http.sock -- curl https://ifconfig.me
```

Use an HTTP URL when the wrapper needs to reach the daemon over loopback or a
supervised local TCP listener:

```bash
./uwgsocks --config ./examples/server.yaml
./uwgwrapper --api http://127.0.0.1:9090 --token demo-api-token-change-me -- curl https://ifconfig.me
```

Both routes end up at the same `/uwg/socket` raw socket API.

## SSH ProxyCommand / stdin Mode

If you do not need `LD_PRELOAD` at all and only want a clean TCP pipe over the
tunnel, `uwgwrapper` can bridge stdin/stdout directly to one tunnel TCP
destination:

```bash
./uwgwrapper \
  --api unix:/tmp/uwgsocks-http.sock \
  --stdio-connect 100.64.90.10:22
```

That is useful as an SSH `ProxyCommand`:

```sshconfig
Host mesh-host
  HostName 100.64.90.10
  ProxyCommand /usr/local/bin/uwgwrapper --api unix:/tmp/uwgsocks-http.sock --stdio-connect %h:%p
```

This path does not consume another WireGuard peer. It is just one more tunnel
TCP stream created through `/uwg/socket`, so multiple commands can be stacked
or run in parallel without editing the peer list.

## Which Path Should You Prefer?

- Use native SOCKS5 or HTTP if the app already supports it.
- Use `--stdio-connect` when the caller already speaks stdin/stdout socket semantics, such as SSH `ProxyCommand`.
- Use `uwgwrapper` when the app cannot speak SOCKS5 or HTTP directly, whether it is hard-coded, static, or just not proxy-aware.

The wrapper is a compatibility layer, not a sandbox. It forces network syscalls
through `uwgsocks`; it does not change the process' Unix privileges.

## Why It Still Works On Static Go Or Rust Binaries

- `transport=systrap-elf` (the default for static targets when seccomp is
  available): patches the binary's ELF headers in a memfd, appending a
  `PT_INTERP` entry pointing at `uwgptloader.so`. The kernel loads the ptloader
  as the ELF interpreter before `_start`, installing the seccomp+SIGSYS handler
  without any ptrace. **No `SYS_PTRACE` capability required.**
- `transport=systrap` (dynamic targets in containers without ptrace): `LD_PRELOAD`
  catches the libc path; a seccomp-bpf filter + in-process SIGSYS handler catches
  raw-asm syscalls. No tracer attached.
- `transport=systrap-supervised` [experimental]: same in-process SIGSYS path as
  `systrap`, plus a persistent ptrace supervisor that re-arms interception at every
  exec boundary. Has a known concurrency race under multi-threaded raw-asm syscall
  load (e.g. Caddy, Python's `test_urllib`). Not selected by `auto`; must be
  explicitly requested. Prefer `systrap-elf` for most exec-chain workloads.
- `transport=ptrace`/`ptrace-only`: per-syscall ptrace fallback for hosts where
  seccomp is not available.
- `transport=preload`: libc-only fallback when neither seccomp nor ptrace is
  available — raw-asm syscalls bypass interception silently.

`auto` probes seccomp and ptrace availability, ELF-checks the target for
`PT_INTERP`, and picks the strongest viable mode. Dynamic-target cascade:
`systrap-elf` → `systrap` → `ptrace-seccomp` → `ptrace` → `preload`.
Static-target cascade: `systrap-elf` → `systrap-static` → `ptrace-seccomp` →
`ptrace` → fail-fast. `systrap-supervised` is not in the auto cascade.

That combination is why `uwgwrapper` is closer to "socksify for any Linux binary"
than to a normal proxy helper. See
[10 Minecraft Soak](10-minecraft-soak.md) for a concrete walkthrough of
`transport=systrap` with a Java/JVM workload, and
[`docs/features/transparent-wrapper.md`](../features/transparent-wrapper.md)
for the full mode comparison + per-host-shape `auto` cascade.

## Static binaries in containers that block ptrace

Some container runtimes (Docker default seccomp profile, Kubernetes pods without
`SYS_PTRACE`, gVisor) block `ptrace(2)` even when they allow `seccomp(2)`.

`systrap-elf` was designed for exactly this shape. It uses ELF `PT_INTERP`
injection rather than ptrace-based blob injection, so it works in any container
that allows seccomp. `auto` selects it automatically for static targets.

One remaining case where ptrace still matters: if your workload is a **dynamic**
binary (e.g. `bash`, a Python script, a JVM) that `execve`s into a **static**
descendant. On either a ptrace-blocked or ptrace-allowed host, `systrap-elf`
handles this via `execve_docker_dispatch` in the ptloader — no ptrace required.

If your container blocks ptrace and your workload has the dynamic-parent-to-static-
child pattern, `systrap-elf` is the right choice (and is what `auto` selects).

See [`docs/features/transparent-wrapper.md`](../features/transparent-wrapper.md)
for the full host-shape compatibility table.

## Server processes that fork privileged workers (Apache, Chromium)

Some server processes fork worker children and then drop privileges (e.g.
Apache event-MPM setuids workers to `www-data`; Chromium setuids its
renderer sandbox). These workers can no longer read the root-owned
shared-state file (`/tmp/uwgwrapper-*/shared-state-*.bin`, mode 0600),
and they lose access to the fdproxy unix socket, so wrapped connections
opened after the privilege drop fail.

**Current recommendation: disable worker sandboxing for these processes
when running under `uwgwrapper`.** This is the same guidance given for
Chromium (which exposes a `--no-sandbox` flag). For Apache, this means
configuring workers to run as the same user as the wrapper rather than a
lower-privilege account (e.g. run `uwgwrapper` as the web user and drop
the `User`/`Group` directive, or use `mod_mpm_event` with a single
non-setuid pool).

This is not a false claim about the wrapper's security properties — the
wrapper is a network-routing shim, not a security sandbox. It does not
prevent what the underlying OS allows; it merely redirects socket traffic.
Running with `--no-sandbox` or equivalent does not weaken the tunnel
itself.

A proper solution (passing the shared memfd through the process tree via
inheritance, verifying via fdproxy auth) is planned but not yet
implemented.
