<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Wrapper transport modes

`uwgwrapper` runs unmodified Linux applications and routes their
network syscalls through a `uwgsocks` instance. There are several
ways to perform that interception, each with different requirements
on the host and different cost/coverage tradeoffs. Pick a mode
explicitly with `--transport=...`, or let `auto` pick.

## Mode summary

| Mode | Libc hooks | Seccomp+SIGSYS | Ptrace | execve chain | Static target | Requires |
|---|---|---|---|---|---|---|
| `preload` | ✅ | — | — | libc only | ❌ | nothing |
| `systrap` | ✅ | ✅ | — | dynamic only | ❌ | seccomp |
| `systrap-docker` | ✅ (dynamic) / ptloader (static) | ✅ | — | ✅ full chain via `execve_docker_dispatch` | ✅ | seccomp |
| `systrap-supervised` | ✅ | ✅ | execve boundary only | ✅ full chain via ptrace supervisor | ✅ | seccomp + ptrace |
| `systrap-static` | — | ✅ | ✅ every execve | ✅ | ✅ | ptrace |
| `ptrace-seccomp` | — | filter only | ✅ every traced call | ✅ | ✅ | ptrace |
| `ptrace-only` | — | — | ✅ every syscall | ✅ | ✅ | ptrace |
| `ptrace` | — | tries, falls back | ✅ | ✅ | ✅ | ptrace |
| `auto` | varies | varies | varies | varies | yes — see cascade | — |

**Key differences between `systrap-docker` and `systrap-supervised`:**

Both handle full exec chains and static targets. The difference is *how* they get interception into a static binary and *what they require from the host*:

- `systrap-docker` — patches the target ELF's headers at launch time using a memfd. The kernel loads `uwgptloader.so` as the ELF interpreter (`PT_INTERP`) before `_start`, so the ptloader installs SIGSYS+seccomp without any ptrace involvement. `execve_docker_dispatch` inside the ptloader handles subsequent exec boundaries. **No ptrace required.** Works in Docker default seccomp profiles.
- `systrap-supervised` — runs a persistent ptrace supervisor that wakes only at execve boundaries. On a dynamic→static exec it injects the freestanding blob into the static child via remote mmap. On dynamic→dynamic it relies on LD_PRELOAD propagation. **Requires ptrace.** Preferred when exec chains spawn a mix of dynamic and static descendants of a dynamic root (e.g. `bash -c 'some-static-bin'`), because the supervisor can re-arm interception across transitions that systrap-docker would have to handle via the ptloader.

For a standalone static binary or a static binary that doesn't exec into dynamic children, `systrap-docker` is simpler, requires fewer kernel capabilities, and avoids the ptrace supervisor goroutine entirely.

## What needs ptrace, in detail

A clear mental model for when ptrace is mandatory vs. optional:

| Scenario | ptrace needed? | Why |
|---|---|---|
| Static binary, `systrap-docker` initial exec | **Not needed** | `uwgptloader.so` is injected via ELF `PT_INTERP` into a memfd. The kernel loads it as the interpreter before `_start` — no ptrace involved. seccomp is required; ptrace is not. |
| Static binary, `systrap-static` / `systrap-supervised` blob inject | **Mandatory for these modes** | These modes inject a freestanding blob via `PTRACE_TRACEME` + remote `mmap` + `POKEDATA` at the post-exec stop. `systrap-docker` exists precisely to avoid this requirement on hosts where ptrace is blocked. |
| Dynamic binary, very first injection (`systrap`) | Not needed | `LD_PRELOAD` propagates through `execve(2)`, the dynamic linker loads our `.so`, the constructor installs SIGSYS+seccomp before user `main` runs. |
| `execve` boundary, dynamic→dynamic | Not needed | `LD_PRELOAD` is in `envp`, kernel preserves it. New image's dynamic linker re-loads our `.so`, constructor re-installs the handler. The seccomp filter is also kernel-inherited. |
| `execve` boundary, dynamic→static (`systrap-docker`) | Not needed | `execve_docker_dispatch` in the ptloader detects the static child, patches it via memfd+PT_INTERP, and re-execs it. No ptrace involved. |
| `execve` boundary, dynamic→static (`systrap-supervised`) | **Mandatory** | `LD_PRELOAD` is meaningless on a static binary. The ptrace supervisor re-injects the freestanding blob at the post-exec stop. |
| `execve` boundary, static→anything (`systrap-docker`) | Not needed | Same `execve_docker_dispatch` path — the ptloader intercepts the exec syscall via SIGSYS and handles it. |
| Multi-threaded process exec'ing | Mandatory only for ptrace-based modes | `execve` kills all sibling threads atomically (kernel guarantee — only the calling thread survives). `systrap-docker` is unaffected — the ptloader is loaded by the kernel before any thread runs. |

## `auto` cascade — what it picks per host shape

`auto` first probes seccomp + ptrace availability, then ELF-checks
the target binary for `PT_INTERP` (= dynamically linked) vs no
`PT_INTERP` (= statically linked), and picks the strongest mode
that can actually intercept this target:

### Dynamic target

| Host shape | `auto` picks | What works | What doesn't |
|---|---|---|---|
| seccomp ✅, ptrace ✅ | **`systrap-supervised`** | Everything: dynamic, dynamic→static execve, dynamic→dynamic execve, multi-threaded execve, fork+exec trees | (nothing) |
| seccomp ✅, ptrace ❌ (typical container: Docker default seccomp, K8s pods w/o `SYS_PTRACE`) | **`systrap-docker`** (PT_INTERP injection, no ptrace) | The dynamic target and any static or dynamic exec descendants (`uwgptloader.so` is injected via `PT_INTERP` into a memfd; the entire exec chain is covered without ptrace) | (nothing) |
| seccomp ❌, ptrace ✅ (sandbox-inside-sandbox edge cases) | **`ptrace`** (auto-picks ptrace-seccomp / ptrace-only inside) | Everything (slow — every syscall round-trips through the tracer) | (nothing) |
| seccomp ❌, ptrace ❌ (very restricted container) | **`preload`** (libc-only) | Libc-routed network calls in the dynamic target | Raw-asm syscalls (Go runtime internals, some C++/Rust net code), descendants that exec into anything bypassing libc |

### Static target

The libc-only `preload` mode and the no-ptrace `systrap` mode
**cannot intercept a static target at all** (no LD_PRELOAD path on
a static binary; the inherited seccomp filter without an installed
SIGSYS handler kills the child on the first trapped syscall).
Auto uses an ELF pre-flight (`PT_INTERP` absent) to detect this
and picks the strongest available mode, or fails fast.

| Host shape | `auto` picks | Notes |
|---|---|---|
| seccomp ✅ (ptrace optional) | **`systrap-docker`** | PT_INTERP injection via memfd — works with or without ptrace. `auto` prefers this for static targets unconditionally when seccomp is available: it does not depend on ptrace-based memory injection, which many container profiles block even when basic ptrace is allowed. Use `--transport=systrap-supervised` explicitly if you need the execve ptrace supervisor (e.g. a static binary that shells out to a mix of dynamic and static children). |
| seccomp ❌, ptrace ✅ | **`ptrace-only`** | Universal slow path via per-syscall ptrace. |
| seccomp ❌, ptrace ❌ | **error** | No mode can intercept a static binary. Options: (a) use a host that allows seccomp or ptrace, (b) wrap a dynamic target, (c) `--transport=preload --force-preload` to accept no-interception. |

> **Kernel-availability fact.** `SECCOMP_RET_TRAP` and `SECCOMP_RET_TRACE` were added in the same kernel commit (Linux 3.5, `c2e1f2e30daa`, 2012). There is no host that ships one without the other — they're both return values of the same `seccomp(2)` syscall. So the "seccomp ✅" hosts above all support both `RET_TRAP` (powering systrap's SIGSYS path) and `RET_TRACE` (used for the execve hook in the supervisor). The independent variable is **ptrace**, which container runtimes commonly block separately from seccomp.

## Choosing a mode explicitly

- **`auto`**: let the wrapper probe + decide. Recommended for
  general use. Fails fast on a static target without a working
  interception path rather than running it un-armed.
- **`systrap-supervised`**: full hosts (most Linux ≥ 4.8 + ptrace
  allowed). Handles dynamic↔static execve seamlessly via the
  ptrace supervisor. Fastest path that's also fully correct.
- **`systrap`**: containers that ban `ptrace(2)` but allow
  `seccomp(2)` (Docker default seccomp profile, K8s pods without
  `SYS_PTRACE`). Same in-process SIGSYS as `systrap-supervised`
  but no execve supervisor, so static descendants of a fork+exec
  lose interception. The right pick when you know your container
  policy blocks ptrace and your workload is dynamic-only.
- **`systrap-docker`**: containers that ban `ptrace(2)` but allow
  `seccomp(2)` **and** the target is (or may be) a static binary.
  Uses ELF `PT_INTERP` injection to load `uwgptloader.so` as the
  kernel interpreter before `_start`; installs SIGSYS+seccomp
  without ptrace. `execve_docker_dispatch` inside the ptloader
  handles further exec chains (static→static, static→dynamic,
  dynamic→static) automatically. `auto` selects this for static
  targets on seccomp-yes/ptrace-no hosts.
- **`preload`**: containers that ban both `seccomp(2)` and
  `ptrace(2)`. Libc-only. The cost is that any caller using
  raw-asm syscalls (parts of the Go runtime, some C++/Rust
  networking code) bypass interception silently.
- **`systrap-static`**: when your target is a statically-linked
  binary (Go-with-`CGO_ENABLED=0`, musl-static C/Rust, BusyBox),
  or when libc on the host is broken / can't link our `.so`.
  Assumes everything is static and tracks new binaries via
  `RET_TRACE` on every `execve`. **Requires ptrace.** The wrapper
  does a pre-flight ptrace probe and fails fast with a clear
  error if ptrace is blocked on this host.
- **`ptrace-only`**: debugging or hosts that block seccomp entirely
  but allow ptrace. Slow.

## Performance — relative cost per intercepted syscall

There are two kinds of network calls in a Linux process:

- **Libc-routed calls** — the app calls `connect()`, `send()`, `recv()` etc.
  via libc. Under any `systrap*` or `preload` mode, our LD_PRELOAD shim
  intercepts these *before* the syscall instruction executes. The seccomp
  filter never fires. Cost: one indirect function call into the shim (~10 ns).
- **Raw-asm calls** — the app issues a `syscall` instruction directly,
  bypassing libc (parts of the Go runtime, some C++/Rust network code, Go
  binaries with `CGO_ENABLED=0`). The seccomp filter fires on every such
  call; in `systrap*` modes this delivers a SIGSYS to an in-process handler.

This split is the performance bypass: **libc calls never touch the seccomp
filter at all under systrap modes**. For most apps (Chromium, JVM, anything
linking glibc or musl) the vast majority of network syscalls are libc-routed,
so the effective overhead of `systrap*` vs `preload` is negligible in practice.

| Mode | Libc-routed call | Raw-asm call | Notes |
|---|---|---|---|
| `preload` | **~10 ns** — shim redirects to tunnel socket, then one kernel syscall | unmodified kernel cost; **not intercepted** — goes direct, bypasses the tunnel | Leaks raw-asm syscalls silently. Only safe for apps that exclusively use libc for networking. |
| `systrap` | **~10 ns** — same libc shim as `preload`; seccomp filter does not fire | **~200–500 ns** — SIGSYS delivered in-process, handler dispatches, tunnel syscall issued; no context switch to a tracer | Libc hot path is identical to `preload`. Raw-asm pays a SIGSYS round-trip *within the same process* — far cheaper than ptrace. |
| `systrap-docker` (dynamic target) | **~10 ns** — same LD_PRELOAD shim; ptloader installed seccomp, libc calls bypass it identically | **~200–500 ns** — same in-process SIGSYS path as `systrap` | Same hot-path cost as `systrap`. The ptloader is only involved at startup and exec boundaries; it does not add per-syscall overhead. |
| `systrap-docker` (static target) | n/a — no libc | **~200–500 ns** — ptloader installed SIGSYS handler before `_start`; same in-process cost as `systrap` raw-asm path | No libc hooks, so every network syscall pays the SIGSYS cost. Still in-process with no tracer; fast in absolute terms. |
| `systrap-supervised` | **~10 ns** — identical to `systrap` | **~200–500 ns** — identical to `systrap` | The ptrace supervisor is **dormant** between execve events; zero per-syscall ptrace cost during normal operation. |
| `systrap-static` | n/a — no libc | **~200–500 ns** — same in-process SIGSYS path | Like `systrap-docker` for static targets but requires ptrace for initial injection. Same runtime cost once running. |
| `ptrace-seccomp` | **~10–100× `systrap`** per traced call | same | Full ptrace round-trip per traced syscall: tracee stops, kernel switches to tracer, tracer runs, kernel switches back. Seccomp pre-filter limits which syscalls are traced. |
| `ptrace-only` | **~100–1000× `preload`** for every syscall | same | Double context-switch on every syscall. Use only when seccomp is unavailable. |

**Practical takeaway:** for any dynamically-linked app (Go with cgo, Rust,
Chromium, JVM, Python), all modes up to and including `systrap-supervised`
deliver effectively **`preload` performance** — the libc bypass means the seccomp
filter never fires on the hot path. `systrap*` modes only add overhead for
raw-asm syscallers, and even then the SIGSYS in-process cost is at least an
order of magnitude cheaper than the ptrace round-trip `ptrace*` modes pay for
every call.

## Environment variables

- `UWGS_WRAPPER_TRANSPORT=systrap` — equivalent to
  `--transport=systrap`. Useful in shell wrappers / CI.
- `UWGS_DISABLE_SYSTRAP=1` — set by the wrapper automatically when
  `transport=preload` is selected. The `.so` constructor reads
  this and skips installing the SIGSYS handler + seccomp filter.
  You can set this manually for testing the libc-only path under
  a different transport.
- `UWGS_DISABLE_SECCOMP=1` — legacy alias for
  `UWGS_DISABLE_SYSTRAP`. Both work.

## What systrap-supervised does on each execve boundary

Once attached, the supervisor waits on
`PTRACE_EVENT_SECCOMP` for `SYS_execve` / `SYS_execveat` (the
filter installed by the `.so` constructor returns
`SECCOMP_RET_TRACE` for those when `UWGS_SUPERVISED=1` is in the
environment). On every event:

1. Let the syscall continue (`PTRACE_CONT`).
2. Wait for the follow-up `PTRACE_EVENT_EXEC` stop. (Note: this
   only fires when execve **succeeds**. A failed `execve(2)`
   returns through the SECCOMP event with the original image
   intact and never produces a EXEC stop — handled correctly
   by the loop.)
3. Single-step once. The EXEC stop fires inside the kernel's
   syscall-exit path (PC has been switched to the new image's
   entry but the syscall hasn't unwound); remote `mmap` is
   unreliable from here. Single-step advances the tracee to
   the first user-space instruction where regs are user-mode
   regs and remote syscalls work.
4. Open `/proc/<pid>/exe` and inspect `PT_INTERP`:
   - present → dynamic image; `LD_PRELOAD` will re-run the
     `.so` constructor in the new image; supervisor does
     nothing.
   - absent → static image; supervisor injects the
     freestanding blob via the same machinery as
     `systrap-static` (parse blob → remote `mmap` →
     `PTRACE_POKEDATA` segments → jump to `uwg_static_init`).
5. `PTRACE_CONT` and loop.

The supervisor stays attached for the **entire lifetime** of the
process tree (it never `PTRACE_DETACH`es). Children spawned via
`fork`/`vfork`/`clone` are auto-traced via
`PTRACE_O_TRACEFORK` / `TRACEVFORK` / `TRACECLONE`. The supervisor
exits with the same status as the root traced PID; non-traced
sibling processes (the fdproxy daemon spawned by the wrapper)
are filtered out of the wait loop by PID.
