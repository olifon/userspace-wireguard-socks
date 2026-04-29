/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Inert SIGSYS pre-init stub for systrap-supervised mode.
 *
 * == What this is ==
 *
 * A minimal SIGSYS handler that the supervisor injects into a tracee
 * BEFORE the tracee's libc-init runs in the post-execve window. Once
 * the wrapped program's real Phase 1 LD_PRELOAD constructor runs, it
 * replaces this stub with the full uwg_sigsys_handler from sigsys.c.
 *
 * == Why ==
 *
 * Today preload/core/seccomp.c trims read / write / close / dup /
 * fcntl out of the trap list because libc-init in the post-execve
 * child runs them heavily and would die on a SIGSYS without an
 * installed handler (signal handlers reset on execve, the inherited
 * filter does not). That trade-off forfeits coverage of those
 * syscalls when called from raw asm — Go-runtime / a few portability
 * shims that bypass the libc symbol layer.
 *
 * Under systrap-supervised the supervisor can ptrace the tracee
 * mid-execve and install this inert stub at the post-execve stop
 * before user code runs. Once the stub is in place we can re-add
 * read/write/close/dup/fcntl to the trap list without losing the
 * post-execve window. Phase 1's real constructor running later
 * overwrites the SIGSYS sa_handler with the dispatching uwg_sigsys_
 * handler, and all subsequent SIGSYS events go through normal
 * dispatch.
 *
 * == What this stub does ==
 *
 * Receive SIGSYS, decode the syscall nr + first 6 args from the
 * ucontext, re-issue the same syscall via raw asm with the bypass
 * secret in arg6, write the return value back into the ucontext's
 * RAX/X0 slot, and return. The kernel's signal-return path then
 * resumes the tracee with the syscall's effective return value in
 * the ABI return register.
 *
 * == Status ==
 *
 * SCAFFOLDED, not built or wired yet. The full integration needs:
 *
 *   1. Position-independent asm version of this stub for both
 *      x86_64 and arm64 (the ucontext field offsets differ across
 *      arches and across kernel versions). Probably easier to have
 *      the Go supervisor side emit the asm directly into the
 *      tracee's mmap'd page (codex's installAMD64CallStub pattern).
 *
 *   2. Supervisor wiring at PTRACE_EVENT_EXEC: mmap a page in the
 *      tracee, write the stub bytes, call rt_sigaction(SIGSYS,
 *      &stub_addr) via remoteSyscall, then PtraceCont. All three
 *      steps need to happen BEFORE the tracee's first user-space
 *      instruction runs.
 *
 *   3. seccomp.c trap-list expansion: add SYS_read, SYS_write,
 *      SYS_close, SYS_dup, SYS_dup2, SYS_dup3, SYS_fcntl back to
 *      uwg_trapped_syscalls[], gated on the supervised flag (so
 *      bare systrap mode keeps its current narrower list and
 *      doesn't need this stub).
 *
 *   4. BPF builder: fd 0/1/2 fast-skip for read/write/close/dup/
 *      fcntl. Inserted between the syscall-nr load and the trap
 *      loop: if nr is one of the stdio-relevant ones AND args[0]
 *      is < 3, RET_ALLOW. Saves a SIGSYS round-trip on every stdio
 *      syscall, which would dominate post-trap-list-expansion cost.
 *      Stdio fds are essentially never WireGuard-tunnel sockets
 *      (would have to be intentional dup2 over them, which breaks
 *      stdio for the rest of the process).
 *
 *   5. Test: tests/preload/inert_stub_test.go that verifies a
 *      raw-asm read/write on a non-stdio tunnel-managed fd is
 *      handled correctly by the stub during the post-execve window.
 *
 * Tracked as task #92.
 */

#ifndef UWG_FREESTANDING
#include <signal.h>
#include <stdint.h>
#include <sys/ucontext.h>

/*
 * Reference C implementation. The runtime stub will be the asm
 * equivalent injected by the supervisor; this C version is here as
 * the canonical specification + a place a future test could link
 * against to validate the contract.
 *
 * The actual asm needs to:
 *   1. Read uc_mcontext.gregs[REG_RAX] (or REG_ORIG_RAX where
 *      available) for the syscall nr.
 *   2. Read gregs[REG_RDI/RSI/RDX/R10/R8/R9] for args 1-6.
 *   3. Issue a raw syscall with the bypass secret as arg6 (overrides
 *      caller's arg6 if any — that's correct because syscalls with
 *      6 args are extremely rare and the secret check is what makes
 *      the syscall pass our own filter).
 *   4. Store the return in gregs[REG_RAX].
 *
 * Async-signal-safe: only inline-asm syscalls, no libc calls, no
 * allocation, no global state mutation.
 */
extern uint64_t uwg_bypass_secret;

void uwg_inert_sigsys_stub(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    (void)info;
    /*
     * Placeholder. The real implementation must use inline asm to
     * read the ucontext's gregs without depending on the libc
     * mcontext_t layout (which has changed across glibc versions).
     * For now: NOP.
     *
     * The supervisor will not call this C function; it will inject
     * a precomputed asm blob. This file documents the contract and
     * is excluded from the build (no build_phase1.sh entry yet).
     */
    (void)ucontext;
}
#endif /* UWG_FREESTANDING */
