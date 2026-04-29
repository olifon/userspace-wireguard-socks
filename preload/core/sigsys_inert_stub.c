/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Design doc for closing the post-execve raw-asm coverage gap (#92).
 *
 * == The gap ==
 *
 * Today preload/core/seccomp.c trims read / write / close / dup /
 * dup2 / dup3 / fcntl out of the trap list because libc-init in the
 * post-execve child runs them heavily and would die on a SIGSYS
 * without an installed handler (signal handlers reset on execve,
 * the inherited filter does not). That trade-off forfeits coverage
 * of those syscalls when called from raw asm — Go-runtime, a few
 * portability shims, and any code that bypasses libc.
 *
 * == Two designs considered ==
 *
 * --- Design A: in-tracee asm stub ---
 *
 * Supervisor at PTRACE_EVENT_EXEC mmaps a page in the tracee,
 * writes a precomputed asm SIGSYS handler (patched with the bypass
 * secret), calls rt_sigaction(SIGSYS, stub_addr) via remoteSyscall,
 * then PtraceCont. The stub: read syscall nr from siginfo->si_syscall,
 * read args from ucontext.uc_mcontext.gregs[], issue the same
 * syscall via raw asm with bypass_secret in arg6, write result back
 * to gregs[REG_RAX], return. Phase 1's real constructor later
 * overwrites the SIGSYS sa_handler with the full dispatcher.
 *
 * Pro: zero supervisor round-trip per trapped syscall after install.
 * Con: ucontext layout differs across glibc versions and arches —
 *      need separate amd64 and arm64 asm blobs, each ~50-80 bytes,
 *      kept in sync with kernel ABI changes. Plus the bypass-secret
 *      patch.
 *
 * --- Design B: supervisor-as-handler ---  *** PREFERRED ***
 *
 * No in-tracee asm. With ptrace attached, every signal stops the
 * tracee for the tracer's review (signal-delivery-stop). For SIGSYS-
 * stops in the trapped subset, the supervisor:
 *
 *   1. Reads tracee regs via PtraceGetRegs.
 *   2. Reads syscall nr from siginfo via PtraceGetSiginfo, OR from
 *      orig_rax in the regs. Reads args 0-5 from regs.
 *   3. Decides handle-or-forward (see "window detection" below).
 *   4. To HANDLE: issues the same syscall via remoteSyscall (which
 *      passes the bypass secret in arg6, so our own filter ALLOWs).
 *      Writes the result to regs.RAX. Advances RIP/PC by the
 *      syscall instruction length (2 bytes on x86_64, 4 on arm64
 *      — same as the syscall opcode width). PtraceSetRegs.
 *      PtraceCont(pid, 0) — suppresses the SIGSYS, tracee continues
 *      from past-the-syscall.
 *   5. To FORWARD: PtraceCont(pid, SIGSYS) — delivers the signal,
 *      tracee's installed handler runs, dispatches via uwg_dispatch.
 *
 * Pro: no in-tracee code. All logic in the Go supervisor. Cross-arch
 *      via the same syscall-arg helpers (cmd/uwgwrapper/exec_env_
 *      inject_amd64.go / _arm64.go) we already have.
 * Con: every trapped syscall costs a ptrace round-trip while the
 *      supervisor handles it. Acceptable because:
 *        a) The window where the supervisor handles is small (libc-
 *           init only); after phase1's constructor runs we forward
 *           SIGSYS to the in-tracee dispatcher which has zero
 *           ptrace overhead.
 *        b) The fd 0/1/2 BPF fast-skip (see below) eliminates the
 *           dominant traffic — stdio.
 *
 * == Window detection ==
 *
 * The supervisor needs to know whether to handle SIGSYS (libc-init
 * window, no in-tracee handler) or forward (post-init, in-tracee
 * dispatcher ready).
 *
 *   - Cleanest: tracee writes to /proc/self/comm or another
 *     supervisor-readable side channel when its constructor finishes.
 *   - Simpler: track per-pid state. handleExecveBoundary marks pid
 *     as "in pre-init window". The supervisor flips it when it
 *     observes the first non-trapped syscall (= phase1 constructor
 *     installed the real handler so subsequent traps ARE going to
 *     the in-tracee handler). Heuristic, but reliable in practice.
 *   - Pragmatic alternative: handle SIGSYS for fd 0/1/2 syscalls
 *     unconditionally (libc-init's pattern); forward for the rest.
 *     The BPF fd 0/1/2 fast-skip below makes this moot — stdio
 *     traps don't reach the supervisor at all.
 *
 * == BPF fd 0/1/2 fast-skip ==
 *
 * For each syscall in the expanded trap set, before RET_TRAP, emit:
 *   if syscall nr matches AND args[0] < 3: RET_ALLOW
 *
 * Saves a SIGSYS round-trip on every stdio syscall. Stdio fds are
 * essentially never WireGuard-tunnel sockets (would have to be
 * intentional dup2 over them, which breaks stdio for the rest of
 * the process).
 *
 * == Implementation order ==
 *
 *   1. Add UWG_FILTER_ARG0_LO infrastructure (already exists, used
 *      by the rt_sigaction(SIGSYS) conditional trap).
 *   2. Extend uwg_build_filter: when supervised, emit per-syscall
 *      trap entries with the fd 0/1/2 fast-skip prepended.
 *   3. Add SYS_read/write/close/dup/dup2/dup3/fcntl to a new
 *      uwg_trapped_syscalls_supervised_extra[] array, included only
 *      when supervised flag is set.
 *   4. supervisor: handle SIGSYS-stop (signal-delivery-stop with
 *      sig == SIGSYS). New helper handleSIGSYSStop in a new file
 *      cmd/uwgwrapper/sigsys_stop_handler.go. Reuses remoteSyscall
 *      / PtraceGetRegs / PtraceSetRegs / readSyscallArg /
 *      writeSyscallArg.
 *   5. Test: tests/preload/inert_stub_test.go — raw-asm read/write
 *      via syscall(2) on a non-stdio tunnel fd in the post-execve
 *      window must succeed.
 *
 * Tracked as task #92. This file exists as the design pin; no code
 * here is built or linked. The Design-A asm-stub C reference below
 * stays for posterity in case Design B's per-syscall ptrace overhead
 * becomes a bottleneck and we want to revisit.
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
