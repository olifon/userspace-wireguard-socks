/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * SA_RESTORER trampoline used by both the .so build and the
 * freestanding (Phase 2) static-binary build. The kernel jumps to this
 * address when a signal handler returns (sa_restorer field on x86_64 /
 * aarch64). Without it, the tracee crashes on the first SIGSYS return.
 *
 * The .so build needs this when it installs its SIGSYS handler via
 * uwg_passthrough_syscall4 (rather than libc's sigaction wrapper). The
 * passthrough is required so the BPF prologue's bypass-secret check
 * ALLOWs the install through the conditional rt_sigaction(SIGSYS) trap
 * — but bypassing libc means we don't get libc's __restore_rt for free,
 * so we provide our own trampoline.
 *
 * Inline asm only — no C runtime dependencies. The trampoline issues
 * SYS_rt_sigreturn which restores the pre-signal context.
 */

#if defined(__x86_64__)
__attribute__((naked, noreturn))
void uwg_sigreturn_trampoline(void) {
    /* SYS_rt_sigreturn = 15 on x86_64. */
    __asm__ volatile (
        "mov $15, %%rax\n\t"
        "syscall\n\t"
        ::: "rax"
    );
}
#elif defined(__aarch64__)
__attribute__((naked, noreturn))
void uwg_sigreturn_trampoline(void) {
    /* SYS_rt_sigreturn = 139 on arm64. */
    __asm__ volatile (
        "mov x8, #139\n\t"
        "svc #0\n\t"
        ::: "x8"
    );
}
#else
#  error "uwg sigreturn trampoline: unsupported arch"
#endif
