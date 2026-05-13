/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_fork.c — ensure SIGSYS is unblocked and its handler is
 * reinstalled in every forked child.
 *
 * Problem 1 (original): Chrome's process-launch sequence calls fork()
 * to create a pre-renderer subprocess. Between the fork() and the
 * subsequent execve(), the pre-renderer inherits whatever signal mask
 * the parent had. If SIGSYS is blocked, force_sig_info resets the
 * disposition to SIG_DFL and terminates the child before our SIGSYS
 * handler ever runs.
 *
 * Problem 2 (glibc 2.38-2.39): glibc's fork() calls clone3 with
 * CLONE_CLEAR_SIGHAND, which resets ALL signal handlers to SIG_DFL in
 * the child — including our SIGSYS handler. Unblocking SIGSYS alone
 * is not enough: if any BPF trap fires before the handler is
 * reinstalled (e.g. a network syscall, or the conditional
 * rt_sigaction(SIGSYS) trap) the kernel delivers SIGSYS with default
 * action and the child dies.
 *
 * Primary fix: uwg_core_init() registers a pthread_atfork child handler
 * (uwg_sigsys_atfork_child) that reinstalls the SIGSYS handler INSIDE
 * glibc's fork(), before __libc_signal_restore_set() unblocks SIGSYS.
 * Because atfork child handlers run before the signal mask is restored,
 * there is no window where SIGSYS is unblocked with SIG_DFL.
 *
 * Secondary fix (this file): after real_fork() returns, re-run the
 * same reinstall as a safety net — handles forks not routed through
 * pthread_atfork (e.g. raw SYS_clone calls intercepted by shim_syscall)
 * and ensures SIGSYS is unblocked in case the parent had it masked.
 *
 * The sigaltstack set up in the parent thread is valid in the child
 * (COW copy of the parent's address space, TLS pointer preserved
 * across fork), so uwg_core_init_thread() is not needed here.
 *
 * dlsym(RTLD_NEXT, "fork") obtains glibc's fork implementation (with
 * its pthread_atfork handlers and malloc-lock cleanup) so we don't
 * skip any glibc fork machinery.
 */

#ifndef UWG_FREESTANDING

#include <stdint.h>
#include <sys/syscall.h>

#include "../core/syscall.h"
#include "../core/dispatch.h"

extern uint64_t uwg_bypass_secret;

#ifndef SIGSYS
#define SIGSYS 31
#endif
#ifndef SIG_UNBLOCK
#define SIG_UNBLOCK 1
#endif
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *)-1L)
#endif

extern void *dlsym(void *, const char *);

typedef int (*uwg_fork_fn)(void); /* pid_t == int on Linux */

int fork(void) {
    static uwg_fork_fn real_fork;
    if (__builtin_expect(!real_fork, 0)) {
        real_fork = (uwg_fork_fn)dlsym(RTLD_NEXT, "fork");
        if (!real_fork) return -1;
    }
    int pid = real_fork();
    if (pid == 0 && uwg_bypass_secret != 0) {
        /* Step 1: unblock SIGSYS. rt_sigprocmask is not in the BPF
         * trap list so this raw syscall goes straight to the kernel.
         * Safe to call even with SIGSYS currently blocked. */
        unsigned long sigsys_bit = (unsigned long)1 << (SIGSYS - 1);
        uwg_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                     (long)&sigsys_bit, 0L, 8L);

        /* Step 2: reinstall the SIGSYS handler. glibc 2.38-2.39 calls
         * clone3(CLONE_CLEAR_SIGHAND) inside fork(), which resets all
         * signal handlers to SIG_DFL in the child — including ours.
         * Without this reinstall, the very next BPF trap fires SIGSYS
         * with default action and kills the child.
         *
         * uwg_install_sigsys_handler() uses uwg_passthrough_syscall4
         * (bypass-secret in arg6) so the BPF filter's conditional
         * rt_sigaction(SIGSYS) trap does not intercept this call. */
        (void)uwg_install_sigsys_handler();
    }
    return pid;
}

#endif /* !UWG_FREESTANDING */
