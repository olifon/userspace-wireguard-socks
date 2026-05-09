/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_sigprocmask.c — prevent SIGSYS from being blocked while the
 * seccomp filter is active.
 *
 * When SECCOMP_RET_TRAP fires the kernel delivers SIGSYS via
 * force_sig_info(). If SIGSYS is in the thread's blocked signal mask,
 * force_sig_info() resets the disposition to SIG_DFL and delivers —
 * killing the process before our handler ever runs.
 *
 * Chrome's LaunchProcess double-fork pattern blocks all signals on the
 * intermediate fork (sigfillset + sigprocmask(SIG_BLOCK, all)), so the
 * doubly-forked grandchild inherits a blocked SIGSYS. When its execve
 * triggers the seccomp trap, force_sig_info sees SIGSYS blocked, resets
 * the handler, and kills the grandchild.
 *
 * Fix: strip SIGSYS from any SIG_BLOCK or SIG_SETMASK operation when
 * the seccomp filter is active (bypass_secret != 0). SIG_UNBLOCK passes
 * through unchanged; a NULL set pointer passes through unchanged.
 */

#ifndef UWG_FREESTANDING  /* libc shim is only for the .so build */

#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>

#include "../core/syscall.h"

extern uint64_t uwg_bypass_secret;

/* SIGSYS is signal 31; bit 30 (0-indexed) in the first unsigned long
 * of the sigset. Clear it without relying on sigdelset (which may be
 * a libc symbol we're shadowing). */
static void uwg_strip_sigsys_from_set(sigset_t *s) {
    unsigned long *w = (unsigned long *)s;
    w[0] &= ~(1UL << (SIGSYS - 1));
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    if (set != NULL && uwg_bypass_secret != 0 &&
            (how == SIG_BLOCK || how == SIG_SETMASK)) {
        sigset_t filtered = *set;
        uwg_strip_sigsys_from_set(&filtered);
        long rc = uwg_syscall4(SYS_rt_sigprocmask, (long)how,
                               (long)&filtered, (long)oldset, 8L);
        if (rc < 0) {
            extern int *__errno_location(void);
            *__errno_location() = (int)-rc;
            return -1;
        }
        return 0;
    }
    long rc = uwg_syscall4(SYS_rt_sigprocmask, (long)how,
                           (long)set, (long)oldset, 8L);
    if (rc < 0) {
        extern int *__errno_location(void);
        *__errno_location() = (int)-rc;
        return -1;
    }
    return 0;
}

/* pthread_sigmask is identical to sigprocmask on Linux (same kernel
 * interface, different POSIX scope semantics that are irrelevant here
 * since we're already single-threaded at fork time). */
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
    return sigprocmask(how, set, oldset);
}

#endif /* !UWG_FREESTANDING */
