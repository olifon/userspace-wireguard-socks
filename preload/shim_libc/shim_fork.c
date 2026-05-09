/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_fork.c — ensure SIGSYS is unblocked in every forked child.
 *
 * Problem: Chrome's process-launch sequence calls fork() to create a
 * pre-renderer subprocess. Between the fork() and the subsequent
 * execve(), the pre-renderer inherits whatever signal mask the parent
 * (Chrome browser) had. If SIGSYS is blocked in the parent — either
 * because Chrome's own init called sigprocmask(SIG_BLOCK, all) before
 * our PLT shim was active, or because glibc's fork() temporarily
 * blocks all signals and the restored mask was already blocking SIGSYS
 * — then the pre-renderer starts with SIGSYS blocked.
 *
 * When the pre-renderer's execve() hits our seccomp SECCOMP_RET_TRAP,
 * the kernel calls force_sig_info(SIGSYS, ...). If SIGSYS is blocked,
 * force_sig_info resets the disposition to SIG_DFL and delivers with
 * default action (core dump / terminate). The pre-renderer dies before
 * our SIGSYS handler ever runs, so the execve interception is lost.
 *
 * Fix: override fork() via PLT. After each fork, in the child, issue
 * rt_sigprocmask(SIG_UNBLOCK, {SIGSYS}) directly. This is the last
 * line of defense regardless of which code path blocked SIGSYS.
 *
 * dlsym(RTLD_NEXT, "fork") obtains glibc's fork implementation (with
 * its pthread_atfork handlers and malloc-lock cleanup) so we don't
 * skip any glibc fork machinery — we only add one inline syscall in
 * the child.
 */

#ifndef UWG_FREESTANDING

#include <stdint.h>
#include <sys/syscall.h>

#include "../core/syscall.h"

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
        /* Unblock SIGSYS so execve seccomp traps reach our handler.
         * rt_sigprocmask is NOT in the BPF trap list, so this raw
         * syscall passes straight through without re-triggering
         * SIGSYS. Safe to call even with SIGSYS currently blocked. */
        unsigned long sigsys_bit = (unsigned long)1 << (SIGSYS - 1);
        uwg_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                     (long)&sigsys_bit, 0L, 8L);
    }
    return pid;
}

#endif /* !UWG_FREESTANDING */
