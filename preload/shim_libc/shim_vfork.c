/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_vfork.c — replace vfork() with fork() in docker mode.
 *
 * Problem: on glibc 2.38–2.39 (Ubuntu 24.04), vfork() is implemented
 * as clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND). glibc's vfork
 * implementation calls rt_sigprocmask(SIG_BLOCK, ~[]) via a direct
 * syscall instruction before invoking clone3. Because it bypasses our
 * shim_sigprocmask PLT override, SIGSYS ends up blocked.
 *
 * When clone3 then hits the docker-mode BPF SECCOMP_RET_TRAP, the
 * kernel calls force_sig_info(SIGSYS). force_sig_info_to_task sees
 * SIGSYS is blocked and resets the disposition to SIG_DFL (Linux
 * kernel: blocked forced-signal → SIG_DFL reset). SIGSYS is then
 * delivered with default action (terminate + core), killing the process
 * before our SIGSYS handler ever runs.
 *
 * Fix: intercept vfork() at PLT level. In docker mode, use fork()
 * instead. fork() creates a COW copy of the address space (no
 * CLONE_VM), so:
 *   - the child has its own address space — no aliasing hazards
 *   - fork() does not block SIGSYS before clone3
 *   - the child inherits our SIGSYS handler
 *   - the child's execve goes through shim_execve → execve_docker_dispatch
 *
 * The performance difference is insignificant for process creation.
 * Python's _posixsubprocess.fork_exec and glibc's posix_spawn both
 * call vfork() via the PLT symbol — both are intercepted by this shim.
 *
 * This shim does NOT override vfork2() or __vfork(); those symbols
 * are internal glibc names not used by application code.
 */

#ifndef UWG_FREESTANDING

#include <sys/syscall.h>
#include <stdint.h>

#include "../core/syscall.h"

extern int uwg_seccomp_docker_flag;
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

typedef int (*uwg_fork_fn)(void);

int vfork(void) {
    if (uwg_seccomp_docker_flag) {
        /* Use fork() in docker mode: no CLONE_VM, no signal blocking,
         * SIGSYS handler preserved in child. */
        static uwg_fork_fn real_fork;
        if (__builtin_expect(!real_fork, 0)) {
            real_fork = (uwg_fork_fn)dlsym(RTLD_NEXT, "fork");
            if (!real_fork) return -1;
        }
        int pid = real_fork();
        if (pid == 0 && uwg_bypass_secret != 0) {
            unsigned long sigsys_bit = (unsigned long)1 << (SIGSYS - 1);
            uwg_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                         (long)&sigsys_bit, 0L, 8L);
        }
        return pid;
    }

    /* Non-docker mode: call real vfork. */
    static uwg_fork_fn real_vfork;
    if (__builtin_expect(!real_vfork, 0)) {
        real_vfork = (uwg_fork_fn)dlsym(RTLD_NEXT, "vfork");
        if (!real_vfork) return -1;
    }
    return real_vfork();
}

#endif /* !UWG_FREESTANDING */
