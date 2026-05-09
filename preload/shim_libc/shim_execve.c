/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_execve.c — libc-level execve/execveat intercept for systrap-docker.
 *
 * Active only when UWGS_SYSTRAP_DOCKER=1 (set by uwgwrapper before the
 * initial exec). Intercepts the libc execve/execveat symbols so that when
 * a dynamically-linked binary calls execve via libc, we get first look at
 * the target binary and can inject the ptloader if it's a static binary.
 *
 * For static binaries, the SIGSYS path in dispatch.c handles the same
 * interception — this shim is the fast-path for the libc-routed case to
 * avoid the kernel-trap round-trip.
 *
 * The actual patching logic lives in execve_docker.c; this file is only
 * the symbol interposition layer.
 */

#ifndef UWG_FREESTANDING  /* libc shim is only for the .so build */

#include <sys/syscall.h>

#include "dispatch.h"
#include "../core/syscall.h"

/* uwg_seccomp_docker_flag: 1 when UWGS_SYSTRAP_DOCKER=1. */
extern int uwg_seccomp_docker_flag;

int execve(const char *path, char * const argv[], char * const envp[]) {
    if (uwg_seccomp_docker_flag) {
        long rc = uwg_execve_docker_dispatch(
            path,
            (const char * const *)argv,
            (const char * const *)envp);
        /* If dispatch returned (exec failed or binary was passthrough'd
         * via syscall and it returned an error), propagate the error. */
        if (rc < 0) {
            /* Set libc errno and return -1. We can use the libc errno
             * here because we're in the shim (not a signal handler). */
            extern int *__errno_location(void);
            *__errno_location() = (int)-rc;
            return -1;
        }
        return 0;
    }
    /* Passthrough: call the raw syscall directly. We must NOT go
     * through our shim_syscall.c::syscall() override here — that
     * routes to uwg_dispatch, which would call uwg_passthrough_syscall3
     * (bypass-secret in arg6), causing the supervisor's seccomp
     * PTRACE_EVENT_SECCOMP interception to be skipped entirely.
     * uwg_syscall3 uses inline asm with no bypass secret, so the kernel
     * seccomp filter sees a normal execve and RET_TRACE / RET_ALLOW
     * fires as expected. */
    long rc = uwg_syscall3(SYS_execve, (long)path, (long)argv, (long)envp);
    if (rc < 0) {
        extern int *__errno_location(void);
        *__errno_location() = (int)-rc;
        return -1;
    }
    return 0;
}

int execveat(int dirfd, const char *path, char * const argv[],
             char * const envp[], int flags) {
    if (uwg_seccomp_docker_flag) {
        long rc = uwg_execveat_docker_dispatch(
            dirfd, path,
            (const char * const *)argv,
            (const char * const *)envp,
            flags);
        if (rc < 0) {
            extern int *__errno_location(void);
            *__errno_location() = (int)-rc;
            return -1;
        }
        return 0;
    }
    /* Same bypass-secret concern as execve above: use inline-asm syscall,
     * not syscall() (which routes through shim_syscall → uwg_dispatch →
     * uwg_passthrough_syscall, adding the bypass secret). */
    long rc = uwg_syscall5(SYS_execveat, (long)dirfd, (long)path,
                           (long)argv, (long)envp, (long)flags);
    if (rc < 0) {
        extern int *__errno_location(void);
        *__errno_location() = (int)-rc;
        return -1;
    }
    return 0;
}

#endif /* !UWG_FREESTANDING */
