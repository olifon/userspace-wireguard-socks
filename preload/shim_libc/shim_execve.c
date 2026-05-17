/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_execve.c — libc-level exec* intercept for systrap-docker.
 *
 * Active only when UWGS_SYSTRAP_DOCKER=1 (set by uwgwrapper before the
 * initial exec). Intercepts libc exec* symbols so that when a
 * dynamically-linked binary calls exec via libc, we get first look at
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

#include <errno.h>
#include <string.h>
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

/*
 * execv — like execve but uses the calling process's environment.
 * Intercepted because Python's subprocess.Popen with no env= calls
 * execv() in the vfork child (from _posixsubprocess.c::child_exec),
 * bypassing our execve PLT override. Without this shim, the child falls
 * through to glibc's execv which issues execve via inline asm — that
 * hits the layer-1 BPF TRAP, which requires the SIGSYS handler to be
 * reachable. The PLT intercept here avoids the trap entirely by routing
 * directly through uwg_execve_docker_dispatch.
 */
int execv(const char *path, char * const argv[]) {
    extern char **environ;
    return execve(path, argv, environ);
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

/* fexecve(fd, argv, envp) is glibc's wrapper for
 * execveat(fd, "", argv, envp, AT_EMPTY_PATH). glibc issues the syscall
 * directly (not through its own execveat PLT entry), so our execveat symbol
 * override is bypassed. Intercept fexecve here to route via
 * uwg_execveat_docker_dispatch which resolves the fd to a real path and
 * injects the ptloader. Without injection, post-exec pre-constructor BPF
 * traps (e.g. libselinux socket() in its .so ctor) fire with no SIGSYS
 * handler installed and kill the child. */
#ifndef AT_EMPTY_PATH
#  define AT_EMPTY_PATH 0x1000
#endif

int fexecve(int fd, char * const argv[], char * const envp[]) {
    if (uwg_seccomp_docker_flag) {
        long rc = uwg_execveat_docker_dispatch(
            fd, "",
            (const char * const *)argv,
            (const char * const *)envp,
            AT_EMPTY_PATH);
        if (rc < 0) {
            extern int *__errno_location(void);
            *__errno_location() = (int)-rc;
            return -1;
        }
        return 0;
    }
    /* Non-docker: issue execveat inline (not via libc to avoid re-entry). */
    long rc = uwg_syscall5(SYS_execveat, (long)fd, (long)"",
                           (long)argv, (long)envp, (long)AT_EMPTY_PATH);
    if (rc < 0) {
        extern int *__errno_location(void);
        *__errno_location() = (int)-rc;
        return -1;
    }
    return 0;
}

/*
 * execvp / execvpe — PATH-searching exec wrappers.
 *
 * glibc's execvpe() calls __execve() directly (not through the PLT execve
 * symbol), so our execve PLT override is skipped.  Python 3.x vfork children
 * reach execvpe("uname", …) after dup2+close_range, hitting the glibc
 * __execvpe→__execve path without ptloader injection.  Overriding execvp and
 * execvpe here routes each PATH candidate through our execve shim.
 */
#define UWG_PATH_MAX 4096

/* Forward declaration — execve is defined earlier in this TU. */
int execve(const char *path, char * const argv[], char * const envp[]);

static int uwg_execvpe_impl(const char *file, char * const argv[],
                            char * const envp[])
{
    extern int *__errno_location(void);

    if (!file || file[0] == '\0') {
        *__errno_location() = ENOENT;
        return -1;
    }

    /* Absolute or relative path — no search needed. */
    if (strchr(file, '/'))
        return execve(file, argv, envp);

    /* Locate PATH= in envp, then fall back to the current environ. */
    const char *path = NULL;
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            const char *e = envp[i];
            if (e[0]=='P' && e[1]=='A' && e[2]=='T' && e[3]=='H' && e[4]=='=') {
                path = e + 5;
                break;
            }
        }
    }
    if (!path) {
        extern char **environ;
        for (char **e = environ; e && *e; e++) {
            const char *s = *e;
            if (s[0]=='P' && s[1]=='A' && s[2]=='T' && s[3]=='H' && s[4]=='=') {
                path = s + 5;
                break;
            }
        }
    }
    if (!path)
        path = "/usr/local/bin:/usr/bin:/bin";

    size_t flen = strlen(file);
    int got_eacces = 0;

    for (const char *p = path; ; ) {
        const char *colon = strchr(p, ':');
        size_t dlen = colon ? (size_t)(colon - p) : strlen(p);

        if (dlen + 1 + flen < UWG_PATH_MAX) {
            char buf[UWG_PATH_MAX];
            if (dlen == 0) {
                /* Empty PATH component means current directory. */
                memcpy(buf, file, flen + 1);
            } else {
                memcpy(buf, p, dlen);
                buf[dlen] = '/';
                memcpy(buf + dlen + 1, file, flen + 1);
            }
            execve(buf, argv, envp);
            int err = *__errno_location();
            if (err == EACCES)
                got_eacces = 1;
            else if (err != ENOENT && err != ENOTDIR)
                return -1;
        }

        if (!colon)
            break;
        p = colon + 1;
    }

    *__errno_location() = got_eacces ? EACCES : ENOENT;
    return -1;
}

int execvp(const char *file, char * const argv[]) {
    extern char **environ;
    return uwg_execvpe_impl(file, argv, (char * const *)environ);
}

int execvpe(const char *file, char * const argv[], char * const envp[]) {
    return uwg_execvpe_impl(file, argv, envp);
}

#endif /* !UWG_FREESTANDING */
