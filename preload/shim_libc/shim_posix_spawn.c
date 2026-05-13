/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_posix_spawn.c — posix_spawn/posix_spawnp override for docker mode.
 *
 * Problem: glibc's posix_spawn uses
 *   clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND)
 * which resets ALL signal handlers to SIG_DFL in the child, including our
 * SIGSYS handler. The child then calls execve, hits the BPF SECCOMP_RET_TRAP,
 * has no handler to intercept it, and is killed by force_sig_info.
 *
 * Trapping clone3 itself does not help: glibc blocks all signals before
 * calling clone3 (rt_sigprocmask(SIG_BLOCK, ~[])), so when clone3 hits the
 * BPF trap, SIGSYS is blocked. force_sig_info_to_task then resets our handler
 * to SIG_DFL and kills the calling process instead.
 *
 * Fix: intercept posix_spawn at the PLT level. In docker mode, use fork() +
 * execve() instead of glibc's implementation. fork() inherits our SIGSYS
 * handler; execve() goes through shim_execve.c → uwg_execve_docker_dispatch
 * which uses the bypass secret, so the BPF filter allows it without re-trapping.
 *
 * glibc internal struct layouts are stable across Ubuntu 18.04+ (glibc 2.17+),
 * which is our target baseline for the embedded uwgpreload.so.
 */

#ifndef UWG_FREESTANDING

#include <spawn.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdint.h>

#include "dispatch.h"
#include "syscall.h"

extern int uwg_seccomp_docker_flag;

#ifndef RTLD_NEXT
#define RTLD_NEXT  ((void *)-1L)
#endif
#ifndef AT_FDCWD
#define AT_FDCWD   (-100)
#endif

extern void *dlsym(void *, const char *);

/* ------------------------------------------------------------------ */
/* glibc-internal file_actions struct layout (stable glibc >= 2.17)    */
/* ------------------------------------------------------------------ */

enum {
    UWG_SPAWN_DO_CLOSE     = 0,
    UWG_SPAWN_DO_DUP2      = 1,
    UWG_SPAWN_DO_OPEN      = 2,
    UWG_SPAWN_DO_CHDIR     = 3,
    UWG_SPAWN_DO_FCHDIR    = 4,
    UWG_SPAWN_DO_TCSETPGRP = 5,
    UWG_SPAWN_DO_CLOSEFROM = 6,  /* glibc 2.34+ */
};

struct uwg_spawn_action {
    int tag;
    /* 4 bytes compiler padding before the union (pointer member requires
     * 8-byte alignment on LP64; int tag is 4 bytes → 4 bytes of padding) */
    union {
        struct { int fd; }                                       close_a;
        struct { int fd; int newfd; }                            dup2_a;
        struct { int fd; char *path; int oflag; unsigned mode; } open_a;
        struct { char *path; }                                   chdir_a;
        struct { int fd; }                                       fchdir_a;
        struct { int fd; }                                       tcsetpgrp_a;
        struct { int from; }                                     closefrom_a;
    } act;
};

struct uwg_file_actions_hdr {
    int __allocated;
    int __used;
    struct uwg_spawn_action *__actions;
};

/* ------------------------------------------------------------------ */
/* glibc-internal posix_spawnattr_t layout (stable glibc >= 2.17)      */
/* ------------------------------------------------------------------ */

struct uwg_spawnattr_hdr {
    short    __flags;
    short    _pad;    /* explicit padding: short→int alignment */
    int      __pgrp;
    sigset_t __sd;    /* signals to reset to SIG_DFL */
    sigset_t __ss;    /* signal mask to apply */
};

#define UWG_SPAWN_SETPGROUP  0x02
#define UWG_SPAWN_SETSIGDEF  0x04
#define UWG_SPAWN_SETSIGMASK 0x08

/* ------------------------------------------------------------------ */
/* Apply file actions in child (all raw syscalls — avoids BPF traps)   */
/* ------------------------------------------------------------------ */

static void uwg_apply_file_actions(const posix_spawn_file_actions_t *fa) {
    if (!fa) return;
    const struct uwg_file_actions_hdr *h = (const struct uwg_file_actions_hdr *)fa;
    for (int i = 0; i < h->__used; i++) {
        const struct uwg_spawn_action *a = &h->__actions[i];
        switch (a->tag) {
        case UWG_SPAWN_DO_CLOSE:
            /* EBADF on close is silently ignored per POSIX. */
            uwg_syscall1(SYS_close, a->act.close_a.fd);
            break;
        case UWG_SPAWN_DO_DUP2: {
            int s = a->act.dup2_a.fd, d = a->act.dup2_a.newfd;
            if (s != d) {
                uwg_syscall3(SYS_dup3, s, d, 0);
            } else {
                long fl = uwg_syscall3(SYS_fcntl, s, F_GETFD, 0);
                if (fl >= 0 && (fl & FD_CLOEXEC))
                    uwg_syscall3(SYS_fcntl, s, F_SETFD, fl & ~(long)FD_CLOEXEC);
            }
            break;
        }
        case UWG_SPAWN_DO_OPEN: {
            long fd = uwg_syscall4(SYS_openat, AT_FDCWD,
                                   (long)a->act.open_a.path,
                                   a->act.open_a.oflag,
                                   a->act.open_a.mode);
            if (fd >= 0 && (int)fd != a->act.open_a.fd) {
                uwg_syscall3(SYS_dup3, (int)fd, a->act.open_a.fd, 0);
                uwg_syscall1(SYS_close, (int)fd);
            }
            break;
        }
        case UWG_SPAWN_DO_CHDIR:
            if (a->act.chdir_a.path)
                uwg_syscall1(SYS_chdir, (long)a->act.chdir_a.path);
            break;
        case UWG_SPAWN_DO_FCHDIR:
            uwg_syscall1(SYS_fchdir, a->act.fchdir_a.fd);
            break;
        /* UWG_SPAWN_DO_TCSETPGRP, UWG_SPAWN_DO_CLOSEFROM: uncommon;
         * skip for now. */
        default:
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Apply spawn attrs in child                                           */
/* ------------------------------------------------------------------ */

static void uwg_apply_spawnattr(const posix_spawnattr_t *sa) {
    if (!sa) return;
    const struct uwg_spawnattr_hdr *h = (const struct uwg_spawnattr_hdr *)sa;
    short flags = h->__flags;

    if (flags & UWG_SPAWN_SETPGROUP)
        uwg_syscall2(SYS_setpgid, 0, h->__pgrp);

    if (flags & UWG_SPAWN_SETSIGDEF) {
        /* Reset each flagged signal to SIG_DFL via rt_sigaction.
         * rt_sigaction(SIGSYS, ...) is swallowed by our dispatch (the
         * BPF conditional trap intercepts signum==31 and returns 0),
         * so our SIGSYS handler is never accidentally reset. */
        const unsigned long *bits = (const unsigned long *)&h->__sd;
        int nwords = (int)(sizeof(sigset_t) / sizeof(unsigned long));
        for (int w = 0; w < nwords; w++) {
            unsigned long word = bits[w];
            while (word) {
                int bit = __builtin_ctzl(word);
                int signum = w * (int)(8 * sizeof(unsigned long)) + bit + 1;
                struct {
                    void    *handler;
                    unsigned long sa_flags;
                    void    *restorer;
                    unsigned long mask[2];
                } sa_dfl = { (void *)0, 0, 0, {0, 0} };
                uwg_syscall4(SYS_rt_sigaction, signum, (long)&sa_dfl, 0L, 8L);
                word &= word - 1;
            }
        }
    }

    if (flags & UWG_SPAWN_SETSIGMASK) {
        /* sigprocmask() is our shim (shim_sigprocmask.c) which strips
         * SIGSYS from any SIG_BLOCK/SIG_SETMASK, keeping it unblocked
         * for the execve in the child. */
        sigprocmask(SIG_SETMASK, &h->__ss, NULL);
    }
}

/* clone3/clone flag and struct definitions needed for the direct fork. */
#ifndef SIGCHLD
# define SIGCHLD 17
#endif
#ifndef SIG_UNBLOCK
# define SIG_UNBLOCK 1
#endif
#ifndef SYS_clone3
# if defined(__x86_64__) || defined(__aarch64__)
#  define SYS_clone3 435
# endif
#endif

/* ------------------------------------------------------------------ */
/* Core docker-mode spawn implementation                                */
/* ------------------------------------------------------------------ */

static int uwg_do_posix_spawn(pid_t *pid_out, const char *path,
                               const posix_spawn_file_actions_t *fa,
                               const posix_spawnattr_t *sa,
                               char *const argv[], char *const envp[]) {
    /* We must NOT call glibc's fork() here. On glibc 2.38-2.39, fork()
     * uses clone3(CLONE_CLEAR_SIGHAND) which resets ALL signal handlers
     * to SIG_DFL in the child — including our SIGSYS handler. The child
     * then cannot handle any BPF trap (e.g. from uwg_apply_spawnattr
     * calling rt_sigaction(SIGSYS)) and dies before reaching execve.
     *
     * Fix: issue clone3 (or clone) directly via passthrough syscall,
     * without CLONE_CLEAR_SIGHAND. The child inherits our SIGSYS handler
     * intact. We bypass pthread_atfork handlers, which is safe here
     * because the child runs only async-signal-safe operations
     * (uwg_syscall* calls) before execve and never runs Python code. */
    long child;
#ifdef SYS_clone3
    /* CLONE_ARGS_SIZE_VER0 = 8 × sizeof(uint64_t) = 64 bytes.
     * exit_signal = SIGCHLD for wait(2) compatibility.
     * No CLONE_CLEAR_SIGHAND: child inherits our SIGSYS handler. */
    uint64_t ca[8];
    __builtin_memset(ca, 0, sizeof(ca));
    /* ca[0] = flags: 0 (pure fork, no special clone flags) */
    ca[4] = (uint64_t)SIGCHLD; /* exit_signal */
    child = uwg_passthrough_syscall2(SYS_clone3, (long)(uintptr_t)ca,
                                     (long)sizeof(ca));
    if (child == -38L /* -ENOSYS */)
#endif
    /* Fallback: SYS_clone with SIGCHLD and no stack/flags. */
    child = uwg_passthrough_syscall5(SYS_clone, (long)SIGCHLD, 0L, 0L, 0L, 0L);

    if (child < 0) return (int)(-(int)child);

    if (child == 0) {
        /* Child: SIGSYS handler inherited, no CLONE_CLEAR_SIGHAND.
         * Unblock SIGSYS defensively — the parent's mask is inherited;
         * if the parent had SIGSYS blocked for any reason, unblock it
         * so BPF traps route to our handler rather than SIG_DFL. */
        unsigned long sigsys_bit = (unsigned long)1 << (SIGSYS - 1);
        uwg_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                     (long)&sigsys_bit, 0L, 8L);

        uwg_apply_spawnattr(sa);
        uwg_apply_file_actions(fa);
        /* execve() → shim_execve.c::execve() → uwg_execve_docker_dispatch()
         * → bypass exec (BPF filter sees bypass secret in arg6 → ALLOW). */
        execve(path, argv, envp);
        uwg_syscall1(SYS_exit_group, 127);
        __builtin_unreachable();
    }
    if (pid_out) *pid_out = (pid_t)child;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public overrides                                                     */
/* ------------------------------------------------------------------ */

typedef int (*posix_spawn_fn)(pid_t *, const char *,
                               const posix_spawn_file_actions_t *,
                               const posix_spawnattr_t *,
                               char *const [], char *const []);

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *sa,
                char *const argv[], char *const envp[]) {
    if (uwg_seccomp_docker_flag)
        return uwg_do_posix_spawn(pid, path, fa, sa, argv, envp);

    static posix_spawn_fn real_fn;
    if (!real_fn)
        real_fn = (posix_spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    if (!real_fn) return ENOSYS;
    return real_fn(pid, path, fa, sa, argv, envp);
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *sa,
                 char *const argv[], char *const envp[]) {
    if (uwg_seccomp_docker_flag)
        return uwg_do_posix_spawn(pid, file, fa, sa, argv, envp);

    static posix_spawn_fn real_fn;
    if (!real_fn)
        real_fn = (posix_spawn_fn)dlsym(RTLD_NEXT, "posix_spawnp");
    if (!real_fn) return ENOSYS;
    return real_fn(pid, file, fa, sa, argv, envp);
}

#endif /* !UWG_FREESTANDING */
