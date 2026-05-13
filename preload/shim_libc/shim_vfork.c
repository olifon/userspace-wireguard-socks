/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_vfork.c — implement vfork() correctly in docker mode.
 *
 * Problem: glibc 2.38–2.39 implements vfork() as:
 *   1. rt_sigprocmask(SIG_BLOCK, ~[SIGKILL,SIGSTOP]) via direct syscall
 *   2. clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND) via direct syscall
 *
 * Step 1 blocks SIGSYS before step 2 fires. When step 2's clone3 hits
 * the docker-mode BPF SECCOMP_RET_TRAP, the kernel calls
 * force_sig_info(SIGSYS). force_sig_info_to_task sees SIGSYS blocked,
 * resets the disposition to SIG_DFL, and delivers SIGSYS with default
 * action (terminate + core), killing the process before our SIGSYS
 * handler ever runs.
 *
 * Fix: intercept vfork() at PLT level. In docker mode, bypass glibc's
 * vfork() entirely and issue clone3(CLONE_VFORK) directly via
 * uwg_passthrough_syscall2. The bypass secret in arg6 makes the BPF
 * filter ALLOW the clone3 without generating a SECCOMP_RET_TRAP, so
 * rt_sigprocmask is never called and SIGSYS is never blocked.
 *
 * CLONE_VM is intentionally omitted: with CLONE_VM the child shares the
 * parent's stack pages, and any function calls the child makes after
 * vfork() returns overwrite the parent's SSP canary — "stack smashing
 * detected" when the parent resumes. Without CLONE_VM the child gets a
 * COW stack that is safe to use freely.
 *
 * CLONE_VFORK blocking semantics are preserved: the parent blocks until
 * the child calls execve(2) or _exit(2), exactly as the vfork(2) ABI
 * requires.
 *
 * For static-libc callers (no PLT interception), the seccomp filter's
 * docker-mode rt_sigprocmask(SIG_BLOCK/SIG_SETMASK) conditional trap
 * handles step 1 before it can block SIGSYS.
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
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef CLONE_VM
#define CLONE_VM    0x00000100ULL
#endif
#ifndef CLONE_VFORK
#define CLONE_VFORK 0x00004000ULL
#endif
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *)-1L)
#endif

extern void *dlsym(void *, const char *);

typedef int (*uwg_fork_fn)(void);

int vfork(void) {
    if (uwg_seccomp_docker_flag) {
#ifdef SYS_clone3
        /* CLONE_ARGS_SIZE_VER0 = 8 × sizeof(uint64_t) = 64 bytes.
         * Fields: flags, pidfd, child_tid, parent_tid, exit_signal,
         * stack, stack_size, tls. Set flags=CLONE_VFORK (NOT CLONE_VM)
         * and exit_signal=SIGCHLD.
         *
         * CLONE_VM is intentionally omitted. With CLONE_VM the child
         * shares the parent's address space AND stack pages. When the
         * child returns from vfork() and the caller pushes new frames,
         * those writes land on the shared stack, overwriting the
         * parent's SSP canary. The parent then sees "stack smashing
         * detected" on resume. Without CLONE_VM the child gets a COW
         * copy; the caller can freely use the stack. CLONE_VFORK still
         * guarantees the parent blocks until the child calls execve or
         * _exit — the blocking semantics are preserved.
         *
         * uwg_passthrough_syscall2 places bypass_secret in arg6 so the
         * BPF filter's prologue ALLOWs this clone3 directly — no
         * SECCOMP_RET_TRAP, no SIGSYS, no glibc rt_sigprocmask(SIG_BLOCK)
         * side-effect. */
        uint64_t ca[8];
        __builtin_memset(ca, 0, sizeof(ca));
        ca[0] = (uint64_t)CLONE_VFORK;
        ca[4] = (uint64_t)SIGCHLD;
        long r = uwg_passthrough_syscall2(SYS_clone3,
                                          (long)(uintptr_t)ca,
                                          (long)sizeof(ca));
        if (r != -38 /* -ENOSYS */) {
            /* Child: unblock SIGSYS defensively (parent's mask should
             * already have it unblocked, but be explicit). SIG_UNBLOCK
             * is not trapped by the BPF filter so this is a direct
             * kernel call. */
            if (r == 0) {
                unsigned long sigsys_bit = (unsigned long)1 << (SIGSYS - 1);
                uwg_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                             (long)(uintptr_t)&sigsys_bit, 0L, 8L);
            }
            return (int)r;
        }
        /* Fall through to real vfork on kernels without clone3. */
#endif /* SYS_clone3 */
    }

    /* Non-docker mode or pre-clone3 kernel: call real vfork. */
    static uwg_fork_fn real_vfork;
    if (__builtin_expect(!real_vfork, 0)) {
        real_vfork = (uwg_fork_fn)dlsym(RTLD_NEXT, "vfork");
        if (!real_vfork) return -1;
    }
    return real_vfork();
}

#endif /* !UWG_FREESTANDING */
