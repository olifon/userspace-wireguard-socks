/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * shim_vfork.c — redirect vfork() to fork() in docker mode.
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
 * A naive fix (bypass clone3 with CLONE_VM via passthrough_syscall) still
 * fails: CLONE_VM gives the child the parent's virtual address space and
 * TLS base (fs.base) but a different kernel TID. glibc's _dl_runtime_resolve
 * calls pthread_mutex_lock which reads pthread_self() from TLS — that
 * returns the parent's TID, not the child's — so glibc's recursive-mutex
 * detection misfires, corrupting the lock state and causing SIGSEGV in
 * the child's PLT resolution path.
 *
 * Fix: in docker mode redirect vfork() to glibc's real fork(). fork()
 * uses CLONE_SETTLS so the child gets its own TLS with the correct TID.
 * The atfork handlers clean up glibc's internal locks. Our
 * uwg_sigsys_atfork_child (registered in init.c) reinstalls the SIGSYS
 * handler in the child, so SIGSYS interception is maintained. PLT
 * lazy-binding, _dl_runtime_resolve, and execv/execve all work correctly.
 *
 * After real_fork() returns in the child, we explicitly unblock SIGSYS via
 * passthrough syscall (bypass secret in arg6 bypasses the layer-2 filter)
 * and reinstall the SIGSYS handler. This mirrors what shim_fork.c does in
 * its PLT shim child path. It is needed because:
 *   - clone3_asm.S child path unblocks SIGSYS before jumping to trap_rip,
 *     but glibc's post-fork signal-mask restore (via rt_sigprocmask →
 *     layer-2 SIGSYS trap → sigsys.c uc_sigmask-only handling) may leave
 *     SIGSYS blocked in uc_sigmask after the SIGSYS auto-mask on handler
 *     entry. The passthrough unblock here clears task->blocked directly,
 *     guaranteeing SIGSYS is unblocked when Python's child_exec later calls
 *     rt_sigprocmask(SIG_SETMASK, {}) which fires the layer-2 trap.
 *
 * Callers (Python's subprocess.Popen, posix_spawn, etc.) issue vfork+exec.
 * The performance regression from fork() vs vfork() is negligible: we are
 * already in docker mode, running a sandboxed process with a ptloader
 * injection round-trip per exec. The COW overhead of fork() is dwarfed by
 * that cost.
 *
 * For static-libc callers (no PLT interception), the uwgptloader
 * injected via systrap-elf installs its own SIGSYS handler before the
 * binary's init runs, so the rt_sigprocmask(SIG_BLOCK) in static vfork
 * implementations is handled by that handler context.
 *
 * This shim does NOT override vfork2() or __vfork(); those symbols
 * are internal glibc names not used by application code.
 */

#ifndef UWG_FREESTANDING

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *)-1L)
#endif

#include <signal.h>
#include <sys/syscall.h>
#include "dispatch.h"
#include "syscall.h"

extern void *dlsym(void *, const char *);
extern int uwg_seccomp_docker_flag;

typedef int (*uwg_fork_fn)(void);

int vfork(void) {
    if (uwg_seccomp_docker_flag) {
        /* Redirect to fork(): child gets its own TLS and clean lock state
         * via atfork handlers; our uwg_sigsys_atfork_child reinstalls the
         * SIGSYS handler before the mask is restored. */
        static uwg_fork_fn real_fork;
        if (__builtin_expect(!real_fork, 0)) {
            real_fork = (uwg_fork_fn)dlsym(RTLD_NEXT, "fork");
            if (!real_fork) return -1;
        }
        int _pid = real_fork();
        if (_pid == 0) {
            if (uwg_bypass_secret != 0) {
                unsigned long sigsys_bit = (unsigned long)1 << (SIGSYS - 1);
                uwg_passthrough_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                                         (long)&sigsys_bit, 0L, 8L);
                (void)uwg_install_sigsys_handler();
            }
        }
        /* Zero r9 before returning so bypass_secret never leaks to the
         * caller. uwg_passthrough_syscall4 puts bypass_secret in r9; the
         * kernel syscall ABI preserves r9, so it remains set until we
         * explicitly clear it. The compiler does not zero caller-saved regs
         * on return. If r9=bypass_secret when glibc's __execve fires the
         * syscall instruction, the layer-1 BPF bypass check allows the exec
         * without ptloader injection, so libselinux's constructor calls
         * socket() before our handler is installed, hitting SIGSYS with
         * SIG_DFL and killing the child. */
#if defined(__x86_64__)
        __asm__ __volatile__("xor %%r9, %%r9" ::: "r9");
#elif defined(__aarch64__)
        __asm__ __volatile__("mov x5, #0" ::: "x5");
#endif
        return _pid;
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
