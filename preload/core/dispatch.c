/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Phase 1 dispatch: stubs for every uwg_* handler. Each returns
 * -ENOSYS so the SIGSYS handler exercise loop can confirm the path
 * "kernel SIGSYS → handler → uwg_dispatch → uwg_<syscall> → -ENOSYS
 * → handler writes result → kernel sigreturn → tracee sees -ENOSYS"
 * works end-to-end before any real per-syscall logic lands.
 *
 * Phase 1's later commits replace each stub with the real
 * implementation (extracted from the existing uwgpreload.c). Until
 * then, a process that installs the filter will see network syscalls
 * fail with ENOSYS — that's expected, and tests use
 * uwg_sigsys_stats() to confirm the handler is being reached at all.
 *
 * Async-signal-safe: every function here is callable from inside
 * the SIGSYS handler. Stubs trivially are; concrete impls must
 * preserve this property.
 */

#include <sys/syscall.h>

#include "dispatch.h"
#include "syscall.h"

/* clone3 and CLONE_CLEAR_SIGHAND were added in Linux 5.3/5.5. Guard for
 * older build toolchains and freestanding builds. */
#ifndef SYS_clone3
# if defined(__x86_64__) || defined(__aarch64__)
#  define SYS_clone3 435
# endif
#endif
#ifndef CLONE_CLEAR_SIGHAND
# define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

#define ENOSYS_RET (-38L)

/* The big switch. Kept dense so the compiler can lay it out as a
 * jump table on architectures that support it. Syscall NRs are
 * intentionally listed in numeric order within each group. */
long uwg_dispatch(long nr, long a1, long a2, long a3,
                  long a4, long a5, long a6) {
    switch (nr) {
    /* --- control plane --- */
    case SYS_socket:      return uwg_socket((int)a1, (int)a2, (int)a3);
    case SYS_socketpair:  return uwg_socketpair((int)a1, (int)a2, (int)a3, (int *)a4);
    case SYS_close:       return uwg_close((int)a1);
    case SYS_connect:     return uwg_connect((int)a1, (const struct sockaddr *)a2, (uint32_t)a3);
    case SYS_bind:        return uwg_bind((int)a1, (const struct sockaddr *)a2, (uint32_t)a3);
    case SYS_listen:      return uwg_listen((int)a1, (int)a2);
    case SYS_accept:      return uwg_accept((int)a1, (struct sockaddr *)a2, (uint32_t *)a3);
    case SYS_accept4:     return uwg_accept4((int)a1, (struct sockaddr *)a2, (uint32_t *)a3, (int)a4);
    case SYS_setsockopt:  return uwg_setsockopt((int)a1, (int)a2, (int)a3, (const void *)a4, (uint32_t)a5);
    case SYS_getsockopt:  return uwg_getsockopt((int)a1, (int)a2, (int)a3, (void *)a4, (uint32_t *)a5);
    case SYS_getsockname: return uwg_getsockname((int)a1, (struct sockaddr *)a2, (uint32_t *)a3);
    case SYS_getpeername: return uwg_getpeername((int)a1, (struct sockaddr *)a2, (uint32_t *)a3);
    case SYS_dup:         return uwg_dup((int)a1);
#ifdef SYS_dup2
    case SYS_dup2:        return uwg_dup2((int)a1, (int)a2);
#endif
    case SYS_dup3:        return uwg_dup3((int)a1, (int)a2, (int)a3);
    case SYS_fcntl:       return uwg_fcntl((int)a1, (int)a2, (long)a3);
    case SYS_shutdown:    return uwg_shutdown((int)a1, (int)a2);

    /* --- message-style --- */
    case SYS_recvfrom:    return uwg_recvfrom((int)a1, (void *)a2, (size_t)a3, (int)a4, (struct sockaddr *)a5, (uint32_t *)a6);
    case SYS_recvmsg:     return uwg_recvmsg((int)a1, (struct msghdr *)a2, (int)a3);
    case SYS_recvmmsg:    return uwg_recvmmsg((int)a1, (struct mmsghdr *)a2, (unsigned int)a3, (int)a4, (struct timespec *)a5);
    case SYS_sendto:      return uwg_sendto((int)a1, (const void *)a2, (size_t)a3, (int)a4, (const struct sockaddr *)a5, (uint32_t)a6);
    case SYS_sendmsg:     return uwg_sendmsg((int)a1, (const struct msghdr *)a2, (int)a3);
    case SYS_sendmmsg:    return uwg_sendmmsg((int)a1, (struct mmsghdr *)a2, (unsigned int)a3, (int)a4);

    /* --- stream-style --- */
    case SYS_read:        return uwg_read((int)a1, (void *)a2, (size_t)a3);
    case SYS_write:       return uwg_write((int)a1, (const void *)a2, (size_t)a3);
    case SYS_readv:       return uwg_readv((int)a1, (const struct iovec *)a2, (int)a3);
    case SYS_writev:      return uwg_writev((int)a1, (const struct iovec *)a2, (int)a3);
    case SYS_pread64:     return uwg_pread((int)a1, (void *)a2, (size_t)a3, (int64_t)a4);
    case SYS_pwrite64:    return uwg_pwrite((int)a1, (const void *)a2, (size_t)a3, (int64_t)a4);

    /* --- execve interception (systrap-docker mode) --- */
#ifdef SYS_execve
    case SYS_execve:
        if (uwg_seccomp_docker_flag) {
            return uwg_execve_docker_dispatch((const char *)a1,
                                              (const char * const *)a2,
                                              (const char * const *)a3);
        }
        return uwg_passthrough_syscall3(SYS_execve, a1, a2, a3);
#endif
#ifdef SYS_execveat
    case SYS_execveat:
        if (uwg_seccomp_docker_flag) {
            return uwg_execveat_docker_dispatch((int)a1, (const char *)a2,
                                                (const char * const *)a3,
                                                (const char * const *)a4,
                                                (int)a5);
        }
        return uwg_passthrough_syscall5(SYS_execveat, a1, a2, a3, a4, a5);
#endif
    /* --- clone3 CLONE_CLEAR_SIGHAND interception (docker mode) --- */
#ifdef SYS_clone3
    case SYS_clone3: {
        /* Reached only via the syscall(2) PLT shim (shim_syscall.c) for
         * dynamic binaries — clone3 is NOT in the docker-mode BPF trap
         * list because glibc's fork() calls rt_sigprocmask(SIG_BLOCK,~all)
         * before clone3, and rt_sigprocmask cannot safely be trapped in the
         * main filter (ld.so calls it before our handler is installed).
         *
         * For static binaries (ptloader path), the ptloader installs its
         * own BPF layer after the SIGSYS handler is in place, allowing
         * rt_sigprocmask and clone3 to be trapped in that layer.
         *
         * a1 = struct clone_args *, a2 = size_t (must be ≥ sizeof flags).
         * We modify flags in-place before the passthrough. */
        int had_clear_sighand = 0;
        if (a1 != 0 && a2 >= (long)sizeof(uint64_t)) {
            uint64_t *flags = (uint64_t *)a1;
            if (*flags & CLONE_CLEAR_SIGHAND) {
                *flags &= ~(uint64_t)CLONE_CLEAR_SIGHAND;
                had_clear_sighand = 1;
            }
        }
        long r = uwg_passthrough_syscall2(SYS_clone3, a1, a2);
        /* Child path: clear all handlers except SIGSYS to emulate
         * CLONE_CLEAR_SIGHAND semantics while preserving interception. */
        if (r == 0 && had_clear_sighand && uwg_seccomp_docker_flag) {
            /* 32-byte zero block = SIG_DFL, sa_flags=0, no restorer, empty mask. */
            long dfl[4] = {0, 0, 0, 0};
            for (int sig = 1; sig <= 64; sig++) {
                if (sig == 31) continue; /* preserve SIGSYS */
                uwg_passthrough_syscall4(SYS_rt_sigaction, sig, (long)dfl, 0, 8);
            }
        }
        return r;
    }
#endif

    /* --- handler-protection --- */
    case SYS_rt_sigaction:
        /* BPF now uses SECCOMP_RET_ERRNO|0 for rt_sigaction(SIGSYS=31),
         * so this case is only reached if the filter somehow lets it
         * through (shouldn't happen in practice). Return 0 to be safe. */
        if ((int)a1 == 31) {
            return 0;
        }
        return uwg_passthrough_syscall4(SYS_rt_sigaction, a1, a2, a3, a4);

    case SYS_rt_sigprocmask: {
        /* Strip SIGSYS from SIG_BLOCK / SIG_SETMASK operations so no
         * code path — whether PLT syscall() shim, Chrome's own signal
         * management, or glibc internals — can accidentally block the
         * signal our seccomp trap handler relies on.
         *
         * On 64-bit Linux the kernel sigset is exactly one unsigned
         * long (8 bytes, 64 signals). SIGSYS=31 is bit 30 of word 0. */
        int how = (int)a1;
        const unsigned long *set = (const unsigned long *)a2;
        long ssz = a4;
        if (set != NULL && ssz > 0 &&
                (how == 0 /* SIG_BLOCK */ || how == 2 /* SIG_SETMASK */)) {
            unsigned long fset = set[0] & ~((unsigned long)1 << (31 - 1));
            return uwg_passthrough_syscall4(SYS_rt_sigprocmask,
                                            (long)how, (long)&fset,
                                            a3, ssz);
        }
        return uwg_passthrough_syscall4(SYS_rt_sigprocmask, a1, a2, a3, a4);
    }

    default:
        /* Unknown syscall — pass through to the kernel with the
         * bypass-secret in arg6 so the seccomp filter ALLOWs it. The
         * SIGSYS handler reaches this branch when:
         *   1. Filter and dispatch table are out of sync (programmer
         *      error — adding a syscall to the trap list without
         *      adding a case here). Passthrough means the kernel does
         *      its normal job; symptom is just lost interception, not
         *      a fail-closed crash. We accept this trade-off because:
         *   2. Library code that calls libc's syscall(2) wrapper
         *      (vs. the per-syscall libc symbols like bind(2)) routes
         *      its raw syscall through this dispatcher — see
         *      preload/shim_libc/shim_syscall.c. The shim's call to
         *      uwg_dispatch lands here for any syscall nr we don't
         *      explicitly intercept, and the right answer is "let the
         *      kernel handle it." */
        return uwg_passthrough_syscall6(nr, a1, a2, a3, a4, a5, a6);
    }
}

/* All uwg_* dispatchers are implemented across the per-op .c files:
 *   socket_ops.c   — socket, socketpair, close
 *   connect_ops.c  — connect
 *   bind_ops.c     — bind (real); listen / accept / accept4
 *                    (passthrough for non-tunnel; -ENOSYS for tunnel
 *                    until the listener migration commit)
 *   stream_ops.c   — read, write, readv, writev, pread64, pwrite64
 *   msg_ops.c      — recvfrom, sendto, recvmsg, sendmsg, recvmmsg,
 *                    sendmmsg (all with MSG_DONTWAIT propagation;
 *                    UDP-non-stream cases -ENOSYS until framing
 *                    helpers land)
 *   fd_ops.c       — dup, dup2, dup3, fcntl, setsockopt, getsockopt,
 *                    getsockname, getpeername, shutdown
 */
