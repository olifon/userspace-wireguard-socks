/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * libc syscall(2) interposition.
 *
 * Some libraries (notably Go's standard library, parts of glibc's
 * pthread layer, and a few shim libs that want to issue syscalls
 * portably) call the variadic libc syscall(2) wrapper instead of the
 * per-syscall libc symbols (bind/connect/recvmsg/etc.). The libc
 * wrappers for those individual symbols inline the syscall instruction
 * via inline asm — they don't route through syscall(2) — so when libc
 * calls bind() it bypasses syscall(2) and hits our shim_socket.c::bind
 * shim directly. But callers that go through syscall(SYS_bind, ...)
 * skip our per-symbol shims and would hit the kernel directly,
 * losing tunnel interception unless our seccomp filter also catches
 * them via the SIGSYS path.
 *
 * This shim closes that gap at the libc symbol level: any caller
 * that resolves the `syscall` name through dynamic linking gets us
 * instead of glibc's wrapper. We forward to uwg_dispatch which
 * either handles the syscall via its per-op case or passes it through
 * to the kernel for unknown nrs (the default branch in dispatch.c).
 *
 * Variadic semantics: the libc prototype is `long syscall(long nr,
 * ...);`. POSIX/Linux uses up to 6 args. We read va_args defensively
 * — extra args (callers that pass fewer) hit garbage va_arg reads;
 * those caller-side args are ignored by uwg_dispatch when the syscall
 * doesn't need them. Same convention glibc's syscall.S follows.
 */

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>

#include "../core/dispatch.h"

long syscall(long nr, ...) {
    va_list ap;
    va_start(ap, nr);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    long rc = uwg_dispatch(nr, a1, a2, a3, a4, a5, a6);
    /* uwg_dispatch follows the freestanding convention: rc < 0 is
     * a -errno, rc >= 0 is the value. libc's syscall(2) wrapper has
     * the same convention as the per-symbol wrappers it would have
     * called: rc on success, -1 + errno on error. */
    if (rc < 0) {
        errno = (int)(-rc);
        return -1;
    }
    return rc;
}
