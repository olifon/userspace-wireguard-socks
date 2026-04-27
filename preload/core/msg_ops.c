/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Message-style I/O dispatchers: recvfrom / sendto / recvmsg / sendmsg /
 * recvmmsg / sendmmsg.
 *
 * For tunnel TCP-stream fds (the chromium hot path), these collapse
 * to a kernel passthrough — fdproxy treats the manager-side socket
 * as a raw byte stream so any libc message-style call works directly.
 *
 * For UDP-connected and UDP-listener fds, these are the protocol-
 * level operations that DO require wrapper-side translation:
 *   - sendmsg/sendto: serialize destination + payload into the
 *     fdproxy datagram protocol (4-byte length prefix + payload for
 *     connected; sockaddr-tagged frame for unconnected listener).
 *   - recvmsg/recvfrom: read a length-prefixed frame from fdproxy
 *     and unpack into msg/buf.
 *
 * MSG_DONTWAIT propagation is load-bearing here. The legacy ptrace
 * path's recvmsg failed to propagate this flag, causing chromium /
 * libuv / Go-netpoller apps to deadlock. v0.1.0-beta.46 fixed it on
 * the ptrace side; this layer re-applies the same logic at the
 * SIGSYS layer.
 *
 * Phase 1 status:
 *   - TCP-stream fast path: all six syscalls passthrough cleanly.
 *   - UDP-connected / UDP-listener data plane: -ENOSYS for now —
 *     full lift from legacy uwgpreload.c is the next migration
 *     commit. The framing helpers are non-trivial (4-byte length
 *     prefix, sockaddr-tagged datagrams for listener case).
 *   - DGRAM-on-loopback: passthrough (kernel handles).
 */

#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

#define UWG_MSG_DONTWAIT 0x40 /* matches kernel ABI */

/*
 * Helper: when the fd has O_NONBLOCK set on the tracee side, OR
 * MSG_DONTWAIT into the syscall flags so the kernel-side recv on
 * the manager socket also returns EAGAIN. Without this, the manager
 * socket (always blocking) would block our handler thread waiting
 * for data the tracee already gave up on. This is the v0.1.0-beta.46
 * recvmsg-MSG_DONTWAIT-propagation fix, re-applied here for the
 * SIGSYS path.
 */
static int effective_recv_flags(const struct tracked_fd *state, int caller_flags) {
    if (state->saved_fl & 04000 /* O_NONBLOCK */) {
        return caller_flags | UWG_MSG_DONTWAIT;
    }
    return caller_flags;
}

/*
 * recvfrom and sendto are 6-arg syscalls; we can't put the bypass-
 * secret in arg6 because all 6 are user data. Solution from legacy
 * uwgpreload.c: convert to recvmsg/sendmsg (3 args, leaves arg6 free).
 *
 * The conversion is exact for the common case. Edge cases that don't
 * map cleanly (recvfrom with MSG_CMSG_CLOEXEC; sendto with NULL
 * dest_addr but nonzero addrlen) fall back to the raw 6-arg syscall
 * path — which DOES go through SIGSYS again. We avoid recursion by
 * having the SIGSYS handler check: if the dispatch path falls back
 * to a raw 6-arg call, the kernel's seccomp filter would re-trap;
 * we accept that double-trip cost on these edge cases (very rare
 * in practice) for the simpler design.
 *
 * For Phase 1 we don't yet implement the fallback — we just punt
 * to -ENOSYS for the edge cases and rely on apps using clean shapes.
 */

#define UWG_MSG_CMSG_CLOEXEC 0x40000000

long uwg_recvfrom(int fd, void *buf, size_t len, int flags,
                  struct sockaddr *src, uint32_t *slen) {
    struct tracked_fd state = uwg_state_lookup(fd);
    int eff_flags = (state.proxied && state.kind == KIND_TCP_STREAM)
                        ? effective_recv_flags(&state, flags)
                        : flags;

    /* MSG_CMSG_CLOEXEC and src-without-slen are awkward — punt for
     * Phase 1. */
    if (flags & UWG_MSG_CMSG_CLOEXEC) return -38L;
    if (src && !slen) return -22; /* -EINVAL */

    /* Build msghdr and use recvmsg (3-arg). */
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg;
    msg.msg_name = src;
    msg.msg_namelen = src ? (slen ? *slen : 0) : 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    /* Tunnel non-TCP-stream still needs the protocol-level translation
     * we haven't implemented yet. */
    if (state.proxied && state.kind != KIND_TCP_STREAM) return -38L;

    long rc = uwg_passthrough_syscall3(SYS_recvmsg, fd, (long)&msg, eff_flags);
    if (rc >= 0 && src && slen) *slen = msg.msg_namelen;
    return rc;
}

long uwg_sendto(int fd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest, uint32_t dlen) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && state.kind != KIND_TCP_STREAM) return -38L;

    /* dest=NULL with nonzero dlen is the awkward case — punt. */
    if (dest == NULL && dlen != 0) return -22;

    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    struct msghdr msg;
    msg.msg_name = (void *)dest;
    msg.msg_namelen = dest ? dlen : 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    return uwg_passthrough_syscall3(SYS_sendmsg, fd, (long)&msg, flags);
}

long uwg_recvmsg(int fd, struct msghdr *msg, int flags) {
    struct tracked_fd state = uwg_state_lookup(fd);

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        int eff_flags = effective_recv_flags(&state, flags);
        return uwg_passthrough_syscall3(SYS_recvmsg, fd, (long)msg, eff_flags);
    }
    if (state.proxied) {
        return -38L;
    }
    return uwg_passthrough_syscall3(SYS_recvmsg, fd, (long)msg, flags);
}

long uwg_sendmsg(int fd, const struct msghdr *msg, int flags) {
    struct tracked_fd state = uwg_state_lookup(fd);

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        return uwg_passthrough_syscall3(SYS_sendmsg, fd, (long)msg, flags);
    }
    if (state.proxied) {
        return -38L;
    }
    return uwg_passthrough_syscall3(SYS_sendmsg, fd, (long)msg, flags);
}

long uwg_recvmmsg(int fd, struct mmsghdr *vec, unsigned int vlen,
                  int flags, struct timespec *to) {
    struct tracked_fd state = uwg_state_lookup(fd);

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        int eff_flags = effective_recv_flags(&state, flags);
        return uwg_passthrough_syscall5(SYS_recvmmsg, fd, (long)vec,
                                        (long)vlen, eff_flags, (long)to);
    }
    if (state.proxied) {
        return -38L;
    }
    return uwg_passthrough_syscall5(SYS_recvmmsg, fd, (long)vec,
                                    (long)vlen, flags, (long)to);
}

long uwg_sendmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, int flags) {
    struct tracked_fd state = uwg_state_lookup(fd);

    if (state.proxied && state.kind == KIND_TCP_STREAM) {
        return uwg_passthrough_syscall4(SYS_sendmmsg, fd, (long)vec,
                                        (long)vlen, flags);
    }
    if (state.proxied) {
        return -38L;
    }
    return uwg_passthrough_syscall4(SYS_sendmmsg, fd, (long)vec,
                                    (long)vlen, flags);
}
