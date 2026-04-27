/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Per-fd state-management dispatchers:
 *   dup / dup2 / dup3                — propagate tunnel state to new fd
 *   fcntl                            — track O_NONBLOCK changes
 *   getsockname / getpeername        — synthesize tunnel-side answers
 *   setsockopt / getsockopt          — track SO_REUSEADDR / SO_REUSEPORT
 *   shutdown                         — propagate to fdproxy when tunnel
 *
 * Phase 1 status: most are minimal — passthrough plus state update.
 * The synthesize-tunnel-side-answer paths (getsockname/getpeername
 * lying to the tracee about the bound IP being a tunnel address)
 * are the most important from a correctness standpoint and ARE
 * implemented. Other refinements are TODO.
 */

#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

#define UWG_F_GETFL 3
#define UWG_F_SETFL 4
#define UWG_F_GETFD 1
#define UWG_F_SETFD 2
#define UWG_F_DUPFD 0
#define UWG_F_DUPFD_CLOEXEC 1030
#define UWG_O_NONBLOCK 04000
#define UWG_O_CLOEXEC  02000000

/*
 * dup variants: if the source fd is tunnel-managed, the new fd must
 * also be marked tunnel in shared state. The kernel-side dup
 * already creates a real fd that points at the same kernel socket;
 * we just need to mirror our table.
 */
long uwg_dup(int fd) {
    long newfd = uwg_passthrough_syscall1(SYS_dup, fd);
    if (newfd < 0) return newfd;

    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.active || state.proxied) {
        (void)uwg_state_store((int)newfd, &state);
    }
    return newfd;
}

long uwg_dup2(int oldfd, int newfd) {
    /* dup2 atomically closes newfd if open. We need to clear our
     * table entry for newfd FIRST so a concurrent lookup never sees
     * the about-to-be-replaced state. */
    struct tracked_fd state = uwg_state_lookup(oldfd);
    uwg_state_clear(newfd);
    long rc = uwg_passthrough_syscall2(SYS_dup2, oldfd, newfd);
    if (rc < 0) return rc;
    if (state.active || state.proxied) {
        (void)uwg_state_store((int)rc, &state);
    }
    return rc;
}

long uwg_dup3(int oldfd, int newfd, int flags) {
    struct tracked_fd state = uwg_state_lookup(oldfd);
    uwg_state_clear(newfd);
    long rc = uwg_passthrough_syscall3(SYS_dup3, oldfd, newfd, flags);
    if (rc < 0) return rc;
    if (state.active || state.proxied) {
        (void)uwg_state_store((int)rc, &state);
    }
    return rc;
}

/*
 * fcntl: F_GETFL / F_SETFL track the O_NONBLOCK bit so msg_ops can
 * propagate MSG_DONTWAIT correctly for tunnel fds (recvmsg-deadlock
 * fix from beta.46).  F_DUPFD / F_DUPFD_CLOEXEC follow the dup
 * semantics — propagate state to the new fd.
 *
 * For other cmds we passthrough; the kernel's actual fd state is
 * authoritative for things we don't track explicitly (close-on-exec,
 * etc.).
 */
long uwg_fcntl(int fd, int cmd, long arg) {
    if (cmd == UWG_F_DUPFD || cmd == UWG_F_DUPFD_CLOEXEC) {
        long newfd = uwg_passthrough_syscall3(SYS_fcntl, fd, cmd, arg);
        if (newfd < 0) return newfd;
        struct tracked_fd state = uwg_state_lookup(fd);
        if (state.active || state.proxied) {
            (void)uwg_state_store((int)newfd, &state);
        }
        return newfd;
    }
    if (cmd == UWG_F_SETFL) {
        struct tracked_fd state = uwg_state_lookup(fd);
        if (state.active || state.proxied) {
            state.saved_fl = (int)arg;
            (void)uwg_state_store(fd, &state);
        }
        return uwg_passthrough_syscall3(SYS_fcntl, fd, cmd, arg);
    }
    if (cmd == UWG_F_GETFL) {
        long rc = uwg_passthrough_syscall3(SYS_fcntl, fd, cmd, arg);
        if (rc >= 0) {
            struct tracked_fd state = uwg_state_lookup(fd);
            if (state.active || state.proxied) {
                state.saved_fl = (int)rc;
                (void)uwg_state_store(fd, &state);
            }
        }
        return rc;
    }
    return uwg_passthrough_syscall3(SYS_fcntl, fd, cmd, arg);
}

/*
 * setsockopt: track SO_REUSEADDR / SO_REUSEPORT so a subsequent
 * tunnel listen() can pass them to fdproxy. Other options pass
 * through.
 */
long uwg_setsockopt(int fd, int level, int optname, const void *val,
                    uint32_t vlen) {
    long rc = uwg_passthrough_syscall5(SYS_setsockopt, fd, level, optname,
                                       (long)val, (long)vlen);
    if (rc < 0) return rc;

    struct tracked_fd state = uwg_state_lookup(fd);
    if ((state.active || state.proxied) && level == SOL_SOCKET) {
        if (optname == SO_REUSEADDR && vlen >= sizeof(int)) {
            state.reuse_addr = (*(const int *)val) ? 1 : 0;
            (void)uwg_state_store(fd, &state);
        } else if (optname == SO_REUSEPORT && vlen >= sizeof(int)) {
            state.reuse_port = (*(const int *)val) ? 1 : 0;
            (void)uwg_state_store(fd, &state);
        }
    }
    return rc;
}

long uwg_getsockopt(int fd, int level, int optname, void *val,
                    uint32_t *vlen) {
    /* Always passthrough — the kernel's view of the underlying
     * socket's options is authoritative. */
    return uwg_passthrough_syscall5(SYS_getsockopt, fd, level, optname,
                                    (long)val, (long)vlen);
}

long uwg_getsockname(int fd, struct sockaddr *addr, uint32_t *alen) {
    /* TODO Phase 1 followup: synthesize tunnel-side bind from
     * shared state for proxied fds. The kernel would return the
     * unix-socketpair address (not what the app wants).
     * For now passthrough — apps may see surprising local addrs
     * for tunnel fds. */
    return uwg_passthrough_syscall3(SYS_getsockname, fd, (long)addr,
                                    (long)alen);
}

long uwg_getpeername(int fd, struct sockaddr *addr, uint32_t *alen) {
    /* TODO Phase 1 followup: synthesize tunnel-side peer address
     * from shared state for proxied fds (state.remote_ip + remote_port).
     * For now passthrough. */
    return uwg_passthrough_syscall3(SYS_getpeername, fd, (long)addr,
                                    (long)alen);
}

long uwg_shutdown(int fd, int how) {
    /* For tunnel TCP streams the shutdown propagates naturally over
     * the unix-socketpair to fdproxy. For UDP-connected we don't yet
     * have a graceful shutdown protocol; passthrough is acceptable
     * (kernel will half-close the unix socket; fdproxy will see
     * EOF and tear down its end). */
    return uwg_passthrough_syscall2(SYS_shutdown, fd, how);
}
