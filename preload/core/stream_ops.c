/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Stream-style I/O dispatchers: read / write / readv / writev /
 * pread64 / pwrite64.
 *
 * The TCP-stream fast path:
 *   For a fd whose state.kind == KIND_TCP_STREAM, we do NOT translate
 *   anything — the fd is already a unix-stream socketpair end whose
 *   peer is fdproxy. Reads and writes flow as raw bytes through the
 *   socketpair and out the WireGuard tunnel without any per-syscall
 *   wrapper involvement. We just bypass-syscall to the kernel and
 *   the kernel does the right thing.
 *
 * The UDP-connected slow path:
 *   For state.kind == KIND_UDP_CONNECTED, the wrapper has set up the
 *   connection but datagram framing requires us to translate
 *   read/write into recv/send-with-length-prefix-frames. The
 *   fdproxy data plane uses a 4-byte big-endian length prefix per
 *   datagram on the manager-stream side.
 *
 *   For Phase 1 we punt UDP-connected read/write to -ENOSYS; very
 *   few apps do stream-style I/O on connected UDP, and the legacy
 *   preload's behavior already requires explicit recv*msg/send*msg
 *   to work end-to-end. Phase 2 lifts the framing helpers.
 *
 * Non-tunnel fds: pure passthrough.
 */

#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#include "../shared_state.h"
#include "syscall.h"
#include "dispatch.h"

long uwg_read(int fd, void *buf, size_t n) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && state.kind == KIND_UDP_CONNECTED) {
        /* TODO Phase 1 followup: stream-syscall-on-UDP-connected.
         * Per-syscall datagram read with length-prefix framing. */
        return -38L; /* -ENOSYS */
    }
    /* TCP-stream / non-tunnel / not active → kernel does it right. */
    return uwg_passthrough_syscall3(SYS_read, fd, (long)buf, (long)n);
}

long uwg_write(int fd, const void *buf, size_t n) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && state.kind == KIND_UDP_CONNECTED) {
        return -38L; /* -ENOSYS — see uwg_read */
    }
    return uwg_passthrough_syscall3(SYS_write, fd, (long)buf, (long)n);
}

long uwg_readv(int fd, const struct iovec *iov, int iovcnt) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && state.kind == KIND_UDP_CONNECTED) {
        return -38L;
    }
    return uwg_passthrough_syscall3(SYS_readv, fd, (long)iov, (long)iovcnt);
}

long uwg_writev(int fd, const struct iovec *iov, int iovcnt) {
    struct tracked_fd state = uwg_state_lookup(fd);
    if (state.proxied && state.kind == KIND_UDP_CONNECTED) {
        return -38L;
    }
    return uwg_passthrough_syscall3(SYS_writev, fd, (long)iov, (long)iovcnt);
}

long uwg_pread(int fd, void *buf, size_t n, int64_t off) {
    /* pread doesn't make sense on a socket; kernel will reject with
     * -ESPIPE. Pass through. */
    return uwg_passthrough_syscall4(SYS_pread64, fd, (long)buf, (long)n,
                                    (long)off);
}

long uwg_pwrite(int fd, const void *buf, size_t n, int64_t off) {
    return uwg_passthrough_syscall4(SYS_pwrite64, fd, (long)buf, (long)n,
                                    (long)off);
}
