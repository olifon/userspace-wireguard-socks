/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Minimal repro for the bare-ptrace connect-EIO bug. curl 8.18 reports
 * "Immediate connect fail ... Input/output error" when connecting to
 * the WG tunnel side under uwgwrapper --transport=ptrace. This stub
 * exercises both ways an app can make a non-blocking socket:
 *
 *   mode=sock-nonblock: socket(SOCK_STREAM | SOCK_NONBLOCK)
 *   mode=fcntl:         socket(SOCK_STREAM) + fcntl(F_SETFL, O_NONBLOCK)
 *   mode=blocking:      socket(SOCK_STREAM)
 *
 * For the two non-blocking modes, valid outcomes are rc=0 OR
 * (rc=-1 + errno=EINPROGRESS). For the blocking mode, expect rc=0.
 * curl uses the fcntl variant (see lib/connect.c in libcurl).
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s ip port mode(sock-nonblock|fcntl|blocking)\n", argv[0]);
        return 2;
    }
    int type = SOCK_STREAM;
    int do_fcntl = 0;
    if (strcmp(argv[3], "sock-nonblock") == 0) type |= SOCK_NONBLOCK;
    else if (strcmp(argv[3], "fcntl") == 0) do_fcntl = 1;
    else if (strcmp(argv[3], "blocking") != 0) { fprintf(stderr, "bad mode\n"); return 2; }

    int fd = socket(AF_INET, type, 0);
    if (fd < 0) { perror("socket"); return 1; }
    if (do_fcntl) {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl < 0) { perror("fcntl F_GETFL"); return 1; }
        if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) { perror("fcntl F_SETFL"); return 1; }
    }
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &sin.sin_addr) != 1) { perror("inet_pton"); return 1; }
    int rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
    int e = errno;
    int nb = (type & SOCK_NONBLOCK) || do_fcntl;
    if (rc < 0 && nb && e != EINPROGRESS) {
        printf("connect FAIL rc=%d errno=%d (%s)\n", rc, e, strerror(e));
        close(fd);
        return 1;
    }
    /* If connect returned EINPROGRESS, do the full curl-style
     * post-connect dance: poll for writability, then check SO_ERROR. */
    if (rc < 0 && nb && e == EINPROGRESS) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        // 30s instead of 5s — bare-ptrace connect through the WG
        // tunnel + manager handshake can run >5s under CI load,
        // and we'd rather wait than spuriously fail.
        int pr = poll(&pfd, 1, 30000);
        if (pr <= 0 || !(pfd.revents & POLLOUT)) {
            printf("poll FAIL pr=%d revents=%x errno=%d (%s)\n", pr, pfd.revents, errno, strerror(errno));
            close(fd);
            return 1;
        }
        int so_err = -1;
        socklen_t slen = sizeof(so_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) < 0) {
            printf("getsockopt FAIL errno=%d (%s)\n", errno, strerror(errno));
            close(fd);
            return 1;
        }
        if (so_err != 0) {
            printf("connect FAIL SO_ERROR=%d (%s)\n", so_err, strerror(so_err));
            close(fd);
            return 1;
        }
    }
    /* Connect succeeded. Now do a tiny HTTP-like round-trip so we
     * exercise send/recv on the same socket curl would use. */
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    if (send(fd, req, strlen(req), 0) < 0) {
        printf("send FAIL errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }
    char buf[1024];
    /* Wait for response. */
    if (nb) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 5000) <= 0) {
            printf("poll-in FAIL errno=%d (%s)\n", errno, strerror(errno));
            close(fd);
            return 1;
        }
    }
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
        printf("recv FAIL errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }
    buf[n] = 0;
    /* Curl-style: after consuming the response, do a final
     * non-blocking recv to probe for more data. On a non-blocking
     * fd this MUST return -1 + EAGAIN (or -1 + EWOULDBLOCK). The
     * tracer used to deadlock here because its handleRecvfrom
     * called the underlying unix.Recvfrom in BLOCKING mode, even
     * though the tracee fd was O_NONBLOCK. That deadlock made curl
     * hang at exit cleanup. Pin it. */
    if (nb) {
        char tail[16];
        ssize_t m = recv(fd, tail, sizeof(tail), 0);
        if (m > 0) {
            /* unexpected extra data — also OK, we don't care */
        } else if (m == 0) {
            /* server closed cleanly — also OK */
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* expected: non-blocking probe found nothing */
        } else {
            printf("tail-recv FAIL errno=%d (%s)\n", errno, strerror(errno));
            close(fd);
            return 1;
        }
    }
    printf("OK got %zd bytes\n", n);
    close(fd);
    return 0;
}
