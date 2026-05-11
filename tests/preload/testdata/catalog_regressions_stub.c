/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Regression stub for the wrapper interop bugs the 2026-05 catalog
 * batch fixed. Each subcommand exercises one specific bug-prone
 * syscall pattern; the Go test harness (catalog_regressions_test.go)
 * runs each through the wrapper and asserts the canonical OK token.
 *
 * Subcommands (argv[1]):
 *   tcp_setsockopt <host> <port>   — TCP_NODELAY + SO_KEEPALIVE on a
 *       wrapper-proxied TCP fd must return 0, not EOPNOTSUPP. Class:
 *       "Python urllib 3.14 TCP_NODELAY EOPNOTSUPP" — preload now
 *       silently swallows SOL_TCP / IPPROTO_IP / IPPROTO_IPV6 /
 *       SOL_UDP options on proxied fds (the AF_UNIX socketpair the
 *       kernel sees won't accept them but the app shouldn't care).
 *
 *   udp_getsockname <bind-ip> <bind-port> — socket(UDP) + bind() then
 *       getsockname must return the tunnel-side bound address even
 *       before the first sendto/recvfrom (lazy listener bootstrap).
 *       Class: "mongod 8.0 Port 0 out of range parsing HostAndPort" —
 *       previously synthesized only when state.proxied, now also
 *       when state.bound.
 *
 *   tcp_accept_inherits <bind-ip> <bind-port> <client-host> <client-port>
 *       — bind+listen a TCP socket on the tunnel, accept once, then
 *       getsockname on the accepted fd. Must return the LISTENER's
 *       bind addr (the address the peer connected to), not 0.0.0.0:0.
 *       Class: "mongod accepted-fd getsockname returns 0.0.0.0:0".
 *
 * Output contract: each subcommand prints exactly one line ending in
 *   "OK: <subtest>"
 * on success, and prints "FAIL: <reason>" (one or more lines) on
 * failure. Test asserts the OK line in stdout.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_tcp(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { perror("socket"); return -1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad host %s\n", host);
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

static int run_tcp_setsockopt(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "FAIL: tcp_setsockopt host port\n"); return 2; }
    const char *host = argv[2];
    int port = atoi(argv[3]);
    int fd = connect_tcp(host, port);
    if (fd < 0) { printf("FAIL: connect %s:%d failed\n", host, port); return 1; }
    int one = 1;
    /* TCP_NODELAY at SOL_TCP — the Python urllib 3.14 regression. */
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        printf("FAIL: setsockopt(TCP_NODELAY) errno=%d (%s)\n", errno, strerror(errno));
        close(fd); return 1;
    }
    /* SO_KEEPALIVE at SOL_SOCKET — the kernel WILL accept this on the
     * AF_UNIX socketpair (it's a socket-layer option), so this must
     * also succeed. Probes that the swallow doesn't accidentally
     * silence legitimate SOL_SOCKET options. */
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) != 0) {
        printf("FAIL: setsockopt(SO_KEEPALIVE) errno=%d (%s)\n", errno, strerror(errno));
        close(fd); return 1;
    }
    /* TCP_KEEPIDLE / TCP_USER_TIMEOUT — common SOL_TCP options the
     * Python ssl/http stack sets. Must swallow. */
    int n = 60;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &n, sizeof(n)) != 0) {
        printf("FAIL: setsockopt(TCP_KEEPIDLE) errno=%d (%s)\n", errno, strerror(errno));
        close(fd); return 1;
    }
    /* Now write the canonical sentry and read it back, to prove the
     * fd is still usable (not closed/poisoned by the setsockopt). */
    const char *msg = "regr-tcp-setsockopt";
    if (write(fd, msg, strlen(msg)) != (ssize_t)strlen(msg)) {
        printf("FAIL: write after setsockopts errno=%d\n", errno);
        close(fd); return 1;
    }
    char buf[64];
    ssize_t r = read(fd, buf, sizeof(buf));
    close(fd);
    if (r != (ssize_t)strlen(msg) || memcmp(buf, msg, r) != 0) {
        printf("FAIL: echo mismatch after setsockopts r=%zd\n", r); return 1;
    }
    printf("OK: tcp_setsockopt\n");
    return 0;
}

static int run_udp_getsockname(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "FAIL: udp_getsockname bind-ip bind-port\n"); return 2; }
    const char *ip = argv[2];
    int port = atoi(argv[3]);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) { printf("FAIL: socket %s\n", strerror(errno)); return 1; }
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        printf("FAIL: bad bind ip\n"); close(fd); return 1;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        printf("FAIL: bind errno=%d (%s)\n", errno, strerror(errno));
        close(fd); return 1;
    }
    /* getsockname BEFORE first sendto/recvfrom — the lazy-listener
     * hasn't bootstrapped yet, but the preload must still synthesize
     * the bound addr because state.bound is set. The mongod regression. */
    struct sockaddr_in got; socklen_t glen = sizeof(got);
    memset(&got, 0, sizeof(got));
    if (getsockname(fd, (struct sockaddr *)&got, &glen) != 0) {
        printf("FAIL: getsockname errno=%d (%s)\n", errno, strerror(errno));
        close(fd); return 1;
    }
    char gotip[64]; inet_ntop(AF_INET, &got.sin_addr, gotip, sizeof(gotip));
    if (strcmp(gotip, ip) != 0 || ntohs(got.sin_port) != port) {
        printf("FAIL: getsockname returned %s:%d, want %s:%d\n",
               gotip, ntohs(got.sin_port), ip, port);
        close(fd); return 1;
    }
    close(fd);
    printf("OK: udp_getsockname\n");
    return 0;
}

static int run_tcp_accept_inherits(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "FAIL: tcp_accept_inherits bind-ip bind-port\n"); return 2; }
    const char *bind_ip = argv[2];
    int bind_port = atoi(argv[3]);

    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv < 0) { printf("FAIL: srv socket\n"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)bind_port);
    if (inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) {
        printf("FAIL: bad bind ip\n"); close(srv); return 1;
    }
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        printf("FAIL: bind errno=%d (%s)\n", errno, strerror(errno));
        close(srv); return 1;
    }
    if (listen(srv, 4) != 0) {
        printf("FAIL: listen errno=%d\n", errno); close(srv); return 1;
    }
    /* The Go test harness reads this LISTENING line as the cue to
     * dial the listener from the test-side (serverEng). Flushing
     * stderr so the line crosses the pipe before accept(2) blocks. */
    fprintf(stderr, "LISTENING %s:%d\n", bind_ip, bind_port);
    fflush(stderr);

    struct sockaddr_in peer; socklen_t plen = sizeof(peer);
    int acc = accept(srv, (struct sockaddr *)&peer, &plen);
    if (acc < 0) {
        printf("FAIL: accept errno=%d (%s)\n", errno, strerror(errno));
        close(srv); return 1;
    }
    /* The crux: getsockname on the ACCEPTED fd must return the
     * LISTENER's bind addr (bind_ip:bind_port). Previously this
     * returned 0.0.0.0:0 because the accepted fd's preload state
     * wasn't copying bind_* from the listener — the mongod regression. */
    struct sockaddr_in got; socklen_t glen = sizeof(got);
    memset(&got, 0, sizeof(got));
    if (getsockname(acc, (struct sockaddr *)&got, &glen) != 0) {
        printf("FAIL: acc getsockname errno=%d (%s)\n", errno, strerror(errno));
        close(acc); close(srv); return 1;
    }
    char gotip[64]; inet_ntop(AF_INET, &got.sin_addr, gotip, sizeof(gotip));
    if (strcmp(gotip, bind_ip) != 0 || ntohs(got.sin_port) != bind_port) {
        printf("FAIL: acc getsockname returned %s:%d, want %s:%d\n",
               gotip, ntohs(got.sin_port), bind_ip, bind_port);
        close(acc); close(srv); return 1;
    }
    /* Drain the message to make sure the connection actually worked. */
    char buf[64];
    ssize_t r = read(acc, buf, sizeof(buf));
    close(acc); close(srv);
    if (r <= 0) {
        printf("FAIL: acc read r=%zd errno=%d\n", r, errno); return 1;
    }
    printf("OK: tcp_accept_inherits\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <subcommand> ...\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "tcp_setsockopt") == 0)      return run_tcp_setsockopt(argc, argv);
    if (strcmp(argv[1], "udp_getsockname") == 0)     return run_udp_getsockname(argc, argv);
    if (strcmp(argv[1], "tcp_accept_inherits") == 0) return run_tcp_accept_inherits(argc, argv);
    fprintf(stderr, "unknown subcommand %s\n", argv[1]);
    return 2;
}
