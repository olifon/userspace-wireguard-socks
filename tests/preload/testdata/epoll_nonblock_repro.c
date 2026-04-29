/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * libuv-style nonblocking TCP flow:
 *   socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK)
 *   connect() -> EINPROGRESS
 *   epoll_wait(EPOLLOUT)
 *   getsockopt(SO_ERROR)
 *   send()
 *   epoll_wait(EPOLLIN)
 *   recv()
 *   recv(MSG_DONTWAIT) -> EAGAIN/EWOULDBLOCK once drained
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static int wait_for_epoll(int epfd, uint32_t events, int timeout_ms) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    int n = epoll_wait(epfd, &ev, 1, timeout_ms);
    if (n <= 0) {
        fprintf(stderr, "epoll_wait timeout/error n=%d errno=%d (%s)\n", n, errno, strerror(errno));
        return 1;
    }
    if ((ev.events & (events | EPOLLERR | EPOLLHUP)) == 0) {
        fprintf(stderr, "epoll_wait got events=%x want=%x\n", ev.events, events);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s ip port\n", argv[0]);
        return 2;
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &sin.sin_addr) != 1) {
        perror("inet_pton");
        close(fd);
        return 1;
    }

    int rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
    if (rc < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "connect errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        perror("epoll_create1");
        close(fd);
        return 1;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        perror("epoll_ctl add");
        close(epfd);
        close(fd);
        return 1;
    }
    if (wait_for_epoll(epfd, EPOLLOUT, 30000) != 0) {
        close(epfd);
        close(fd);
        return 1;
    }
    int so_error = -1;
    socklen_t so_len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0 || so_error != 0) {
        fprintf(stderr, "SO_ERROR=%d errno=%d (%s)\n", so_error, errno, strerror(errno));
        close(epfd);
        close(fd);
        return 1;
    }

    const char *req = "GET / HTTP/1.0\r\n\r\n";
    if (send(fd, req, strlen(req), 0) != (ssize_t)strlen(req)) {
        perror("send");
        close(epfd);
        close(fd);
        return 1;
    }

    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        perror("epoll_ctl mod");
        close(epfd);
        close(fd);
        return 1;
    }
    char buf[1024];
    ssize_t n = -1;
    for (int attempt = 0; attempt < 500; attempt++) {
        if (wait_for_epoll(epfd, EPOLLIN, 30000) != 0) {
            close(epfd);
            close(fd);
            return 1;
        }
        n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n >= 0) {
            break;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv");
            close(epfd);
            close(fd);
            return 1;
        }
        usleep(10000);
    }
    if (n < 0) {
        fprintf(stderr, "recv did not become readable after epoll readiness\n");
        close(epfd);
        close(fd);
        return 1;
    }
    buf[n] = 0;

    char tail[16];
    ssize_t m = recv(fd, tail, sizeof(tail), MSG_DONTWAIT);
    if (m < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "tail recv errno=%d (%s)\n", errno, strerror(errno));
        close(epfd);
        close(fd);
        return 1;
    }

    printf("OK epoll got %zd bytes\n", n);
    close(epfd);
    close(fd);
    return 0;
}
