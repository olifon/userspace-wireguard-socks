/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Starts several pthreads, lets each establish an intercepted TCP
 * connection, then kills the whole tracee while those threads are blocked in
 * recv(). The wrapper/tracer should observe the thread-group death and exit
 * instead of waiting forever for a syscall-exit stop that will never arrive.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int ready_count = 0;

struct worker_arg {
    const char *ip;
    int port;
};

static void mark_ready(void) {
    pthread_mutex_lock(&mu);
    ready_count++;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mu);
}

static void *worker_main(void *opaque) {
    struct worker_arg *arg = (struct worker_arg *)opaque;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        mark_ready();
        return NULL;
    }
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)arg->port);
    if (inet_pton(AF_INET, arg->ip, &sin.sin_addr) != 1) {
        perror("inet_pton");
        close(fd);
        mark_ready();
        return NULL;
    }
    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        perror("connect");
        close(fd);
        mark_ready();
        return NULL;
    }
    mark_ready();
    char buf[32];
    (void)recv(fd, buf, sizeof(buf), 0);
    close(fd);
    return NULL;
}

static int wait_until_ready(int want) {
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        perror("clock_gettime");
        return 1;
    }
    deadline.tv_sec += 10;

    pthread_mutex_lock(&mu);
    while (ready_count < want) {
        int rc = pthread_cond_timedwait(&cond, &mu, &deadline);
        if (rc == ETIMEDOUT) {
            fprintf(stderr, "timeout waiting for workers: ready=%d want=%d\n", ready_count, want);
            pthread_mutex_unlock(&mu);
            return 1;
        }
        if (rc != 0) {
            fprintf(stderr, "pthread_cond_timedwait: %s\n", strerror(rc));
            pthread_mutex_unlock(&mu);
            return 1;
        }
    }
    pthread_mutex_unlock(&mu);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s ip port workers\n", argv[0]);
        return 2;
    }
    int workers = atoi(argv[3]);
    if (workers <= 0 || workers > 64) {
        fprintf(stderr, "bad workers=%d\n", workers);
        return 2;
    }

    struct worker_arg arg = {
        .ip = argv[1],
        .port = atoi(argv[2]),
    };
    pthread_t tids[64];
    for (int i = 0; i < workers; i++) {
        int rc = pthread_create(&tids[i], NULL, worker_main, &arg);
        if (rc != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(rc));
            return 1;
        }
    }

    if (wait_until_ready(workers) != 0) {
        return 1;
    }
    printf("READY\n");
    fflush(stdout);
    usleep(100000);
    kill(getpid(), SIGKILL);
    return 99;
}
