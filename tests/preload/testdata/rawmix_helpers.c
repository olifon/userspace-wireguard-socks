/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#include "rawmix_helpers.h"

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

static long rawmix_syscall6(long nr, long a1, long a2, long a3, long a4,
                            long a5, long a6) {
#if defined(__x86_64__)
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8),
                     "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  register long x4 __asm__("x4") = a5;
  register long x5 __asm__("x5") = a6;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                   : "memory");
  return x0;
#else
# error "rawmix_helpers: unsupported architecture"
#endif
}

static long rawmix_fixret(long ret) {
  if (ret < 0 && ret >= -4095) {
    errno = (int)-ret;
    return -1;
  }
  return ret;
}

int rawmix_socket(int domain, int type, int protocol) {
  return (int)rawmix_fixret(rawmix_syscall6(SYS_socket, domain, type, protocol,
                                            0, 0, 0));
}

int rawmix_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
  return (int)rawmix_fixret(
      rawmix_syscall6(SYS_connect, fd, (long)addr, addrlen, 0, 0, 0));
}

ssize_t rawmix_write(int fd, const void *buf, size_t len) {
  return (ssize_t)rawmix_fixret(
      rawmix_syscall6(SYS_write, fd, (long)buf, (long)len, 0, 0, 0));
}

ssize_t rawmix_read(int fd, void *buf, size_t len) {
  return (ssize_t)rawmix_fixret(
      rawmix_syscall6(SYS_read, fd, (long)buf, (long)len, 0, 0, 0));
}

int rawmix_close(int fd) {
  return (int)rawmix_fixret(rawmix_syscall6(SYS_close, fd, 0, 0, 0, 0, 0));
}
