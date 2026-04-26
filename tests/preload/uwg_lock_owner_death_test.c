//go:build ignore

/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Owner-death regression test for the C-side robust rwlocks defined in
 * preload/shared_state.h. The story we are pinning here:
 *
 *   1. Process A acquires the write lock (via uwg_rwlock_wrlock).
 *   2. Process A is killed with SIGKILL while still holding it.
 *   3. Process B (the parent of A in this test) attempts to acquire
 *      the same lock. It MUST NOT hang. It MUST return UWG_LOCK_POISONED
 *      within a small deadline. The lock is now poisoned; future
 *      acquisitions also return UWG_LOCK_POISONED instead of trying to
 *      surgically recover.
 *
 * The test exits with status 0 on pass, non-zero with a printed message
 * on fail. It is invoked from uwg_lock_owner_death_test.go which builds
 * + runs it.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Pull in the rwlock primitive under test directly. */
#include "../../preload/shared_state.h"

static int my_tid(void) { return (int)syscall(SYS_gettid); }

/* die_holding_wrlock: child entry point. Acquires the write lock, then
 * SIGKILLs itself so the OS records the owner-died bit on the
 * underlying robust pthread_mutex. The parent picks up the test from
 * here. */
static int die_holding_wrlock(struct uwg_rwlock *lock) {
  int rc = uwg_rwlock_wrlock(lock, my_tid());
  if (rc != UWG_LOCK_OK) {
    fprintf(stderr, "child: wrlock failed rc=%d\n", rc);
    return 99;
  }
  /* Tell the parent we have the lock. We use a pipe rather than a
   * shared int so we don't have to coordinate ordering across the
   * mutex itself. */
  ssize_t n = write(STDOUT_FILENO, "got\n", 4);
  (void)n;
  /* Now die without releasing. SIGKILL specifically — the kernel
   * notices and (because the mutex is robust) marks it
   * owner-died on the next acquisition attempt. */
  if (kill(getpid(), SIGKILL) != 0) {
    fprintf(stderr, "child: self-kill failed: %m\n");
    return 98;
  }
  /* Unreachable. */
  for (;;) pause();
  return 0;
}

int main(void) {
  /* Allocate the shared rwlock in MAP_SHARED|MAP_ANONYMOUS memory so
   * the child sees it. */
  size_t sz = sizeof(struct uwg_rwlock);
  void *mem = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "mmap failed: %m\n");
    return 1;
  }
  struct uwg_rwlock *lock = (struct uwg_rwlock *)mem;
  memset(lock, 0, sz);

  /* Pre-init from the parent so the pthread_mutex object exists. The
   * uwg_rwlock_ensure_inited path would also do this on first use. */
  uwg_rwlock_ensure_inited(lock);

  /* Pipe so the child can signal "I have the lock" before dying. */
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    fprintf(stderr, "pipe failed: %m\n");
    return 2;
  }

  pid_t child = fork();
  if (child < 0) {
    fprintf(stderr, "fork failed: %m\n");
    return 3;
  }
  if (child == 0) {
    close(pipefd[0]);
    /* Redirect child stdout to the pipe so its "got\n" reaches us. */
    if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
      _exit(97);
    }
    close(pipefd[1]);
    _exit(die_holding_wrlock(lock));
  }
  close(pipefd[1]);

  /* Wait for the child's "got" signal. */
  char buf[8];
  ssize_t n = read(pipefd[0], buf, sizeof(buf));
  if (n <= 0) {
    fprintf(stderr, "parent: did not read child handshake (n=%zd)\n", n);
    return 4;
  }
  close(pipefd[0]);

  /* Reap. The child has already SIGKILLed itself by now, but waitpid
   * synchronises so we know the kernel has finished tearing it down. */
  int status = 0;
  if (waitpid(child, &status, 0) < 0) {
    fprintf(stderr, "waitpid: %m\n");
    return 5;
  }
  if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
    fprintf(stderr, "child did not die by SIGKILL: status=0x%x\n", status);
    return 6;
  }

  /* Now the load-bearing assertion: a wrlock attempt from the parent
   * must NOT hang. Spawn a helper thread that attempts the lock with
   * a deadline measured by the parent; if it hasn't returned within
   * 5 seconds, the test fails. We do this with alarm()-based
   * supervision because timed pthread_mutex variants would defeat
   * the point of the test (the user wants the natural call path to
   * survive owner death without anyone having to remember a
   * timeout). */
  struct sigaction sa = {0};
  sa.sa_handler = SIG_DFL;
  sigaction(SIGALRM, &sa, NULL);
  alarm(5);

  long long t0 = uwg_monotonic_now_ns();
  int rc = uwg_rwlock_wrlock(lock, my_tid());
  long long elapsed = uwg_monotonic_now_ns() - t0;
  alarm(0);

  if (rc != UWG_LOCK_POISONED) {
    fprintf(stderr,
            "expected UWG_LOCK_POISONED (%d), got rc=%d after %lldms\n",
            UWG_LOCK_POISONED, rc, elapsed / 1000000LL);
    return 7;
  }
  if (elapsed > 2LL * 1000LL * 1000LL * 1000LL) {
    fprintf(stderr, "wrlock returned but took %lldms — too slow\n",
            elapsed / 1000000LL);
    return 8;
  }
  if (!uwg_rwlock_is_poisoned(lock)) {
    fprintf(stderr, "lock not flagged poisoned after recovery\n");
    return 9;
  }

  /* Subsequent acquisitions must also return POISONED — once a lock is
   * poisoned it stays poisoned for the lifetime of the mapping. */
  int rc2 = uwg_rwlock_wrlock(lock, my_tid());
  if (rc2 != UWG_LOCK_POISONED) {
    fprintf(stderr, "second wrlock returned %d, want POISONED\n", rc2);
    return 10;
  }
  int rc3 = uwg_rwlock_rdlock(lock, my_tid());
  if (rc3 != UWG_LOCK_POISONED) {
    fprintf(stderr, "rdlock returned %d, want POISONED\n", rc3);
    return 11;
  }

  printf("ok\n");
  return 0;
}
