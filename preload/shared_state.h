/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#ifndef UWG_SHARED_STATE_H
#define UWG_SHARED_STATE_H

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifndef MAX_TRACKED_FD
#define MAX_TRACKED_FD 65536
#endif

#ifndef MAX_TRACKED_SLOTS
#define MAX_TRACKED_SLOTS 65536
#endif

#ifndef UWG_GUARD_SLOTS
#define UWG_GUARD_SLOTS 256
#endif

/* Maximum time a writer is willing to wait for active readers to drain.
 * If a reader thread crashes between rdlock and rdunlock the atomic
 * reader count never reaches zero on its own; a writer that exceeds this
 * deadline assumes that happened, poisons the lock, and returns
 * UWG_LOCK_POISONED. Coarse but matches the project's stated "fail what
 * is not guaranteed safe rather than deadlock" policy. */
#ifndef UWG_LOCK_READER_DRAIN_DEADLINE_NS
#define UWG_LOCK_READER_DRAIN_DEADLINE_NS (5LL * 1000LL * 1000LL * 1000LL)
#endif

/* Lock-call return codes. Backward-compatible with the prior "0 ok,
 * non-zero failure" contract — existing call sites that treat any
 * non-zero as "do not proceed" continue to work. New callers can
 * distinguish reentrancy from poison from a transient acquire failure
 * if they care.
 *
 * UWG_LOCK_OK         — lock acquired successfully.
 * UWG_LOCK_REENTRANT  — same thread is already inside the lock; the
 *                       call is a no-op for us, the caller should
 *                       NOT also call unlock.
 * UWG_LOCK_POISONED   — the lock detected unrecoverable corruption
 *                       (owner died, or readers failed to drain
 *                       within the deadline). Subsequent ops on
 *                       this lock will also return POISONED. The
 *                       preload uses this to enter passthrough mode
 *                       for the affected state.
 * UWG_LOCK_TRANSIENT  — the underlying pthread_mutex_lock returned
 *                       an error we don't recognize as fatal. The
 *                       caller should treat this as "could not lock
 *                       this time" — same as POISONED for the
 *                       immediate caller, but does NOT trigger the
 *                       global poison flag. Future attempts may
 *                       succeed. */
#define UWG_LOCK_OK 0
#define UWG_LOCK_REENTRANT (-1)
#define UWG_LOCK_POISONED (-2)
#define UWG_LOCK_TRANSIENT (-3)

enum managed_kind {
  KIND_NONE = 0,
  KIND_TCP_STREAM = 1,
  KIND_UDP_CONNECTED = 2,
  KIND_UDP_LISTENER = 3,
  KIND_TCP_LISTENER = 4,
};

struct tracked_fd {
  int active;
  int domain;
  int type;
  int protocol;
  int proxied;
  int kind;
  int hot_ready;
  int bound;
  int reuse_addr;
  int reuse_port;
  int bind_family;
  uint16_t bind_port;
  char bind_ip[46];
  int remote_family;
  uint16_t remote_port;
  char remote_ip[46];
  int saved_fl;
  int saved_fdfl;
};

struct tracked_slot {
  int32_t owner_pid;
  int32_t fd;
  struct tracked_fd state;
};

/* uwg_rwlock and uwg_guardlock are intentionally similar: a robust
 * process-shared pthread_mutex serializes writer-acquire (and briefly
 * blocks reader-counter bumps), atomic counters track in-flight readers.
 *
 * "Robust" means the kernel records the owning TID inside the mutex.
 * If that TID dies while holding the mutex, the next acquirer gets
 * EOWNERDEAD. We treat that as evidence that the state protected by
 * this lock is now in an unknown state and POISON the lock — every
 * subsequent operation returns UWG_LOCK_POISONED instead of trying to
 * recover surgically. Callers handle poison by failing fast (typically:
 * mark their tracked sockets as broken so subsequent syscalls return
 * ECONNRESET). See docs/internal/security-conventions.md and
 * docs/internal/lock-map-fdproxy.md for the full rationale.
 *
 * init_state is a CAS-guarded gate so the first thread to touch the
 * lock initializes the mutex with PTHREAD_PROCESS_SHARED + ROBUST and
 * subsequent threads spin briefly until it's done. */
struct uwg_rwlock {
  _Atomic uint32_t init_state;     /* 0 = uninit, 1 = initing, 2 = ready */
  _Atomic uint32_t poisoned;       /* 0 = healthy, non-zero = poisoned */
  _Atomic uint32_t readers;        /* in-flight reader count */
  _Atomic int32_t writer_tid;      /* TID of holding writer, 0 = none */
  pthread_mutex_t writer_mutex;    /* robust + process-shared */
};

struct uwg_guardlock {
  _Atomic uint32_t init_state;
  _Atomic uint32_t poisoned;
  _Atomic uint32_t readers;
  _Atomic int32_t writer_tid;
  pthread_mutex_t writer_mutex;
  /* Reader-TID slots so a writer can identify which threads are still
   * inside read sections. Used today for reentrancy detection only;
   * future work could use it to reap dead readers without a deadline. */
  _Atomic int32_t reader_tids[UWG_GUARD_SLOTS];
};

#define UWG_SHARED_MAGIC 0x55574753u
/* Bump this whenever the struct layout below or the lock layout above
 * changes. Mismatched mappings are rejected by the preload, which then
 * falls back to local-only state — no silent layout-corruption. */
#define UWG_SHARED_VERSION 7u

static inline int uwg_rwlock_writer_owned_by(struct uwg_rwlock *lock,
                                             int32_t tid) {
  return atomic_load_explicit(&lock->writer_tid, memory_order_acquire) == tid &&
         tid != 0;
}

static inline int uwg_guard_writer_owned_by(struct uwg_guardlock *lock,
                                            int32_t tid) {
  return atomic_load_explicit(&lock->writer_tid, memory_order_acquire) == tid &&
         tid != 0;
}

/* Internal helpers — initialize the underlying pthread_mutex with the
 * "process shared + robust" attributes when supported. Falls back to
 * default attrs if either flag is rejected (very old kernels / unusual
 * libcs); the lock still works in that case, just without owner-death
 * recovery. Callers should not invoke directly; use
 * uwg_rwlock_ensure_inited / uwg_guard_ensure_inited. */
static inline int uwg_pthread_mutex_init_robust(pthread_mutex_t *m) {
  pthread_mutexattr_t attr;
  if (pthread_mutexattr_init(&attr) != 0)
    return pthread_mutex_init(m, NULL);
  /* Process-shared so a mutex stored in mmap'd memory is acquireable
   * from any process that maps the same file. Best-effort. */
  (void)pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
  /* Robust so the kernel records the owning TID and the next acquirer
   * gets EOWNERDEAD if the owner died. Best-effort: if the platform
   * doesn't support robust mutexes the init still proceeds with
   * whatever defaults the attrs bag holds, and we lose owner-death
   * recovery (but the lock still functions correctly under normal
   * acquire/release). */
  (void)pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
  int rc = pthread_mutex_init(m, &attr);
  (void)pthread_mutexattr_destroy(&attr);
  if (rc != 0) {
    /* Last-resort fallback: default mutex. This loses every
     * recovery property we wanted but keeps the call graph alive
     * instead of bailing the preload entirely. */
    return pthread_mutex_init(m, NULL);
  }
  return 0;
}

/* CAS-guarded one-shot init. We can't use pthread_once here because the
 * lock lives in mmap'd shared memory and pthread_once state is
 * per-process. */
static inline void uwg_rwlock_ensure_inited(struct uwg_rwlock *lock) {
  uint32_t st = atomic_load_explicit(&lock->init_state, memory_order_acquire);
  if (st == 2)
    return;
  if (st == 0) {
    uint32_t expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &lock->init_state, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      (void)uwg_pthread_mutex_init_robust(&lock->writer_mutex);
      atomic_store_explicit(&lock->init_state, 2, memory_order_release);
      return;
    }
  }
  /* Lost the init race — wait for the winner to finish. */
  while (atomic_load_explicit(&lock->init_state, memory_order_acquire) != 2)
    sched_yield();
}

static inline void uwg_guard_ensure_inited(struct uwg_guardlock *lock) {
  uint32_t st = atomic_load_explicit(&lock->init_state, memory_order_acquire);
  if (st == 2)
    return;
  if (st == 0) {
    uint32_t expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &lock->init_state, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      (void)uwg_pthread_mutex_init_robust(&lock->writer_mutex);
      atomic_store_explicit(&lock->init_state, 2, memory_order_release);
      return;
    }
  }
  while (atomic_load_explicit(&lock->init_state, memory_order_acquire) != 2)
    sched_yield();
}

/* uwg_lock_poison_pthread is the recovery path shared between the
 * rwlock and the guardlock. EOWNERDEAD means the owning thread died
 * while holding the mutex; the protected state is no longer trustworthy.
 * We mark the lock consistent (so subsequent acquirers don't all get
 * EOWNERDEAD), unlock it, and set the poisoned flag. */
static inline void uwg_lock_poison_after_owner_death(pthread_mutex_t *m,
                                                     _Atomic uint32_t *poisoned,
                                                     _Atomic int32_t *writer_tid) {
  atomic_store_explicit(writer_tid, 0, memory_order_release);
  atomic_store_explicit(poisoned, 1, memory_order_release);
  (void)pthread_mutex_consistent(m);
  (void)pthread_mutex_unlock(m);
}

/* monotonic_now_ns: nanoseconds since some stable epoch (CLOCK_MONOTONIC).
 * Used only for the reader-drain deadline. */
static inline long long uwg_monotonic_now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

static inline int uwg_rwlock_rdlock(struct uwg_rwlock *lock, int32_t tid) {
  uwg_rwlock_ensure_inited(lock);
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire))
    return UWG_LOCK_POISONED;
  if (uwg_rwlock_writer_owned_by(lock, tid))
    return UWG_LOCK_REENTRANT;
  /* Briefly take the writer mutex so we can be sure no writer is
   * mid-critical-section while we bump the reader count. EOWNERDEAD
   * here means a previous writer died — poison and bail. Any other
   * non-zero error is treated as a transient acquire failure: the
   * lock state itself is fine, we just couldn't take it this time. */
  int rc = pthread_mutex_lock(&lock->writer_mutex);
  if (rc == EOWNERDEAD) {
    uwg_lock_poison_after_owner_death(&lock->writer_mutex, &lock->poisoned,
                                      &lock->writer_tid);
    return UWG_LOCK_POISONED;
  }
  if (rc == ENOTRECOVERABLE)
    return UWG_LOCK_POISONED;
  if (rc != 0)
    return UWG_LOCK_TRANSIENT;
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire)) {
    (void)pthread_mutex_unlock(&lock->writer_mutex);
    return UWG_LOCK_POISONED;
  }
  atomic_fetch_add_explicit(&lock->readers, 1, memory_order_acq_rel);
  (void)pthread_mutex_unlock(&lock->writer_mutex);
  return UWG_LOCK_OK;
}

static inline void uwg_rwlock_rdunlock(struct uwg_rwlock *lock) {
  atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
}

static inline int uwg_rwlock_wrlock(struct uwg_rwlock *lock, int32_t tid) {
  uwg_rwlock_ensure_inited(lock);
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire))
    return UWG_LOCK_POISONED;
  if (uwg_rwlock_writer_owned_by(lock, tid))
    return UWG_LOCK_REENTRANT;
  int rc = pthread_mutex_lock(&lock->writer_mutex);
  if (rc == EOWNERDEAD) {
    uwg_lock_poison_after_owner_death(&lock->writer_mutex, &lock->poisoned,
                                      &lock->writer_tid);
    return UWG_LOCK_POISONED;
  }
  if (rc == ENOTRECOVERABLE)
    return UWG_LOCK_POISONED;
  if (rc != 0)
    return UWG_LOCK_TRANSIENT;
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire)) {
    (void)pthread_mutex_unlock(&lock->writer_mutex);
    return UWG_LOCK_POISONED;
  }
  atomic_store_explicit(&lock->writer_tid, tid, memory_order_release);
  /* Wait for in-flight readers to drain. If a reader thread died
   * mid-critical-section, the count never reaches zero; on deadline
   * expiry we poison and bail. */
  long long deadline = uwg_monotonic_now_ns() + UWG_LOCK_READER_DRAIN_DEADLINE_NS;
  while (atomic_load_explicit(&lock->readers, memory_order_acquire) != 0) {
    if (uwg_monotonic_now_ns() >= deadline) {
      atomic_store_explicit(&lock->writer_tid, 0, memory_order_release);
      atomic_store_explicit(&lock->poisoned, 1, memory_order_release);
      (void)pthread_mutex_unlock(&lock->writer_mutex);
      return UWG_LOCK_POISONED;
    }
    sched_yield();
  }
  return UWG_LOCK_OK;
}

static inline void uwg_rwlock_wrunlock(struct uwg_rwlock *lock) {
  atomic_store_explicit(&lock->writer_tid, 0, memory_order_release);
  (void)pthread_mutex_unlock(&lock->writer_mutex);
}

/* uwg_rwlock_is_poisoned: cheap, non-locking observation. Hot-path
 * callers can short-circuit before doing any work. */
static inline int uwg_rwlock_is_poisoned(struct uwg_rwlock *lock) {
  return atomic_load_explicit(&lock->poisoned, memory_order_acquire) != 0;
}

/* Reader-TID bookkeeping for the guardlock: same structure as before,
 * used for reentrancy detection. The slot table is also useful as a
 * future "reap dead reader TIDs" mechanism but we don't yet do that. */
static inline int uwg_guard_hold_slot(struct uwg_guardlock *lock, int32_t tid) {
  for (size_t i = 0; i < UWG_GUARD_SLOTS; i++) {
    int32_t owner =
        atomic_load_explicit(&lock->reader_tids[i], memory_order_acquire);
    if (owner == tid)
      return 0;
    if (owner != 0)
      continue;
    int32_t expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &lock->reader_tids[i], &expected, tid, memory_order_acq_rel,
            memory_order_acquire) ||
        expected == tid)
      return 0;
  }
  return -1;
}

static inline void uwg_guard_release_slot(struct uwg_guardlock *lock,
                                          int32_t tid) {
  for (size_t i = 0; i < UWG_GUARD_SLOTS; i++) {
    int32_t expected = tid;
    if (atomic_compare_exchange_strong_explicit(
            &lock->reader_tids[i], &expected, 0, memory_order_acq_rel,
            memory_order_acquire) ||
        atomic_load_explicit(&lock->reader_tids[i], memory_order_acquire) == 0)
      return;
  }
}

/* Guardlock acquire/release: same skeleton as uwg_rwlock — robust
 * pthread mutex around the writer slot, atomic reader count, poison-on-
 * EOWNERDEAD. Reader-TID bookkeeping is added so reentrant readers from
 * the same TID don't double-count. */
static inline int uwg_guard_rdlock(struct uwg_guardlock *lock, int32_t tid) {
  uwg_guard_ensure_inited(lock);
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire))
    return UWG_LOCK_POISONED;
  if (uwg_guard_writer_owned_by(lock, tid))
    return UWG_LOCK_REENTRANT;
  while (uwg_guard_hold_slot(lock, tid) != 0)
    sched_yield();
  int rc = pthread_mutex_lock(&lock->writer_mutex);
  if (rc == EOWNERDEAD) {
    uwg_lock_poison_after_owner_death(&lock->writer_mutex, &lock->poisoned,
                                      &lock->writer_tid);
    uwg_guard_release_slot(lock, tid);
    return UWG_LOCK_POISONED;
  }
  if (rc == ENOTRECOVERABLE) {
    uwg_guard_release_slot(lock, tid);
    return UWG_LOCK_POISONED;
  }
  if (rc != 0) {
    uwg_guard_release_slot(lock, tid);
    return UWG_LOCK_TRANSIENT;
  }
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire)) {
    (void)pthread_mutex_unlock(&lock->writer_mutex);
    uwg_guard_release_slot(lock, tid);
    return UWG_LOCK_POISONED;
  }
  atomic_fetch_add_explicit(&lock->readers, 1, memory_order_acq_rel);
  (void)pthread_mutex_unlock(&lock->writer_mutex);
  return UWG_LOCK_OK;
}

static inline void uwg_guard_rdunlock(struct uwg_guardlock *lock, int32_t tid) {
  atomic_fetch_sub_explicit(&lock->readers, 1, memory_order_release);
  uwg_guard_release_slot(lock, tid);
}

static inline int uwg_guard_wrlock(struct uwg_guardlock *lock, int32_t tid) {
  uwg_guard_ensure_inited(lock);
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire))
    return UWG_LOCK_POISONED;
  int rc = pthread_mutex_lock(&lock->writer_mutex);
  if (rc == EOWNERDEAD) {
    uwg_lock_poison_after_owner_death(&lock->writer_mutex, &lock->poisoned,
                                      &lock->writer_tid);
    return UWG_LOCK_POISONED;
  }
  if (rc == ENOTRECOVERABLE)
    return UWG_LOCK_POISONED;
  if (rc != 0)
    return UWG_LOCK_TRANSIENT;
  if (atomic_load_explicit(&lock->poisoned, memory_order_acquire)) {
    (void)pthread_mutex_unlock(&lock->writer_mutex);
    return UWG_LOCK_POISONED;
  }
  atomic_store_explicit(&lock->writer_tid, tid, memory_order_release);
  long long deadline = uwg_monotonic_now_ns() + UWG_LOCK_READER_DRAIN_DEADLINE_NS;
  while (atomic_load_explicit(&lock->readers, memory_order_acquire) != 0) {
    if (uwg_monotonic_now_ns() >= deadline) {
      atomic_store_explicit(&lock->writer_tid, 0, memory_order_release);
      atomic_store_explicit(&lock->poisoned, 1, memory_order_release);
      (void)pthread_mutex_unlock(&lock->writer_mutex);
      return UWG_LOCK_POISONED;
    }
    sched_yield();
  }
  return UWG_LOCK_OK;
}

static inline void uwg_guard_wrunlock(struct uwg_guardlock *lock) {
  atomic_store_explicit(&lock->writer_tid, 0, memory_order_release);
  (void)pthread_mutex_unlock(&lock->writer_mutex);
}

static inline int uwg_guard_is_poisoned(struct uwg_guardlock *lock) {
  return atomic_load_explicit(&lock->poisoned, memory_order_acquire) != 0;
}

struct uwg_shared_state {
  uint32_t magic;
  uint32_t version;
  uint64_t syscall_passthrough_secret;
  struct uwg_rwlock lock;
  struct uwg_guardlock guard;
  struct tracked_slot tracked[MAX_TRACKED_SLOTS];
};

#endif /* UWG_SHARED_STATE_H */
