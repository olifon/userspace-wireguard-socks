/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Runtime abstractions that diverge between the .so build (libc-linked,
 * uses __thread + extern environ) and the freestanding static-blob
 * build (no libc, manual TID-keyed storage, env from auxv).
 */

#ifndef UWG_PRELOAD_CORE_FREESTANDING_RUNTIME_H
#define UWG_PRELOAD_CORE_FREESTANDING_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

/* Process-wide environment vector. Set during early init:
 *   - .so build: assigned from libc's `extern char **environ` in the
 *     constructor.
 *   - freestanding build: parsed from auxv at uwg_static_init() time.
 * All env-walking code (uwg_getenv, dns_force.c, fdproxy_sock.c, …)
 * reads via uwg_environ instead of libc's environ. */
extern char **uwg_environ;

/* Size of the mmap'd alternate signal stack allocated per thread.
 * 64 KiB is comfortable for the dispatcher's stack frames; never
 * recurse and the heaviest path is a fdproxy round-trip. Defined here
 * so init.c, clone3_trampoline.c, and sigsys.c all share the value. */
#define UWG_SIGALTSTACK_SIZE (64 * 1024)

/* Per-thread sigaltstack lookup. Replaces the __thread-keyed storage
 * that the .so build uses. The freestanding build can't use __thread
 * because TLS requires runtime support (__tls_get_addr) absent in
 * static binaries.
 *
 * Backed by a TID-indexed open-addressing table with linear probing.
 * Deletions write a tombstone (INT32_MIN) instead of 0 to preserve the
 * probe chain for other TIDs whose entries are further in the chain.
 * The cost of a lookup is a linear probe over a few cache lines —
 * negligible compared to the per-syscall overhead.
 *
 * In docker/elf mode, SYS_exit is BPF-trapped so the sigaltstack entry
 * is tombstoned and munmapped on thread exit. In non-docker modes
 * (plain systrap), SYS_exit is not trapped, so entries persist as
 * stale-live after thread exit. TID recycling means a new thread may
 * find and reuse the old entry (the mapping is still valid). The table
 * is sized to comfortably outlive typical high-churn workloads (Go HTTP
 * servers, Python multiprocessing) before slot exhaustion is possible.
 * A full table silently degrades to SIGSYS on the normal stack rather
 * than the sigaltstack (see uwg_set_thread_sigaltstack comment). */
#define UWG_TID_TOMBSTONE ((int32_t)(-2147483647 - 1)) /* INT32_MIN */

void *uwg_get_thread_sigaltstack(void);
void  uwg_set_thread_sigaltstack(void *stack);
/* Mark the current thread's sigaltstack table entry as tombstone.  Uses a
 * tombstone rather than zeroing so other TIDs whose probe chains pass
 * through this slot can still find their own entries. */
void  uwg_clear_thread_sigaltstack(void);

#endif /* UWG_PRELOAD_CORE_FREESTANDING_RUNTIME_H */
