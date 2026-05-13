/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Core init: wire the bypass-secret, install sigaltstack, install
 * the SIGSYS handler, install the seccomp filter — in that exact
 * order. Wrong order bricks the process.
 *
 * Called from:
 *   - preload/shim_libc/shim_init.c constructor (the .so build)
 *   - preload/static/start.S → __uwg_init (the static-binary build,
 *     Phase 2)
 *
 * Async-signal-safe within the init function itself (we can't easily
 * tell if the caller is in a signal context — they shouldn't be, but
 * defensively we use only inline-asm syscalls).
 */

#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "dispatch.h"
#include "syscall.h"

/* The bypass secret. Read once at init from UWGS_TRACE_SECRET env.
 * Written by uwg_core_init; read by uwg_passthrough_syscall* (in
 * syscall.h, declared extern there). */
uint64_t uwg_bypass_secret;

/* Per-thread alternate signal stack — must be allocated and
 * registered before SIGSYS can fire on this thread. The .so build
 * calls uwg_core_init_thread() from the libc shim's first hooked
 * call on a new thread (cheap if already done, expensive once per
 * thread). The static build wires it up at __uwg_init for the main
 * thread and via a clone() shim for spawned threads (Phase 2).
 *
 * 64 KiB is comfortable for the dispatcher's stack frames; we never
 * recurse and the heaviest path is a fdproxy round-trip plus one
 * call into a uwg_* op. */
#include "freestanding_runtime.h"

#define UWG_SIGALTSTACK_SIZE (64 * 1024)

/*
 * Parse a uint64 from a NUL-terminated string. Async-signal-safe
 * replacement for strtoull. Returns 0 on parse failure (which the
 * filter installer treats as -EINVAL, fail-closed).
 */
static uint64_t parse_u64(const char *s) {
    if (!s) return 0;
    uint64_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        uint64_t d = (uint64_t)(*s - '0');
        if (v > (UINT64_MAX - d) / 10) return 0; /* overflow */
        v = v * 10 + d;
    }
    return v;
}

/* getenv replacement that walks the env vector. Both builds populate
 * uwg_environ at init: the .so build copies libc's `environ`; the
 * freestanding build parses envp from auxv at uwg_static_init time. */
extern char **environ;

static const char *uwg_getenv(const char *name) {
    if (!uwg_environ) return NULL;
    /* Compare name to each env entry up to '='. */
    size_t nlen = 0;
    while (name[nlen]) nlen++;
    for (char **e = uwg_environ; *e; e++) {
        const char *p = *e;
        size_t i = 0;
        while (i < nlen && p[i] && p[i] == name[i]) i++;
        if (i == nlen && p[i] == '=') {
            return p + i + 1;
        }
    }
    return NULL;
}

/* Atfork child handler — reinstall SIGSYS dispatcher after fork().
 * Must be at file scope (C has no local functions) and declared before use.
 * Defined as weak so the freestanding build (which doesn't link libc / this
 * TU's pthread_atfork call) can omit it without a linker error. */
#ifndef UWG_FREESTANDING
static void uwg_sigsys_atfork_child(void) {
    if (uwg_bypass_secret != 0)
        (void)uwg_install_sigsys_handler();
}

/* Forward-declare pthread_atfork without pulling in all of <pthread.h>. */
extern int pthread_atfork(void (*prepare)(void), void (*parent)(void),
                          void (*child)(void));

static int uwg_register_sigsys_atfork(void) {
    return pthread_atfork(NULL, NULL, uwg_sigsys_atfork_child);
}
#endif /* !UWG_FREESTANDING */

int uwg_core_init_thread(void) {
    if (uwg_get_thread_sigaltstack() != NULL) {
        return 0; /* already done */
    }

    /* Allocate via mmap — never malloc (async-signal-safety). */
    long mm = uwg_syscall6(SYS_mmap, 0, UWG_SIGALTSTACK_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mm < 0) return (int)mm;

    void *stack = (void *)mm;

    stack_t ss = {
        .ss_sp = stack,
        .ss_size = UWG_SIGALTSTACK_SIZE,
        .ss_flags = 0,
    };

    long rc = uwg_syscall2(SYS_sigaltstack, (long)&ss, 0);
    if (rc < 0) {
        /* Free the stack we just allocated. */
        (void)uwg_syscall2(SYS_munmap, (long)stack, UWG_SIGALTSTACK_SIZE);
        return (int)rc;
    }
    uwg_set_thread_sigaltstack(stack);
    return 0;
}

int uwg_core_init(void) {
    /* (0) bind libc's environ to our process-wide pointer. The
     * freestanding build sets uwg_environ from auxv before calling
     * uwg_core_init(), in which case this NULL-check leaves it alone. */
#ifndef UWG_FREESTANDING
    if (!uwg_environ) uwg_environ = environ;
#endif

    /* (1) bypass secret */
    const char *secret_env = uwg_getenv("UWGS_TRACE_SECRET");
    uwg_bypass_secret = parse_u64(secret_env);

    /* UWGS_DISABLE_SYSTRAP=1 (preferred name, set by transport=preload)
     * or its legacy alias UWGS_DISABLE_SECCOMP=1 forces libc-only
     * shim mode: no SIGSYS handler, no seccomp filter, no kernel
     * trap. The shim_libc layer alone covers libc-routed calls.
     *
     * The wrapper sets this env when:
     *   - transport=preload (libc-only, the new default for hosts
     *     without seccomp support — restricted containers etc.)
     *   - the user opts out via env in any other mode.
     *
     * "systrap" is the kernel-trap path (seccomp + SIGSYS handler);
     * disabling it here strips us back to the libc-fast-path only. */
    const char *disable = uwg_getenv("UWGS_DISABLE_SYSTRAP");
    if (!disable) disable = uwg_getenv("UWGS_DISABLE_SECCOMP");
    int seccomp_disabled = disable && (*disable == '1');

    if (uwg_bypass_secret == 0 && !seccomp_disabled) {
        return -22; /* -EINVAL */
    }

    /* (2) shared state mmap.
     * Best-effort: if UWGS_SHARED_STATE_PATH isn't set or the file
     * doesn't validate, dispatchers fall back to "treat fd as
     * non-tunnel and pass through". Correctness preserved; the
     * tunnel functionality just won't engage. */
    (void)uwg_state_init();
    /* If the shared state provided a secret, prefer that one over
     * what we read from env. The Go side is the authoritative source
     * for the secret value when both are available. */
    uint64_t shared_secret = uwg_state_secret();
    if (shared_secret != 0) {
        uwg_bypass_secret = shared_secret;
    }

    /* (2b) initialize fdproxy path lookup (env read at init time so
     * the SIGSYS handler doesn't have to walk environ later). */
    uwg_fdproxy_init();

    /* (3) per-thread arena — main thread first */
    int rc = uwg_core_init_thread();
    if (rc < 0) return rc;

    /* If we're in shim-only mode (no seccomp filter), there's no
     * SIGSYS to handle and no filter to install. The shim_libc
     * symbol layer alone provides interception for the libc-routed
     * surface, which is sufficient for drop-in legacy compat and
     * for apps like chromium that fork+exec frequently. Return
     * success so the constructor doesn't print an error. */
    if (seccomp_disabled || uwg_bypass_secret == 0) {
        return 0;
    }

    /* (4) SIGSYS handler — must be installed BEFORE the filter,
     * and must ALWAYS be reinstalled even when the filter is
     * inherited across execve (signal handlers reset on exec,
     * seccomp filters do not). */
    rc = uwg_install_sigsys_handler();
    if (rc < 0) return rc;

    /* (4b) Atfork child handler to close the CLONE_CLEAR_SIGHAND window.
     *
     * glibc 2.38-2.39's fork() calls clone3(CLONE_CLEAR_SIGHAND) which
     * resets ALL signal handlers to SIG_DFL in the child — including our
     * SIGSYS handler. The signal mask (all-blocked from glibc's pre-clone3
     * rt_sigprocmask(SIG_BLOCK, ~[])) is restored AFTER the user-side
     * atfork child handlers run. So any BPF-trapped syscall fired during
     * glibc's own child-cleanup OR in a user atfork handler will queue a
     * SIGSYS; the queued signal delivers when the mask is restored — with
     * SIG_DFL → process killed.
     *
     * Fix: register an atfork child handler that reinstalls the SIGSYS
     * handler. pthread_atfork child handlers run BEFORE glibc restores
     * the signal mask (see nptl/pthread_fork.c: call_function_static_weak
     * fires before __libc_signal_restore_set). Because we register here
     * (before any application code), our handler runs first, before
     * Python's / Chromium's / etc. handlers. The passthrough syscall
     * bypasses the BPF conditional rt_sigaction(SIGSYS) trap even while
     * SIGSYS is blocked, so the install succeeds unconditionally. */
#ifndef UWG_FREESTANDING
    (void)uwg_register_sigsys_atfork();
#endif

    /* (5) Seccomp filter — last; once this is in place we can't
     * undo it. UWGS_SUPERVISED=1 in the env tells the filter
     * builder to additionally route SYS_execve/SYS_execveat to
     * RET_TRACE for the systrap-supervised supervisor. The wrapper
     * sets this env when transport=systrap-supervised. */
    const char *sup = uwg_getenv("UWGS_SUPERVISED");
    uwg_seccomp_supervised_flag = (sup && *sup == '1') ? 1 : 0;

    /* UWGS_SYSTRAP_DOCKER=1: add execve/execveat to SECCOMP_RET_TRAP
     * so the in-process SIGSYS handler can intercept them and inject
     * the ptloader for static-binary children (no ptrace required). */
    const char *docker = uwg_getenv("UWGS_SYSTRAP_DOCKER");
    uwg_seccomp_docker_flag = (docker && *docker == '1') ? 1 : 0;
    if (uwg_seccomp_docker_flag) {
        uwg_ptloader_docker_init();
    }

    /* Skip duplicate filter install across execve: the kernel inherits
     * seccomp filters across execve, so when the child's preload
     * constructor runs the parent's filter is already in place.
     * Stacking a second identical filter works (kernel allows N
     * filters) but burns cycles on every syscall. UWGS_SECCOMP_INSTALLED=1
     * in the inherited env tells us to skip filter install only —
     * the SIGSYS handler was already reinstalled above (step 4). */
    const char *already = uwg_getenv("UWGS_SECCOMP_INSTALLED");
    if (already && *already == '1') {
        return 0;
    }

    rc = uwg_install_seccomp_filter(uwg_bypass_secret);
    if (rc < 0) return rc;

#ifndef UWG_FREESTANDING
    /* Mark the filter as installed in the environment so children
     * inheriting our env via execve can skip the duplicate install.
     * setenv is libc-only; the freestanding/static build can't easily
     * mutate environ, but it doesn't typically execve into Phase-1
     * preload children either, so the missed-dedupe cost is moot. */
    extern int setenv(const char *, const char *, int);
    (void)setenv("UWGS_SECCOMP_INSTALLED", "1", 1);
#endif

    return 0;
}
