/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Phase 1 seccomp filter: traps the syscall surface that uwg_*
 * dispatchers handle, allows everything else through. The filter
 * exempts any syscall whose 6th argument equals the bypass secret,
 * which is how `uwg_passthrough_syscall*` re-issues kernel syscalls
 * from inside core dispatchers without recursing into the SIGSYS
 * handler.
 *
 * Filter rule order (top to bottom; first match wins):
 *
 *   1.  Architecture check — refuse non-x86_64 / non-aarch64 frames
 *       (kernels can deliver mixed-arch syscalls via 32-bit compat;
 *       we ignore those for now).
 *   2.  Bypass-secret check — args[5] == BYPASS_SECRET → ALLOW.
 *   3.  execve / execveat → RET_TRACE (Phase 2 bootstrap supervisor).
 *   4.  Trapped syscalls → SECCOMP_RET_TRAP (delivered as SIGSYS).
 *   5.  Default → ALLOW.
 *
 * Built by hand as a cBPF program. Doing this in seccomp_with_libseccomp
 * would link us to libseccomp (which we don't want for the static-binary
 * build) and would lose the args[5] check granularity.
 *
 * The filter is INSTALL-once-and-forget: kernel inherits across fork
 * and execve. The bootstrap supervisor in Phase 2 will use the
 * RET_TRACE on execve to detect new binaries and inject preload there
 * if needed. Until then, RET_TRACE without a tracer is treated as
 * RET_ALLOW by the kernel — the execve passes through unhindered.
 */

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "syscall.h"

#define UWG_FILTER_NR_OFFSET     offsetof(struct seccomp_data, nr)
#define UWG_FILTER_ARCH_OFFSET   offsetof(struct seccomp_data, arch)
#define UWG_FILTER_ARG0_LO       offsetof(struct seccomp_data, args[0])
#define UWG_FILTER_ARG5_LO       offsetof(struct seccomp_data, args[5])
#define UWG_FILTER_ARG5_HI       (offsetof(struct seccomp_data, args[5]) + 4)

#if defined(__x86_64__)
#  define UWG_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define UWG_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#  error "uwg core: unsupported arch for seccomp filter"
#endif

/*
 * Trap list. These are syscalls the core dispatchers handle.
 * Kept as a static const so callers can introspect for tests.
 */
/*
 * Trap list scope — Phase 1 trade-off.
 *
 * The full surface (read/write/close/dup/fcntl + network) is what
 * shim_libc covers; trapping in the kernel too is the belt-and-
 * braces safety net for raw asm. BUT: trapping read/write/close
 * makes the libc-init window after execve fatal — those are
 * heavy-use syscalls during init, and the SIGSYS handler is
 * process-local and reset on exec, so the kernel's default
 * disposition (terminate) fires before our constructor reinstalls
 * the handler. That's the chromium-fork+exec problem.
 *
 * Trim the trap list to network-only syscalls. libc-init doesn't
 * touch socket/connect/bind/listen/accept/sendmsg/recvmsg, so the
 * post-exec window is safe. Raw asm read/write/close/dup/fcntl on
 * tunnel-managed fds will bypass our interception — accepted as a
 * Phase 1 trade-off; shim_libc still catches the libc-routed
 * common case. The full trap list returns when Phase 1.5's execve
 * supervisor lands.
 */
static const int uwg_trapped_syscalls[] = {
    /* control-plane — socket creation, connection, listener setup */
    SYS_socket,
    SYS_socketpair,
    SYS_connect,
    SYS_bind,
    SYS_listen,
    SYS_accept,
    SYS_accept4,
    SYS_setsockopt,
    SYS_getsockopt,
    SYS_getsockname,
    SYS_getpeername,
    SYS_shutdown,

    /* message-style — explicit network IO */
    SYS_recvfrom,
    SYS_recvmsg,
    SYS_recvmmsg,
    SYS_sendto,
    SYS_sendmsg,
    SYS_sendmmsg,

    /* read / write / close / dup / fcntl ARE trapped under the
     * supervised flag (see uwg_trapped_extra_supervised below).
     * Without supervised mode they stay un-trapped — libc-init
     * uses them heavily and the post-execve window would die.
     * Under supervised mode the wrapper acts as the inert pre-init
     * SIGSYS handler (cmd/uwgwrapper/sigsys_stop_handler.go) until
     * the LD_PRELOAD constructor reinstalls the in-tracee
     * dispatcher. */

    /* rt_sigaction is NOT in this unconditional trap list. It's handled
     * by a separate conditional-trap branch below in the BPF filter:
     * trap only when arg0 (the signum) == SIGSYS. That preserves the
     * Go-runtime / chromium-sandbox protection (their handlers install
     * SIGSYS sigactions that would clobber ours), while letting glibc-
     * init's rt_sigaction calls for OTHER signums pass through during
     * the post-execve window when our SIGSYS handler isn't yet
     * reinstalled. Without that exemption the child dies on SIGSYS
     * default-action because libc-init runs before LD_PRELOAD
     * constructors. See the conditional block in uwg_build_filter. */
};

/* Extra trap list activated only under systrap-supervised. These are
 * the syscalls that libc-init uses heavily; without supervisor SIGSYS-
 * stop handling they'd terminate the post-execve child. The supervisor
 * (cmd/uwgwrapper/sigsys_stop_handler.go) catches SIGSYS-stops on
 * these and runs the syscall on the tracee's behalf via remoteSyscall
 * with the bypass-secret in arg6.
 *
 * The fd 0/1/2 fast-skip below short-circuits stdio at the BPF layer
 * so the supervisor doesn't get woken up for every printf — those
 * syscalls return RET_ALLOW directly. */
static const int uwg_trapped_extra_supervised[] = {
    SYS_read,
    SYS_write,
    SYS_close,
#ifdef SYS_dup
    SYS_dup,
#endif
#ifdef SYS_dup2
    SYS_dup2,
#endif
    SYS_dup3,
    SYS_fcntl,
};
#define UWG_N_TRAPPED_EXTRA_SUPERVISED \
    (sizeof(uwg_trapped_extra_supervised) / sizeof(uwg_trapped_extra_supervised[0]))

/* execve / execveat → RET_TRACE for the systrap-supervised mode.
 *
 * Behaviour switches at runtime based on whether a supervisor is
 * attached:
 *
 *   - `systrap` (no supervisor): traced list is empty; execve and
 *     execveat fall through to the default RET_ALLOW. The wrapped
 *     binary's exec into a static child loses interception (the
 *     documented systrap limitation — see PHASE2_DESIGN.md and
 *     docs/features/transparent-wrapper.md).
 *
 *   - `systrap-supervised` (UWGS_SUPERVISED=1): traced list is
 *     {SYS_execve, SYS_execveat}; the wrapper attaches a ptrace
 *     supervisor that catches PTRACE_EVENT_SECCOMP for these and
 *     re-arms the appropriate injection (LD_PRELOAD propagation
 *     for dynamic targets, freestanding-blob inject for static).
 *
 * Linux's seccomp filter caveat: RET_TRACE with NO tracer
 * attached makes the kernel fail the syscall with -ENOSYS
 * (man seccomp(2)). So we MUST only enable the traced entries
 * when the wrapper has confirmed it's attached as a tracer.
 */
static const int uwg_traced_syscalls_supervised[] = {
#ifdef SYS_execve
    SYS_execve,
#endif
#ifdef SYS_execveat
    SYS_execveat,
#endif
};
#define UWG_N_TRACED_SUPERVISED \
    (sizeof(uwg_traced_syscalls_supervised) / sizeof(uwg_traced_syscalls_supervised[0]))

/* Compile-time sentinel for the unsupervised case. */
static const int uwg_traced_syscalls_unsupervised[] = {0};
#define UWG_N_TRACED_UNSUPERVISED 0

#define UWG_N_TRAPPED  (sizeof(uwg_trapped_syscalls) / sizeof(uwg_trapped_syscalls[0]))

/* Supervised flag — set by uwg_core_init() in init.c after it reads
 * UWGS_SUPERVISED from the environment. The seccomp filter builder
 * reads this to decide whether to add execve/execveat to the
 * RET_TRACE list. */
int uwg_seccomp_supervised_flag = 0;

/* Docker flag — set by uwg_core_init() when UWGS_SYSTRAP_DOCKER=1.
 * When 1, the seccomp filter adds execve/execveat to SECCOMP_RET_TRAP
 * so the in-process SIGSYS handler can intercept them without ptrace. */
int uwg_seccomp_docker_flag = 0;

/* SYS_clone3 was added in Linux 5.3 (2019). Define it if the build
 * headers pre-date that (e.g. older container toolchains, freestanding
 * builds). The number is stable: 435 on both x86_64 and aarch64. */
#ifndef SYS_clone3
# if defined(__x86_64__) || defined(__aarch64__)
#  define SYS_clone3 435
# endif
#endif

/* execve/execveat → SECCOMP_RET_TRAP for systrap-docker mode.
 * Mutually exclusive with the supervised-trace list (a given process
 * runs either supervised or docker, not both).
 *
 * NOTE: clone3 is NOT in this main filter. See uwg_install_seccomp_filter_layer2()
 * for the BPF-trap approach (installed after handler, docker mode only).
 * This docker list only traps execve/execveat. */
static const int uwg_trapped_docker_syscalls[] = {
#ifdef SYS_execve
    SYS_execve,
#endif
#ifdef SYS_execveat
    SYS_execveat,
#endif
};
#define UWG_N_TRAPPED_DOCKER \
    (sizeof(uwg_trapped_docker_syscalls) / sizeof(uwg_trapped_docker_syscalls[0]))

/*
 * Filter program build buffer. Sized to comfortably hold:
 *   - 2 instr arch check
 *   - 4 instr bypass-secret check (load lo, jmp neq, load hi, jmp eq)
 *   - 2 * UWG_N_TRACED  (load nr is shared; one jeq per trace target → ret)
 *   - 2 * UWG_N_TRAPPED (one jeq per trap target → ret)
 *   - 1 final ALLOW
 *
 * 256 instructions is plenty (kernel limit is 32768).
 */
#define UWG_FILTER_MAX_INSNS 256

struct uwg_filter_prog {
    struct sock_filter insns[UWG_FILTER_MAX_INSNS];
    size_t n;
};

static void uwg_emit(struct uwg_filter_prog *p, struct sock_filter ins) {
    /* Caller is responsible for not exceeding UWG_FILTER_MAX_INSNS. */
    p->insns[p->n++] = ins;
}

/*
 * Build the filter program. Returns 0 on success, -EINVAL if the
 * insn buffer would overflow. Output is a struct sock_fprog that
 * the caller passes to seccomp(2) directly.
 */
static int uwg_build_filter(struct uwg_filter_prog *p, uint64_t bypass_secret,
                            int supervised) {
    p->n = 0;
    const int *traced = supervised
        ? uwg_traced_syscalls_supervised
        : uwg_traced_syscalls_unsupervised;
    size_t n_traced = supervised
        ? UWG_N_TRACED_SUPERVISED
        : (size_t)UWG_N_TRACED_UNSUPERVISED;

    /* (1) architecture check */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARCH_OFFSET));
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, UWG_AUDIT_ARCH, 1, 0));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    /* Bypass-secret halves for the general bypass check (applies to all
     * syscalls that are not execve/execveat in docker mode). */
    uint32_t lo = (uint32_t)(bypass_secret & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)((bypass_secret >> 32) & 0xFFFFFFFFu);

    /* Execve-specific bypass secret: different from the general secret so
     * that glibc's execve — which does not zero arg6 before the syscall
     * instruction — cannot accidentally match a leftover bypass_secret in
     * arg6 and slip past the docker-mode execve trap.  Only
     * uwg_passthrough_execve_syscall* puts this value in arg6. */
    uint64_t exec_bypass = bypass_secret ^ UWG_EXECVE_BYPASS_TWEAK;
    uint32_t exec_lo = (uint32_t)(exec_bypass & 0xFFFFFFFFu);
    uint32_t exec_hi = (uint32_t)((exec_bypass >> 32) & 0xFFFFFFFFu);

    /* (2) Load syscall number first — required so the docker-execve block
     * below can check nr before deciding whether to apply the execve-bypass
     * or the general bypass. */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_NR_OFFSET));

    /* (2b) execve / execveat → ALLOW (with execve_bypass) or RET_TRAP.
     *
     * Docker mode only; mutually exclusive with supervised mode.  The
     * in-process SIGSYS handler intercepts trapped execves and injects
     * the ptloader before handing off to the real ld.so.
     *
     * Each docker syscall gets a 7-instruction block:
     *   JEQ A==nr, jt=0 (fall to exec_bypass check), jf=6 (skip block)
     *   LD arg5_lo
     *   JEQ lo==exec_lo, jt=0, jf=3  (mismatch → RET_TRAP)
     *   LD arg5_hi
     *   JEQ hi==exec_hi, jt=0, jf=1  (mismatch → RET_TRAP)
     *   RET ALLOW  ← only uwg_passthrough_execve_syscall* reaches here
     *   RET TRAP   ← all other callers (including glibc execve after a
     *                passthrough call that left bypass_secret in arg6)
     *
     * rt_sigprocmask and clone3 are NOT in this main trap list because
     * the main filter is inherited by exec'd children before the SIGSYS
     * handler is reinstalled.  They are trapped by the layer-2 filter
     * which is installed only after the SIGSYS handler is running. */
    if (uwg_seccomp_docker_flag) {
        for (size_t i = 0; i < UWG_N_TRAPPED_DOCKER; i++) {
            /* JEQ A==nr: if false, skip the 6-instruction exec_bypass block. */
            uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                     uwg_trapped_docker_syscalls[i],
                                                     0, 6));
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_LO));
            uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, exec_lo, 0, 3));
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_HI));
            uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, exec_hi, 0, 1));
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));
        }
    }

    /* (3) General bypass-secret check on args[5] — applies to all remaining
     * syscalls (execve/execveat in docker mode have already been handled above).
     * cBPF can only load 32 bits at a time, so we check lo and hi halves of
     * the 64-bit arg separately.  An exact match returns ALLOW immediately;
     * a mismatch falls through to the trap list.
     *
     * After this block A = arg5_hi (the last BPF load); reload nr before
     * the trace/trap lists. */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_LO));
    /* if lo != expected → skip the hi check + ALLOW return (3 insns) */
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, lo, 0, 3));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_HI));
    /* if hi != expected → skip the ALLOW return (1 insn) */
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, hi, 0, 1));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    /* Reload nr — the bypass check above loaded arg5 into A. */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_NR_OFFSET));

    /* (4) execve / execveat → RET_TRACE (only when supervised)
     * We emit one JEQ per syscall; a match returns RET_TRACE
     * immediately, otherwise falls through to the trap list. */
    for (size_t i = 0; i < n_traced; i++) {
        uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 traced[i], 0, 1));
        uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));
    }

    /* (4) trapped syscalls → SECCOMP_RET_TRAP */
    for (size_t i = 0; i < UWG_N_TRAPPED; i++) {
        uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 uwg_trapped_syscalls[i], 0, 1));
        uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));
    }

    /* (4a) Supervised-extra trap list: read/write/close/dup/fcntl,
     * with fd 0/1/2 fast-skip. Each entry emits 6 BPF instructions:
     *   JEQ A == nr ──┐ skip-true=0, skip-false=4 (next syscall test)
     *   LD args[0] (lo)
     *   JLE A <= 2 ──┐ skip-true=1, skip-false=0 (fd > 2 → RET_TRAP)
     *   RET ALLOW    │
     *   RET TRAP     ◀┘
     *   LD nr        (reload nr for next loop iteration)
     *
     * Without the fast-skip every printf to stderr would round-trip
     * through the supervisor; with it stdio is RET_ALLOW'd at the
     * filter layer and never wakes the supervisor.
     *
     * The supervisor in cmd/uwgwrapper/sigsys_stop_handler.go catches
     * the SIGSYS-stops generated by RET_TRAP here and runs the
     * syscall on the tracee's behalf via remoteSyscall with the
     * bypass-secret in arg6. */
    if (supervised) {
        for (size_t i = 0; i < UWG_N_TRAPPED_EXTRA_SUPERVISED; i++) {
            int nr = uwg_trapped_extra_supervised[i];
            /* JEQ A==nr; if not, skip 4 instrs to next iteration. */
            uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 4));
            /* Load args[0] lo. fd is a 32-bit int so the lo half is
             * sufficient — high half is zero or sign-extended for the
             * 31-bit space the fd table uses. */
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG0_LO));
            /* JGT A > 2 → skip-true=0 (fall to RET_TRAP), skip-false=1 (skip RET_TRAP, fall to RET_ALLOW) */
            uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 2, 0, 1));
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));
            /* Reload nr for the next loop iteration since A was
             * clobbered by the args[0] load. */
            uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_NR_OFFSET));
        }
    }

    /* (4b) Conditional block: rt_sigaction(SIGSYS, ...) only.
     * After the unconditional trap loop, A still holds the syscall nr.
     * If nr == SYS_rt_sigaction and arg0 (the signum) == SIGSYS (31),
     * return errno=0 (success) WITHOUT executing the syscall.
     * Any other signum falls through to ALLOW.
     *
     * Using SECCOMP_RET_ERRNO | 0 (return-0-as-success) instead of
     * SECCOMP_RET_TRAP is critical here. SECCOMP_RET_TRAP would deliver
     * SIGSYS to the process; if the SIGSYS handler hasn't been reinstalled
     * yet (the post-exec LD_PRELOAD-constructor window), the process dies
     * with SIG_DFL. This window exists for every dynamic binary exec'd
     * under systrap-elf: exec resets all handlers, then ld.so loads
     * uwgpreload.so and runs our constructor, but that happens AFTER ld.so
     * does its own setup. Any rt_sigaction(SIGSYS) call in that window
     * (e.g. from glibc's fork-child path on glibc 2.39, or from
     * subprocess.Popen's posix_spawn child on Ubuntu 24.04) fires TRAP,
     * SIGSYS is SIG_DFL, process killed.
     *
     * With SECCOMP_RET_ERRNO | 0: the kernel returns 0 (success) without
     * executing rt_sigaction. Our handler stays installed. No SIGSYS
     * delivered. No timing window. The caller (Go, Chrome, glibc child
     * path) sees return=0 and continues.
     *
     * Go's runtime calls rt_sigaction(SIGSYS=31). With the old
     * SECCOMP_RET_ERRNO|EPERM it got EPERM → panic("sigaction failed").
     * Go only ignores errors for signals 32, 33, 64 — not 31. With
     * errno=0 Go sees success and happily continues.
     *
     * The old_sa (3rd arg) is NOT filled by either approach: with
     * SECCOMP_RET_ERRNO the kernel skips the call; callers that need the
     * old handler should query it separately before installing. In
     * practice all callers we care about (Go, Chrome sandbox) pass NULL.
     *
     * Our own uwg_install_sigsys_handler() uses uwg_passthrough_syscall4
     * which places bypass_secret in args[5]; the BPF rule above (step 2)
     * returns ALLOW for that call before reaching this branch.
     *
     * SIGSYS is 31 on every Linux arch we support (asm-generic/signal.h);
     * no need for arch-specific constants. The signum fits in the lo
     * 32 bits of args[0] so we don't need to also check the hi half. */
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             SYS_rt_sigaction, 0, 3));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG0_LO));
    uwg_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             31 /* SIGSYS */, 0, 1));
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0));

    /* (5) default — let the kernel handle it */
    uwg_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    if (p->n > UWG_FILTER_MAX_INSNS) {
        return -22; /* -EINVAL */
    }
    return 0;
}

/*
 * Install the filter. Returns 0 on success or negative -errno.
 * Must be called AFTER PR_SET_NO_NEW_PRIVS and AFTER the SIGSYS
 * handler is installed.
 *
 * Uses raw syscalls — no libc — so it works in both .so and static
 * builds and is safe to call from the freestanding `core` layer.
 *
 * SECCOMP_FILTER_FLAG_TSYNC propagates the filter to all current
 * threads atomically. Any future thread (clone after this point)
 * inherits the filter automatically per kernel semantics.
 */
int uwg_install_seccomp_filter(uint64_t bypass_secret) {
    /* A zero secret would match any syscall whose unused arg6 happens
     * to be zero (the common case for syscalls with <6 args), making
     * the filter a no-op. Refuse rather than ship a broken filter.
     * Caller must generate a cryptographically-random nonzero secret
     * (uwgwrapper does this via /dev/urandom). */
    if (bypass_secret == 0) {
        return -22; /* -EINVAL */
    }

    int supervised = uwg_seccomp_supervised_flag;
    struct uwg_filter_prog prog;
    int rc = uwg_build_filter(&prog, bypass_secret, supervised);
    if (rc < 0) {
        return rc;
    }

    /* PR_SET_NO_NEW_PRIVS is required for non-cap_sys_admin processes
     * to install seccomp filters. Idempotent — safe to call again
     * even if the wrapper-launcher already set it. */
    long pr_rc = uwg_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (pr_rc < 0) {
        return (int)pr_rc;
    }

    struct sock_fprog fprog = {
        .len = (unsigned short)prog.n,
        .filter = prog.insns,
    };

    long sc_rc = uwg_syscall3(SYS_seccomp,
                              SECCOMP_SET_MODE_FILTER,
                              SECCOMP_FILTER_FLAG_TSYNC,
                              (long)&fprog);
    if (sc_rc < 0) {
        return (int)sc_rc;
    }
    return 0;
}

/*
 * Layer-2 filter — stacked AFTER the SIGSYS handler is installed (systrap-elf
 * / docker mode only). Adds rt_sigprocmask and clone3 to the trap list.
 *
 * The main filter cannot include these because it is inherited by exec'd
 * children before the handler is reinstalled:
 *   - rt_sigprocmask: ld.so calls it during startup; with SIG_DFL the SIGSYS
 *     trap would kill the child.
 *   - clone3: glibc's __libc_fork() calls rt_sigprocmask(SIG_BLOCK,~all)
 *     BEFORE clone3 (via inline asm, bypassing our PLT shim and the main
 *     filter). If clone3 were in the main filter, force_sig_info_to_task
 *     would see SIGSYS blocked and reset our handler to SIG_DFL.
 *
 * Safe in systrap-elf (docker) mode because ALL exec'd ELF children get
 * ptloader as their PT_INTERP. ptloader installs the SIGSYS handler BEFORE
 * ld.so, so:
 *   - ld.so's rt_sigprocmask calls deliver to our handler → handler strips
 *     SIGSYS from the blocked set → SIGSYS is never blocked.
 *   - glibc's pre-clone3 rt_sigprocmask(SIG_BLOCK,~all) → same stripping.
 *   - clone3(CLONE_CLEAR_SIGHAND) → handler fires via clone3_trampoline →
 *     strips CLONE_CLEAR_SIGHAND, does the passthrough, clears other handlers
 *     in the child.
 *
 * With this filter in place, clone3_asm.S and the sigsys.c clone3 trampoline
 * are live code for the BPF-trap path (in addition to the PLT-shim path they
 * already served). dispatch.c case SYS_rt_sigprocmask is also live for the
 * BPF-trap path.
 */
int uwg_install_seccomp_filter_layer2(uint64_t bypass_secret) {
    if (bypass_secret == 0) return -22;

    struct uwg_filter_prog prog;
    prog.n = 0;

    uint32_t lo = (uint32_t)(bypass_secret & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)((bypass_secret >> 32) & 0xFFFFFFFFu);

    /* (1) bypass-secret: args[5] == secret → ALLOW (same as main filter). */
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_LO));
    uwg_emit(&prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, lo, 0, 3));
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_ARG5_HI));
    uwg_emit(&prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, hi, 0, 1));
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    /* (2) load syscall nr. */
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, UWG_FILTER_NR_OFFSET));

    /* (3) rt_sigprocmask → TRAP.
     * handler (dispatch.c case SYS_rt_sigprocmask) strips SIGSYS from any
     * SIG_BLOCK/SIG_SETMASK set, ensuring SIGSYS is never blocked. */
    uwg_emit(&prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  SYS_rt_sigprocmask, 0, 1));
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));

    /* (4) clone3 → TRAP.
     * handler (sigsys.c → clone3_trampoline → clone3_asm.S) strips
     * CLONE_CLEAR_SIGHAND. Safe because step (3) ensures SIGSYS is never
     * blocked when clone3 runs, so force_sig_info_to_task delivers normally
     * instead of resetting our handler to SIG_DFL. */
#ifdef SYS_clone3
    uwg_emit(&prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  SYS_clone3, 0, 1));
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));
#endif

    /* (5) SYS_exit → TRAP.
     * Handler (sigsys.c) munmaps the pre-allocated 64 KiB sigaltstack via
     * the assembly gate uwg_munmap_and_exit, then re-issues the real exit
     * with bypass_secret in arg6 so this very rule is bypassed. Without
     * the munmap, each thread creation leaks one VMA entry — harmless in
     * size but grows the kernel's mm_struct rb-tree and slows mmap/fault
     * paths over the process lifetime. */
#ifdef SYS_exit
    uwg_emit(&prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  SYS_exit, 0, 1));
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));
#endif

    /* (6) SYS_exit_group → TRAP.
     * Same munmap-and-exit path as SYS_exit.  Handles threads created with
     * CLONE_VM but without CLONE_THREAD (e.g. some async runtimes). */
#ifdef SYS_exit_group
    uwg_emit(&prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  SYS_exit_group, 0, 1));
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP));
#endif

    /* (7) default → ALLOW. */
    uwg_emit(&prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    long pr_rc = uwg_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (pr_rc < 0) return (int)pr_rc;

    struct sock_fprog fprog = {
        .len  = (unsigned short)prog.n,
        .filter = prog.insns,
    };
    long sc_rc = uwg_syscall3(SYS_seccomp,
                               SECCOMP_SET_MODE_FILTER,
                               SECCOMP_FILTER_FLAG_TSYNC,
                               (long)&fprog);
    return (sc_rc < 0) ? (int)sc_rc : 0;
}

/* Test helper: returns the trapped-syscall list for unit testing. */
const int *uwg_seccomp_trapped_list(size_t *n) {
    if (n) *n = UWG_N_TRAPPED;
    return uwg_trapped_syscalls;
}

const int *uwg_seccomp_traced_list(size_t *n) {
    /* Returns the active traced list based on the supervised flag.
     * When supervised, includes execve/execveat; otherwise empty. */
    if (uwg_seccomp_supervised_flag) {
        if (n) *n = UWG_N_TRACED_SUPERVISED;
        return uwg_traced_syscalls_supervised;
    }
    if (n) *n = UWG_N_TRACED_UNSUPERVISED;
    return uwg_traced_syscalls_unsupervised;
}
