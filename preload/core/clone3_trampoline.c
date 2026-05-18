/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * clone3 trampoline — C setup layer.
 *
 * When the SIGSYS handler catches SYS_clone3 in docker mode, this path
 * handles two distinct cases:
 *
 * Case 1 — CLONE_CLEAR_SIGHAND (fork-like, e.g. glibc 2.38+ fork()):
 *   1. Strips CLONE_CLEAR_SIGHAND so the child inherits our SIGSYS handler.
 *   2. Passes the actual clone3 to the kernel via the assembly gate.
 *   3. Assembly gate child path: clears all handlers EXCEPT SIGSYS, signals
 *      the parent futex if needed, restores registers, jumps to trap_rip.
 *
 * Case 2 — CLONE_VM without CLONE_VFORK (thread creation, e.g. pthread_create):
 *   sigaltstack is per-thread. Linux clears (disables) the child's alternate
 *   signal stack when CLONE_VM is set and CLONE_VFORK is not. Without a
 *   sigaltstack, SA_ONSTACK SIGSYS delivery falls back to the thread's tiny
 *   stack and can overflow or fail if the stack is exhausted. Fix: pre-mmap
 *   a 64 KB sigaltstack in the parent, embed it in the save area, and have
 *   the assembly gate call SYS_sigaltstack in the child path — before
 *   touching any stack — so the child thread immediately has a valid alt
 *   stack for SIGSYS delivery.
 *
 * For threads (CLONE_SIGHAND set), the handler-clear loop MUST NOT run:
 * with CLONE_SIGHAND the sigaction table is shared, so rt_sigaction from the
 * child would reset handlers in the parent too. The clear_sighandlers flag
 * controls this: true only for CLONE_CLEAR_SIGHAND (fork-like) clones.
 *
 * The save_area is on the parent's SIGSYS signal stack (sigaltstack).
 * Parent waits for child to finish reading it (via futex) when CLONE_VM
 * is set without CLONE_VFORK; parent is blocked by kernel when CLONE_VFORK
 * is set; COW copy is independent when neither flag is set.
 *
 * Async-signal-safe: runs inside the SIGSYS handler. No malloc, no libc.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>

#include "syscall.h"
#include "dispatch.h"

#ifndef UWG_SIGALTSTACK_SIZE
# define UWG_SIGALTSTACK_SIZE (64 * 1024)
#endif

/* Ubuntu 18.04 / kernel-4.15 headers predate clone3 (Linux 5.3).
 * Provide arch-correct fallback syscall numbers so the guard below fires
 * and uwg_clone3_dfl_action is always compiled in — matching the identical
 * fallback in clone3_asm.S. */
#ifndef SYS_clone3
# ifdef __aarch64__
#  define SYS_clone3 220
# else
#  define SYS_clone3 435
# endif
#endif

/* SYS_clone is always present on Linux; fallback in case freestanding
 * headers omit it. */
#ifndef SYS_clone
# if defined(__x86_64__)
#  define SYS_clone 56
# elif defined(__aarch64__)
#  define SYS_clone 220
# endif
#endif

/* Guard: only meaningful on architectures where clone3 exists. */
#if defined(SYS_clone3) && (defined(__x86_64__) || defined(__aarch64__))

/* Minimal clone_args layout — only fields we read (flags, stack, stack_size).
 * The caller may pass a larger struct; size is checked before access. */
struct uwg_ca {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
};

#ifndef CLONE_CLEAR_SIGHAND
# define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif
#ifndef CLONE_VFORK
# define CLONE_VFORK 0x00004000
#endif
#ifndef CLONE_VM
# define CLONE_VM 0x00000100
#endif
#ifndef CLONE_SIGHAND
# define CLONE_SIGHAND 0x00000800
#endif

/*
 * Register save area — placed on the parent's signal stack so the child can
 * access it via a callee-saved register bookmark. The child reads all fields
 * and then signals the futex (telling the parent it's done).
 *
 * Only registers that survive a syscall instruction are saved; rax/x0 (child
 * returns 0) and rsp/sp (set from child_rsp) are handled separately. On
 * x86_64, rcx and r11 are also excluded: the `syscall` instruction clobbers
 * them (rcx ← RIP, r11 ← RFLAGS), so the caller's code at the syscall site
 * never relies on their values after the call. On aarch64, `svc #0` only
 * writes x0; all other registers are preserved by the kernel, so x8
 * (syscall number) is excluded to avoid false precision.
 */
#if defined(__x86_64__)
struct uwg_clone3_save {
    uint64_t rbx;   /* 0x00 */
    uint64_t rdx;   /* 0x08 */
    uint64_t rsi;   /* 0x10 */
    uint64_t rdi;   /* 0x18 */
    uint64_t rbp;   /* 0x20 */
    uint64_t r8;    /* 0x28 */
    uint64_t r9;    /* 0x30 */
    uint64_t r10;   /* 0x38 */
    uint64_t r12;   /* 0x40 */
    uint64_t r13;   /* 0x48 */
    uint64_t r14;   /* 0x50 */
    uint64_t r15;   /* 0x58 */
};
#elif defined(__aarch64__)
struct uwg_clone3_save {
    uint64_t x1, x2, x3, x4, x5, x6, x7;              /* 0x00 */
    uint64_t x9, x10, x11, x12, x13, x14, x15;         /* 0x38 */
    uint64_t x16, x17, x18;                             /* 0x70 */
    uint64_t x19, x20, x21, x22, x23, x24, x25, x26, x27, x28; /* 0x88 */
    uint64_t x29, x30;                                  /* 0xd8 */
};
#endif

/* 32-byte all-zero kernel_sigaction → SIG_DFL, no restorer, no flags, empty mask.
 * Used by the assembly gate's per-signal clear loop. */
const char uwg_clone3_dfl_action[32] = {0};

/*
 * Assembly gate — see clone3_asm.S. C interface:
 *   clone_args_ptr  : pointer to the (already modified) clone_args
 *   clone_args_size : sizeof the clone_args struct (passed through to kernel)
 *   save_area_ptr   : pointer to uwg_clone3_save_ext on the signal stack
 *
 * R12/X19 = trap_rip/trap_pc      (loaded from save_area.trap_rip)
 * R13/X20 = child_rsp/child_sp    (loaded from save_area.child_rsp)
 * R14/X21 = futex_ptr             (loaded from save_area.futex_ptr)
 * R15/X22 = save_area_ext_ptr     (rdx/x2 directly)
 *
 * Additional fields read by assembly in child path only:
 *   save_area.ss_ptr            — pointer to inline stack_t (or 0)
 *   save_area.clear_sighandlers — 1 = run rt_sigaction clear loop
 */

/* Extended save area: GPR struct + coordination fields + optional sigaltstack.
 *
 * Field offsets (must match clone3_asm.S exactly):
 *   x86_64: regs=0x00..0x5F (0x60), trap_rip=0x60, child_rsp=0x68,
 *           futex_ptr=0x70, ss_ptr=0x78, clear_sighandlers=0x80,
 *           ss_sp=0x88, ss_flags=0x90, _ss_pad=0x94, ss_size=0x98
 *   aarch64: regs=0x00..0xE7 (0xE8), trap_rip=0xE8, child_rsp=0xF0,
 *            futex_ptr=0xF8, ss_ptr=0x100, clear_sighandlers=0x108,
 *            ss_sp=0x110, ss_flags=0x118, _ss_pad=0x11C, ss_size=0x120
 */
struct uwg_clone3_save_ext {
    struct uwg_clone3_save regs;
    uint64_t trap_rip;          /* jump target for child */
    uint64_t child_rsp;         /* RSP/SP to set in child */
    uint64_t futex_ptr;         /* &futex_word, or 0 if no wait needed */
    /* Sigaltstack setup for CLONE_VM+no_CLONE_VFORK children: */
    uint64_t ss_ptr;            /* pointer to ss_sp below, or 0 (inherit) */
    uint64_t clear_sighandlers; /* 1 = run handler-clear loop, 0 = skip */
    /* Inline stack_t layout (valid when ss_ptr != 0; ss_ptr points here): */
    uint64_t ss_sp;             /* sigaltstack base address */
    uint32_t ss_flags;          /* always 0 */
    uint32_t _ss_pad;           /* ABI alignment padding */
    uint64_t ss_size;           /* sigaltstack size in bytes */
};

/* Declared in clone3_asm.S */
extern long uwg_clone3_asm_gate(long clone_args_ptr,
                                 long clone_args_size,
                                 long save_area_ext_ptr);

/* clone (old-style) asm gate — same save_ext layout, different syscall
 * number and flat arg layout.  Declared in clone3_asm.S.
 * Args: save_ext_ptr, flags, child_stack, parent_tid, child_tid, tls.
 * The asm entry point shuffles these into the kernel-ABI registers for
 * SYS_clone, loads bypass_secret into the 6th syscall arg, then jumps
 * to the shared clone3/clone common body. */
extern long uwg_clone_asm_gate(long save_ext_ptr,
                                long flags,
                                long child_stack,
                                long parent_tid,
                                long child_tid,
                                long tls);

/*
 * Entry point called from the SIGSYS handler (sigsys.c) when SYS_clone3
 * is trapped in docker mode. uc is the signal ucontext — provides exact
 * trap-point register state. Returns child PID (parent) or does not return
 * (child — jumps directly to application code).
 */
long uwg_clone3_trampoline(long a1, long a2, ucontext_t *uc)
{
    struct uwg_ca *ca = (struct uwg_ca *)a1;
    long size = a2;

    if (!ca || size < (long)sizeof(uint64_t))
        goto fallback;

    /* Determine what we need to fix up for this clone3 call. */
    int need_clr = !!(ca->flags & CLONE_CLEAR_SIGHAND);
    /* CLONE_VM without CLONE_VFORK = thread creation: kernel clears child's
     * sigaltstack. CLONE_VFORK = parent blocked by kernel, child inherits. */
    int need_ss  = !!(ca->flags & CLONE_VM) && !(ca->flags & CLONE_VFORK);

    if (!need_clr && !need_ss)
        goto fallback;

    /* Strip CLONE_CLEAR_SIGHAND so the child inherits our SIGSYS handler.
     * The assembly gate then clears all other handlers in the child. */
    if (need_clr)
        ca->flags &= ~(uint64_t)CLONE_CLEAR_SIGHAND;

    /* Build the extended save area on the signal stack (local variable —
     * signal stack is large enough for this struct). */
    struct uwg_clone3_save_ext ext;

    /* Fill GPR save from ucontext. */
#if defined(__x86_64__)
    ext.regs.rbx = (uint64_t)uc->uc_mcontext.gregs[REG_RBX];
    ext.regs.rdx = (uint64_t)uc->uc_mcontext.gregs[REG_RDX];
    ext.regs.rsi = (uint64_t)uc->uc_mcontext.gregs[REG_RSI];
    ext.regs.rdi = (uint64_t)uc->uc_mcontext.gregs[REG_RDI];
    ext.regs.rbp = (uint64_t)uc->uc_mcontext.gregs[REG_RBP];
    ext.regs.r8  = (uint64_t)uc->uc_mcontext.gregs[REG_R8];
    ext.regs.r9  = (uint64_t)uc->uc_mcontext.gregs[REG_R9];
    ext.regs.r10 = (uint64_t)uc->uc_mcontext.gregs[REG_R10];
    ext.regs.r12 = (uint64_t)uc->uc_mcontext.gregs[REG_R12];
    ext.regs.r13 = (uint64_t)uc->uc_mcontext.gregs[REG_R13];
    ext.regs.r14 = (uint64_t)uc->uc_mcontext.gregs[REG_R14];
    ext.regs.r15 = (uint64_t)uc->uc_mcontext.gregs[REG_R15];

    ext.trap_rip  = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    /* child_rsp: if an explicit stack is given use its top; otherwise the
     * child gets a COW copy of the parent's address space and RSP = the
     * parent's RSP at the syscall instruction (= ucontext RSP). */
    if (size >= (long)__builtin_offsetof(struct uwg_ca, stack_size) + 8 &&
        ca->stack != 0) {
        ext.child_rsp = ca->stack + ca->stack_size;
    } else {
        ext.child_rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
    }
#elif defined(__aarch64__)
    ext.regs.x1  = (uint64_t)uc->uc_mcontext.regs[1];
    ext.regs.x2  = (uint64_t)uc->uc_mcontext.regs[2];
    ext.regs.x3  = (uint64_t)uc->uc_mcontext.regs[3];
    ext.regs.x4  = (uint64_t)uc->uc_mcontext.regs[4];
    ext.regs.x5  = (uint64_t)uc->uc_mcontext.regs[5];
    ext.regs.x6  = (uint64_t)uc->uc_mcontext.regs[6];
    ext.regs.x7  = (uint64_t)uc->uc_mcontext.regs[7];
    ext.regs.x9  = (uint64_t)uc->uc_mcontext.regs[9];
    ext.regs.x10 = (uint64_t)uc->uc_mcontext.regs[10];
    ext.regs.x11 = (uint64_t)uc->uc_mcontext.regs[11];
    ext.regs.x12 = (uint64_t)uc->uc_mcontext.regs[12];
    ext.regs.x13 = (uint64_t)uc->uc_mcontext.regs[13];
    ext.regs.x14 = (uint64_t)uc->uc_mcontext.regs[14];
    ext.regs.x15 = (uint64_t)uc->uc_mcontext.regs[15];
    ext.regs.x16 = (uint64_t)uc->uc_mcontext.regs[16];
    ext.regs.x17 = (uint64_t)uc->uc_mcontext.regs[17];
    ext.regs.x18 = (uint64_t)uc->uc_mcontext.regs[18];
    ext.regs.x19 = (uint64_t)uc->uc_mcontext.regs[19];
    ext.regs.x20 = (uint64_t)uc->uc_mcontext.regs[20];
    ext.regs.x21 = (uint64_t)uc->uc_mcontext.regs[21];
    ext.regs.x22 = (uint64_t)uc->uc_mcontext.regs[22];
    ext.regs.x23 = (uint64_t)uc->uc_mcontext.regs[23];
    ext.regs.x24 = (uint64_t)uc->uc_mcontext.regs[24];
    ext.regs.x25 = (uint64_t)uc->uc_mcontext.regs[25];
    ext.regs.x26 = (uint64_t)uc->uc_mcontext.regs[26];
    ext.regs.x27 = (uint64_t)uc->uc_mcontext.regs[27];
    ext.regs.x28 = (uint64_t)uc->uc_mcontext.regs[28];
    ext.regs.x29 = (uint64_t)uc->uc_mcontext.regs[29];
    ext.regs.x30 = (uint64_t)uc->uc_mcontext.regs[30];

    ext.trap_rip  = (uint64_t)uc->uc_mcontext.pc;
    if (size >= (long)__builtin_offsetof(struct uwg_ca, stack_size) + 8 &&
        ca->stack != 0) {
        ext.child_rsp = ca->stack + ca->stack_size;
    } else {
        ext.child_rsp = (uint64_t)uc->uc_mcontext.sp;
    }
#endif

    /* Futex word (on signal stack, child writes 1 when done).
     * Only needed for CLONE_VM + no CLONE_VFORK: shared address space,
     * parent not blocked by kernel. Without the futex, the parent could
     * return from this SIGSYS handler and trigger a new SIGSYS that
     * overwrites this stack frame before the child has finished reading it.
     *
     * CLONE_VFORK: kernel blocks parent until exec → no futex needed.
     * No CLONE_VM (fork-like): COW copy of address space → no shared stack. */
    uint32_t futex_word = 0;
    int need_futex = (ca->flags & CLONE_VM) && !(ca->flags & CLONE_VFORK);
    ext.futex_ptr = need_futex ? (uint64_t)&futex_word : 0;

    /* Sigaltstack for child thread: when CLONE_VM is set without CLONE_VFORK,
     * Linux clears the child's sigaltstack at clone3 time. Allocate 64 KB now
     * (in the parent, safe to call mmap from SIGSYS handler) and embed the
     * stack_t in the save area. The assembly gate calls SYS_sigaltstack in the
     * child path using registers only — no stack push — so the call is safe
     * even before child_rsp is established. */
    if (need_ss) {
        long mm = uwg_syscall6(SYS_mmap, 0, UWG_SIGALTSTACK_SIZE,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mm < 0) goto fallback;
        ext.ss_sp    = (uint64_t)mm;
        ext.ss_flags = 0;
        ext._ss_pad  = 0;
        ext.ss_size  = UWG_SIGALTSTACK_SIZE;
        ext.ss_ptr   = (uint64_t)&ext.ss_sp; /* points into ext on signal stack */
    } else {
        ext.ss_ptr = 0;
    }

    /* Only run the signal-handler clear loop for CLONE_CLEAR_SIGHAND.
     * With CLONE_SIGHAND (threads), the sigaction table is SHARED: running
     * rt_sigaction from the child would reset handlers in the parent too. */
    ext.clear_sighandlers = need_clr ? 1 : 0;

    return uwg_clone3_asm_gate(a1, a2, (long)&ext);

fallback:
    /* Nothing to intercept — pass through directly. */
    return uwg_passthrough_syscall2(SYS_clone3, a1, a2);
}

#endif /* SYS_clone3 */

/* SYS_clone (old-style) trampoline.
 *
 * glibc < 2.34, musl, and the Go runtime use SYS_clone (not SYS_clone3) for
 * thread creation.  Linux clears the child's sigaltstack for CLONE_VM without
 * CLONE_VFORK threads just as it does for clone3 — so the same per-thread
 * sigaltstack setup is required.
 *
 * CLONE_CLEAR_SIGHAND is a clone3-only flag; SYS_clone does not support it.
 * So need_clr is always 0 here.  We only intercept when CLONE_VM is set
 * without CLONE_VFORK (thread creation) and a sigaltstack install is needed.
 *
 * Reuses uwg_clone3_save_ext (identical struct layout) and the shared
 * assembly common body via uwg_clone_asm_gate (new entry point in
 * clone3_asm.S that sets rax/x8=SYS_clone and shuffles the flat args into
 * syscall register order before jumping to the shared common code).
 *
 * SYS_clone flat arg layout:
 *   x86_64: rdi=flags, rsi=child_stack, rdx=parent_tid, r10=child_tid, r8=tls
 *   aarch64: x0=flags, x1=child_stack, x2=parent_tid, x3=child_tid, x4=tls
 *
 * The ucontext reflects these positions via uwg_uctx_load_args (args[0..4]).
 */
#if defined(__x86_64__) || defined(__aarch64__)
long uwg_clone_trampoline(long a1, long a2, long a3, long a4, long a5,
                          ucontext_t *uc)
{
    /* a1=flags, a2=child_stack, a3=parent_tid, a4=child_tid, a5=tls */
    uint64_t flags       = (uint64_t)a1;
    long     child_stack = a2;

    /* Only intercept thread creation: CLONE_VM set, CLONE_VFORK not set.
     * Anything else (fork-like, vfork) doesn't need sigaltstack setup. */
    int need_ss = !!(flags & CLONE_VM) && !(flags & CLONE_VFORK);
    if (!need_ss)
        goto fallback;

    struct uwg_clone3_save_ext ext;

    /* Fill GPR save from ucontext — same fields as clone3 trampoline. */
#if defined(__x86_64__)
    ext.regs.rbx = (uint64_t)uc->uc_mcontext.gregs[REG_RBX];
    ext.regs.rdx = (uint64_t)uc->uc_mcontext.gregs[REG_RDX];
    ext.regs.rsi = (uint64_t)uc->uc_mcontext.gregs[REG_RSI];
    ext.regs.rdi = (uint64_t)uc->uc_mcontext.gregs[REG_RDI];
    ext.regs.rbp = (uint64_t)uc->uc_mcontext.gregs[REG_RBP];
    ext.regs.r8  = (uint64_t)uc->uc_mcontext.gregs[REG_R8];
    ext.regs.r9  = (uint64_t)uc->uc_mcontext.gregs[REG_R9];
    ext.regs.r10 = (uint64_t)uc->uc_mcontext.gregs[REG_R10];
    ext.regs.r12 = (uint64_t)uc->uc_mcontext.gregs[REG_R12];
    ext.regs.r13 = (uint64_t)uc->uc_mcontext.gregs[REG_R13];
    ext.regs.r14 = (uint64_t)uc->uc_mcontext.gregs[REG_R14];
    ext.regs.r15 = (uint64_t)uc->uc_mcontext.gregs[REG_R15];
    ext.trap_rip  = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    /* child_rsp: SYS_clone's child_stack arg is the TOP of the child stack
     * (Linux kernel interprets it as the starting SP directly).  If zero,
     * the child inherits the parent's RSP. */
    ext.child_rsp = child_stack ? (uint64_t)child_stack
                                : (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
#elif defined(__aarch64__)
    ext.regs.x1  = (uint64_t)uc->uc_mcontext.regs[1];
    ext.regs.x2  = (uint64_t)uc->uc_mcontext.regs[2];
    ext.regs.x3  = (uint64_t)uc->uc_mcontext.regs[3];
    ext.regs.x4  = (uint64_t)uc->uc_mcontext.regs[4];
    ext.regs.x5  = (uint64_t)uc->uc_mcontext.regs[5];
    ext.regs.x6  = (uint64_t)uc->uc_mcontext.regs[6];
    ext.regs.x7  = (uint64_t)uc->uc_mcontext.regs[7];
    ext.regs.x9  = (uint64_t)uc->uc_mcontext.regs[9];
    ext.regs.x10 = (uint64_t)uc->uc_mcontext.regs[10];
    ext.regs.x11 = (uint64_t)uc->uc_mcontext.regs[11];
    ext.regs.x12 = (uint64_t)uc->uc_mcontext.regs[12];
    ext.regs.x13 = (uint64_t)uc->uc_mcontext.regs[13];
    ext.regs.x14 = (uint64_t)uc->uc_mcontext.regs[14];
    ext.regs.x15 = (uint64_t)uc->uc_mcontext.regs[15];
    ext.regs.x16 = (uint64_t)uc->uc_mcontext.regs[16];
    ext.regs.x17 = (uint64_t)uc->uc_mcontext.regs[17];
    ext.regs.x18 = (uint64_t)uc->uc_mcontext.regs[18];
    ext.regs.x19 = (uint64_t)uc->uc_mcontext.regs[19];
    ext.regs.x20 = (uint64_t)uc->uc_mcontext.regs[20];
    ext.regs.x21 = (uint64_t)uc->uc_mcontext.regs[21];
    ext.regs.x22 = (uint64_t)uc->uc_mcontext.regs[22];
    ext.regs.x23 = (uint64_t)uc->uc_mcontext.regs[23];
    ext.regs.x24 = (uint64_t)uc->uc_mcontext.regs[24];
    ext.regs.x25 = (uint64_t)uc->uc_mcontext.regs[25];
    ext.regs.x26 = (uint64_t)uc->uc_mcontext.regs[26];
    ext.regs.x27 = (uint64_t)uc->uc_mcontext.regs[27];
    ext.regs.x28 = (uint64_t)uc->uc_mcontext.regs[28];
    ext.regs.x29 = (uint64_t)uc->uc_mcontext.regs[29];
    ext.regs.x30 = (uint64_t)uc->uc_mcontext.regs[30];
    ext.trap_rip  = (uint64_t)uc->uc_mcontext.pc;
    ext.child_rsp = child_stack ? (uint64_t)child_stack
                                : (uint64_t)uc->uc_mcontext.sp;
#endif

    /* Futex: CLONE_VM without CLONE_VFORK means shared address space, parent
     * not blocked by kernel — need futex to prevent save_ext reuse before
     * child is done reading it. */
    uint32_t futex_word = 0;
    ext.futex_ptr = (uint64_t)&futex_word;

    /* Allocate per-thread sigaltstack (same as clone3 thread path). */
    long mm = uwg_syscall6(SYS_mmap, 0, UWG_SIGALTSTACK_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mm < 0) goto fallback;
    ext.ss_sp    = (uint64_t)mm;
    ext.ss_flags = 0;
    ext._ss_pad  = 0;
    ext.ss_size  = UWG_SIGALTSTACK_SIZE;
    ext.ss_ptr   = (uint64_t)&ext.ss_sp;

    /* SYS_clone with CLONE_SIGHAND shares the sigaction table — never clear
     * handlers from the child (would reset parent's handlers too). */
    ext.clear_sighandlers = 0;

    return uwg_clone_asm_gate((long)&ext, a1, a2, a3, a4, a5);

fallback:
    return uwg_passthrough_syscall5(SYS_clone, a1, a2, a3, a4, a5);
}
#endif /* __x86_64__ || __aarch64__ */
