/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * clone3 CLONE_CLEAR_SIGHAND trampoline — C setup layer.
 *
 * When the SIGSYS handler catches SYS_clone3 in docker mode, instead of
 * simply stripping CLONE_CLEAR_SIGHAND (which leaves all parent signal
 * handlers inherited in the child), this path:
 *
 *   1. Strips CLONE_CLEAR_SIGHAND so the child inherits our SIGSYS handler.
 *   2. Passes the actual clone3 to the kernel via the assembly gate.
 *   3. In the child (via the assembly gate): clears all signal handlers
 *      EXCEPT SIGSYS using passthrough rt_sigaction, signals the parent's
 *      futex if needed, restores the exact trap-point register state, and
 *      jumps to the instruction after the original clone3 in the caller's
 *      code — indistinguishable from an unintercepted clone3 minus the
 *      SIGSYS handler being preserved.
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
#include <sys/syscall.h>
#include <sys/ucontext.h>

#include "syscall.h"
#include "dispatch.h"

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
 *   save_area_ptr   : pointer to uwg_clone3_save on the signal stack
 *
 * R12/X19 = trap_rip/trap_pc  (loaded from save_area.trap_rip)
 * R13/X20 = child_rsp/child_sp (loaded from save_area.child_rsp)
 * R14/X21 = futex_ptr          (loaded from save_area.futex_ptr)
 * R15/X22 = save_area_ptr      (rdx/x2 directly)
 *
 * The extra fields (trap_rip, child_rsp, futex_ptr) are appended after
 * the GPR fields in the save_area struct and accessed by the assembly.
 */

/* Extended save area: the GPR struct + three coordination fields. */
struct uwg_clone3_save_ext {
    struct uwg_clone3_save regs;
    uint64_t trap_rip;    /* jump target for child */
    uint64_t child_rsp;   /* RSP/SP to set in child */
    uint64_t futex_ptr;   /* &futex_word, or 0 if no wait needed */
};

/* Declared in clone3_asm.S */
extern long uwg_clone3_asm_gate(long clone_args_ptr,
                                 long clone_args_size,
                                 long save_area_ext_ptr);

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

    /* Caller (kernel) guarantees a2 >= sizeof(flags). Only access fields
     * within the provided size. */
    if (!ca || size < (long)sizeof(uint64_t))
        goto fallback;

    /* Only intercept if the flag is actually set. */
    if (!(ca->flags & CLONE_CLEAR_SIGHAND))
        goto fallback;

    /* Strip the flag: child will inherit our SIGSYS handler. The assembly
     * gate then clears all other handlers in the child explicitly. */
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

    return uwg_clone3_asm_gate(a1, a2, (long)&ext);

fallback:
    /* Caller didn't set CLONE_CLEAR_SIGHAND or struct too small — original
     * simple path: just pass through. */
    return uwg_passthrough_syscall2(SYS_clone3, a1, a2);
}

#endif /* SYS_clone3 */
