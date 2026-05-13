/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * clone3 CLONE_CLEAR_SIGHAND assembly gate.
 *
 * Implements uwg_clone3_asm_gate(clone_args_ptr, clone_args_size,
 * save_area_ext_ptr) for x86_64 and aarch64.
 *
 * See clone3_trampoline.c for the full design description and struct
 * layouts. This file must stay in sync with the field offsets there.
 *
 * ============================================================
 * SAFETY CONSTRAINTS — read before changing this file.
 * ============================================================
 *
 *  1. Async-signal-safe: runs inside the SIGSYS handler.  No stack
 *     frame switching, no libc, no malloc.
 *  2. x86_64 `syscall` clobbers rcx (← rip) and r11 (← rflags).
 *     We use r12..r15 as bookmarks; they survive the syscall.
 *     r11 is used as the final jump register AFTER all syscalls.
 *  3. aarch64 `svc #0` only modifies x0 (return value).  x5
 *     (bypass_secret) and x19..x22 (bookmarks) survive each svc.
 *  4. The save_area lives on the parent's sigaltstack.  The child
 *     must complete ALL reads from save_area BEFORE the parent can
 *     return from the SIGSYS handler.  The futex (when needed)
 *     serialises this: parent waits, child signals, then restores.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <sys/syscall.h>

/* Fallback syscall numbers — sys/syscall.h provides these on modern
 * Linux, but older sysroots sometimes omit them. */
#ifndef SYS_clone3
# if defined(__x86_64__) || defined(__aarch64__)
#  define SYS_clone3 435
# endif
#endif
#ifndef SYS_rt_sigaction
# if defined(__x86_64__)
#  define SYS_rt_sigaction 13
# elif defined(__aarch64__)
#  define SYS_rt_sigaction 134
# endif
#endif
#ifndef SYS_futex
# if defined(__x86_64__)
#  define SYS_futex 202
# elif defined(__aarch64__)
#  define SYS_futex 98
# endif
#endif
/* SIGSYS = 31 on Linux (all architectures). */
#ifndef SIGSYS
# define SIGSYS 31
#endif

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

#if defined(SYS_clone3) && (defined(__x86_64__) || defined(__aarch64__))

/* ================================================================
 * x86_64
 * ================================================================ */
#if defined(__x86_64__)

/*
 * uwg_clone3_save field offsets (x86_64, 12 GPRs × 8 = 0x60 bytes).
 * Must match clone3_trampoline.c exactly.
 */
#define X64_OFF_RBX   0x00
#define X64_OFF_RDX   0x08
#define X64_OFF_RSI   0x10
#define X64_OFF_RDI   0x18
#define X64_OFF_RBP   0x20
#define X64_OFF_R8    0x28
#define X64_OFF_R9    0x30
#define X64_OFF_R10   0x38
#define X64_OFF_R12   0x40
#define X64_OFF_R13   0x48
#define X64_OFF_R14   0x50
#define X64_OFF_R15   0x58
/* uwg_clone3_save_ext coordination fields */
#define X64_OFF_TRAP_RIP  0x60
#define X64_OFF_CHILD_RSP 0x68
#define X64_OFF_FUTEX_PTR 0x70

    .text
    .globl uwg_clone3_asm_gate
    .type  uwg_clone3_asm_gate, @function
uwg_clone3_asm_gate:
    /*
     * C args on entry:
     *   rdi = clone_args_ptr
     *   rsi = clone_args_size
     *   rdx = save_area_ext_ptr
     *
     * Callee-saved registers used as bookmarks (survive syscall):
     *   r15 = save_area_ext_ptr
     *   r14 = futex_ptr          (0 if no futex needed)
     *   r13 = child_rsp
     *   r12 = trap_rip
     *   rbp = &uwg_clone3_dfl_action    (child clear loop)
     *   rbx = signal counter (child) / child PID (parent futex wait)
     */
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    /* r15 = save_area_ext_ptr (C arg 3, in rdx) */
    movq  %rdx, %r15

    /* Load coordination fields from save_area_ext */
    movq  X64_OFF_TRAP_RIP(%r15),  %r12   /* r12 = trap_rip */
    movq  X64_OFF_CHILD_RSP(%r15), %r13   /* r13 = child_rsp */
    movq  X64_OFF_FUTEX_PTR(%r15), %r14   /* r14 = futex_ptr */

    /* Load bypass_secret into r9 (syscall arg6).
     * GOT-indirect: one load gives &bypass_secret, second load dereferences.
     * r9 is NOT clobbered by the syscall instruction (only rcx and r11
     * are), so one load suffices for the passthrough clone3 AND the
     * child's rt_sigaction clear loop. */
    movq  uwg_bypass_secret@GOTPCREL(%rip), %r9
    movq  (%r9), %r9

    /* Passthrough clone3 with bypass_secret in r9 — the BPF prologue
     * ALLOWs it before reaching any TRAP rule.
     * rdi, rsi already hold the correct clone3 args. */
    xorl  %edx, %edx
    xorl  %r10d, %r10d
    xorl  %r8d, %r8d
    movl  $SYS_clone3, %eax
    syscall
    /* syscall clobbers rcx (← rip) and r11 (← rflags).
     * r9, r12..r15, rbx, rbp are all preserved. */

    testq %rax, %rax
    jnz   .Lx64_parent

    /* ==============================================================
     * CHILD PATH   (rax = 0)
     * r12 = trap_rip   r13 = child_rsp   r14 = futex_ptr
     * r15 = save_area_ext_ptr   r9 = bypass_secret
     * ==============================================================
     *
     * Clear signal handlers 1..64 except SIGSYS (31) via passthrough
     * rt_sigaction.  r9 (bypass_secret) survives every syscall.
     * rbp = &uwg_clone3_dfl_action,  rbx = signal counter.
     */
    movq  uwg_clone3_dfl_action@GOTPCREL(%rip), %rbp
    movl  $1, %ebx

.Lx64_clr:
    cmpl  $SIGSYS, %ebx
    je    .Lx64_clr_skip

    /* rt_sigaction(sig, &dfl_action, NULL, 8) */
    movl  %ebx, %edi
    movq  %rbp, %rsi
    xorl  %edx, %edx          /* old_act = NULL */
    movl  $8, %r10d           /* sigset_size = 8 */
    xorl  %r8d, %r8d
    /* r9 = bypass_secret (preserved) */
    movl  $SYS_rt_sigaction, %eax
    syscall
    /* r9, r12..r15, rbx, rbp preserved */

.Lx64_clr_skip:
    addl  $1, %ebx
    cmpl  $65, %ebx
    jne   .Lx64_clr

    /* All handlers cleared except SIGSYS.  Now: set RSP, signal futex,
     * restore GPRs, jump to trap_rip. */

    /* Step 1: RSP = child_rsp */
    movq  %r13, %rsp

    /* Step 2: signal futex if r14 != 0 (CLONE_VM + no CLONE_VFORK case) */
    testq %r14, %r14
    jz    .Lx64_child_nofutex

    movl  $1, (%r14)               /* *futex_ptr = 1 */
    movq  %r14, %rdi
    movl  $FUTEX_WAKE, %esi
    movl  $1, %edx
    xorl  %r10d, %r10d
    xorl  %r8d, %r8d
    xorl  %r9d, %r9d              /* futex does not need bypass */
    movl  $SYS_futex, %eax
    syscall
    /* r11 clobbered — trap_rip is safe in r12 */

.Lx64_child_nofutex:
    /* Step 3: r11 = trap_rip AFTER the last syscall that clobbers r11 */
    movq  %r12, %r11

    /* Step 4: restore all saved GPRs from save_area (r15 = base).
     * r15 self-destructs on the last load. r11 and rcx are excluded
     * from save_area (clobbered by syscall instruction; callers do not
     * rely on their post-syscall values). */
    movq  X64_OFF_RBX(%r15), %rbx
    movq  X64_OFF_RDX(%r15), %rdx
    movq  X64_OFF_RSI(%r15), %rsi
    movq  X64_OFF_RDI(%r15), %rdi
    movq  X64_OFF_RBP(%r15), %rbp
    movq  X64_OFF_R8 (%r15), %r8
    movq  X64_OFF_R9 (%r15), %r9
    movq  X64_OFF_R10(%r15), %r10
    movq  X64_OFF_R12(%r15), %r12
    movq  X64_OFF_R13(%r15), %r13
    movq  X64_OFF_R14(%r15), %r14
    movq  X64_OFF_R15(%r15), %r15  /* r15 self-destructs */

    /* Step 5: rax = 0, jump to trap_rip via r11 */
    xorl  %eax, %eax
    jmpq  *%r11
    /* child never returns */

    /* ==============================================================
     * PARENT PATH  (rax = child PID or negative error)
     * ==============================================================
     */
.Lx64_parent:
    testq %r14, %r14
    jz    .Lx64_parent_done

    movq  %rax, %rbx               /* save child PID across wait loop */

.Lx64_futex_retry:
    movl  (%r14), %ecx
    testl %ecx, %ecx
    jnz   .Lx64_futex_done

    movq  %r14, %rdi
    xorl  %esi, %esi               /* FUTEX_WAIT = 0 */
    xorl  %edx, %edx               /* expected = 0 */
    xorl  %r10d, %r10d
    xorl  %r8d, %r8d
    xorl  %r9d, %r9d
    movl  $SYS_futex, %eax
    syscall
    /* -EWOULDBLOCK: child wrote 1 before wait → retry check
     * -EINTR: interrupted → retry   0: spurious → retry */
    jmp   .Lx64_futex_retry

.Lx64_futex_done:
    movq  %rbx, %rax               /* restore child PID */

.Lx64_parent_done:
    popq  %r15
    popq  %r14
    popq  %r13
    popq  %r12
    popq  %rbp
    popq  %rbx
    retq

    .size uwg_clone3_asm_gate, . - uwg_clone3_asm_gate

/* ================================================================
 * aarch64
 * ================================================================ */
#elif defined(__aarch64__)

/*
 * uwg_clone3_save_ext field offsets (aarch64).
 * GPR area: 29 registers × 8 = 232 = 0xE8 bytes.
 * Must match clone3_trampoline.c exactly.
 */
#define A64_OFF_TRAP_PC   0xE8
#define A64_OFF_CHILD_SP  0xF0
#define A64_OFF_FUTEX_PTR 0xF8

/*
 * Individual GPR offsets (for restore in child path).
 * x0 excluded (return value; child gets 0 explicitly).
 * x8 excluded (syscall number; reused as jump register in child).
 */
#define A64_OFF_X1   0x00
#define A64_OFF_X2   0x08
#define A64_OFF_X3   0x10
#define A64_OFF_X4   0x18
#define A64_OFF_X5   0x20
#define A64_OFF_X6   0x28
#define A64_OFF_X7   0x30
/* x8 absent — x9 immediately follows x7 in memory */
#define A64_OFF_X9   0x38
#define A64_OFF_X10  0x40
#define A64_OFF_X11  0x48
#define A64_OFF_X12  0x50
#define A64_OFF_X13  0x58
#define A64_OFF_X14  0x60
#define A64_OFF_X15  0x68
#define A64_OFF_X16  0x70
#define A64_OFF_X17  0x78
#define A64_OFF_X18  0x80
#define A64_OFF_X19  0x88
#define A64_OFF_X20  0x90
#define A64_OFF_X21  0x98
#define A64_OFF_X22  0xA0
#define A64_OFF_X23  0xA8
#define A64_OFF_X24  0xB0
#define A64_OFF_X25  0xB8
#define A64_OFF_X26  0xC0
#define A64_OFF_X27  0xC8
#define A64_OFF_X28  0xD0
#define A64_OFF_X29  0xD8
#define A64_OFF_X30  0xE0

    .text
    .globl uwg_clone3_asm_gate
    .type  uwg_clone3_asm_gate, %function
uwg_clone3_asm_gate:
    /*
     * C args on entry:
     *   x0 = clone_args_ptr
     *   x1 = clone_args_size
     *   x2 = save_area_ext_ptr
     *
     * aarch64 `svc #0` only clobbers x0 (return value); all other
     * registers survive, including x5 (bypass_secret bookmark).
     *
     * Callee-saved registers used as bookmarks:
     *   x22 = save_area_ext_ptr
     *   x21 = futex_ptr
     *   x20 = child_sp
     *   x19 = trap_pc
     *   x24 = &uwg_clone3_dfl_action   (child clear loop)
     *   x23 = signal counter           (child clear loop)
     */
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    stp   x27, x28, [sp, #-16]!
    stp   x25, x26, [sp, #-16]!
    stp   x23, x24, [sp, #-16]!
    stp   x21, x22, [sp, #-16]!
    stp   x19, x20, [sp, #-16]!

    /* x22 = save_area_ext_ptr (C arg 3, in x2) */
    mov   x22, x2

    /* Load coordination fields from save_area_ext */
    ldr   x19, [x22, #A64_OFF_TRAP_PC]    /* x19 = trap_pc */
    ldr   x20, [x22, #A64_OFF_CHILD_SP]   /* x20 = child_sp */
    ldr   x21, [x22, #A64_OFF_FUTEX_PTR]  /* x21 = futex_ptr */

    /* Load bypass_secret into x5 (syscall arg5) via GOT.
     * svc #0 does not modify x5, so one load covers both the
     * passthrough clone3 and the child's rt_sigaction clear loop. */
    adrp  x5, :got:uwg_bypass_secret
    ldr   x5, [x5, :got_lo12:uwg_bypass_secret]   /* x5 = &bypass_secret */
    ldr   x5, [x5]                                  /* x5 = bypass_secret value */

    /* Passthrough clone3:
     * x0 = clone_args_ptr (C arg 1, already set)
     * x1 = clone_args_size (C arg 2, already set)
     * x2..x4 = 0 (unused), x5 = bypass_secret, x8 = SYS_clone3 */
    mov   x2, xzr
    mov   x3, xzr
    mov   x4, xzr
    mov   x8, #SYS_clone3
    svc   #0
    /* x0 = result; x1..x30 (except x0) preserved by kernel */

    cbnz  x0, .La64_parent

    /* ==============================================================
     * CHILD PATH   (x0 = 0)
     * x19 = trap_pc   x20 = child_sp   x21 = futex_ptr
     * x22 = save_area_ext_ptr   x5 = bypass_secret
     * ==============================================================
     *
     * Clear signal handlers 1..64 except SIGSYS (31) via passthrough
     * rt_sigaction.  x5 (bypass_secret) survives each svc #0.
     * x24 = &uwg_clone3_dfl_action,  x23 = signal counter.
     */
    adrp  x24, :got:uwg_clone3_dfl_action
    ldr   x24, [x24, :got_lo12:uwg_clone3_dfl_action]   /* x24 = &dfl_action[0] */
    mov   x23, #1

.La64_clr:
    cmp   x23, #SIGSYS
    b.eq  .La64_clr_skip

    /* rt_sigaction(sig, &dfl_action, NULL, 8) */
    mov   x0, x23
    mov   x1, x24
    mov   x2, xzr             /* old_act = NULL */
    mov   x3, #8              /* sigset_size = 8 */
    mov   x4, xzr
    /* x5 = bypass_secret (preserved by svc) */
    mov   x8, #SYS_rt_sigaction
    svc   #0
    /* x0 = return value (ignored); x5, x23, x24 preserved */

.La64_clr_skip:
    add   x23, x23, #1
    cmp   x23, #65
    b.ne  .La64_clr

    /* All handlers cleared except SIGSYS. */

    /* Step 1: SP = child_sp (x20 bookmark, still valid) */
    mov   sp, x20

    /* Step 2: signal futex if x21 != 0 */
    cbz   x21, .La64_child_nofutex

    mov   w0, #1
    str   w0, [x21]                /* *futex_ptr = 1 */
    mov   x0, x21
    mov   x1, #FUTEX_WAKE
    mov   x2, #1
    mov   x3, xzr
    mov   x4, xzr
    mov   x5, xzr                  /* futex does not need bypass */
    mov   x8, #SYS_futex
    svc   #0

.La64_child_nofutex:
    /* Step 3: x8 = trap_pc (jump register, not in save_area).
     * Load AFTER futex so the futex svc cannot interfere.
     * x22 still points to save_area (not yet overwritten by restore). */
    ldr   x8, [x22, #A64_OFF_TRAP_PC]

    /* Step 4: copy save_area base to x0 — restoring x22 from save_area
     * in the loop below would overwrite the base pointer otherwise. */
    mov   x0, x22

    /* Step 5: restore all saved GPRs from save_area using x0 as base.
     * ldp x7,x9 and ldp x18,x19 pair across the missing x8/skipped gap
     * cleanly because the struct layout is contiguous in memory.
     * x8 is intentionally NOT restored (holds trap_pc for br below). */
    ldp   x1,  x2,  [x0, #A64_OFF_X1]
    ldp   x3,  x4,  [x0, #A64_OFF_X3]
    ldp   x5,  x6,  [x0, #A64_OFF_X5]
    ldp   x7,  x9,  [x0, #A64_OFF_X7]   /* x8 absent in struct */
    ldp   x10, x11, [x0, #A64_OFF_X10]
    ldp   x12, x13, [x0, #A64_OFF_X12]
    ldp   x14, x15, [x0, #A64_OFF_X14]
    ldp   x16, x17, [x0, #A64_OFF_X16]
    ldp   x18, x19, [x0, #A64_OFF_X18]  /* x19 bookmark → caller's x19 */
    ldp   x20, x21, [x0, #A64_OFF_X20]  /* bookmarks → caller's values */
    ldp   x22, x23, [x0, #A64_OFF_X22]  /* x22 base self-destructs */
    ldp   x24, x25, [x0, #A64_OFF_X24]
    ldp   x26, x27, [x0, #A64_OFF_X26]
    ldp   x28, x29, [x0, #A64_OFF_X28]
    ldr   x30,      [x0, #A64_OFF_X30]

    /* Step 6: x0 = 0 (child return value), jump to trap_pc */
    mov   x0, xzr
    br    x8
    /* child never returns */

    /* ==============================================================
     * PARENT PATH  (x0 = child PID or negative error)
     * ==============================================================
     */
.La64_parent:
    cbz   x21, .La64_parent_done

    mov   x19, x0                  /* save child PID */

.La64_futex_retry:
    ldr   w0, [x21]
    cbnz  w0, .La64_futex_done

    mov   x0, x21
    mov   x1, #FUTEX_WAIT
    mov   x2, xzr                  /* expected = 0 */
    mov   x3, xzr
    mov   x4, xzr
    mov   x5, xzr
    mov   x8, #SYS_futex
    svc   #0
    b     .La64_futex_retry

.La64_futex_done:
    mov   x0, x19                  /* restore child PID */

.La64_parent_done:
    ldp   x19, x20, [sp], #16
    ldp   x21, x22, [sp], #16
    ldp   x23, x24, [sp], #16
    ldp   x25, x26, [sp], #16
    ldp   x27, x28, [sp], #16
    ldp   x29, x30, [sp], #16
    ret

    .size uwg_clone3_asm_gate, . - uwg_clone3_asm_gate

#endif /* __x86_64__ / __aarch64__ */

#endif /* SYS_clone3 */

    .section .note.GNU-stack, "", @progbits
