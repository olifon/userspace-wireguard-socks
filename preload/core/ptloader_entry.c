/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * ptloader_entry.c — entry point for uwgptloader.so when loaded by the
 * Linux kernel as a PT_INTERP interpreter for a patched static binary.
 *
 * Execution flow:
 *   1. Assembly stub (uwg_ptloader_entry): saves initial_sp, calls
 *      uwg_ptloader_start(initial_sp).
 *   2. uwg_ptloader_start (C, no globals): finds AT_BASE from auxv,
 *      applies own RELATIVE relocations via uwg_apply_own_relocations(base),
 *      then calls uwg_ptloader_run(initial_sp).
 *   3. uwg_ptloader_run: reads the .uwgcfg global (now safe after relocs),
 *      patches AT_PHDR/AT_PHNUM in the auxv stack, re-arms CLOEXEC on
 *      cfg.interp_fd, calls uwg_core_init(), then jumps to AT_ENTRY.
 *   4. Assembly stub: restores initial_sp (as stack pointer) and jumps to
 *      the return value of uwg_ptloader_start (= AT_ENTRY).
 *
 * Self-relocation rationale:
 *   When the kernel loads a PT_INTERP interpreter, it maps the interpreter's
 *   PT_LOAD segments but does NOT apply its RELATIVE relocations — that is
 *   the interpreter's own job (normal dynamic linkers do this in their
 *   bootstrap stub). Our freestanding .so build may have RELATIVE relocations
 *   for initialized pointer-valued globals (e.g. function-pointer tables).
 *   We apply them with a minimal bootstrapper before touching any C global.
 *
 * AT_PHDR kernel behaviour:
 *   Linux fs/binfmt_elf.c only sets AT_PHDR when e_phoff falls inside a
 *   PT_LOAD segment. Our patched binary's e_phoff points past all PT_LOAD
 *   segments (appended at EOF), so AT_PHDR arrives as 0 (non-PIE) or
 *   AT_BASE (PIE — the ELF header address, not the phdr table). We fix
 *   both cases from the cfg struct before jumping to AT_ENTRY.
 */

#include <elf.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "ptloader_cfg.h"
#include "syscall.h"
#include "dispatch.h"

#ifndef F_SETFD
#  define F_SETFD    2
#endif
#ifndef FD_CLOEXEC
#  define FD_CLOEXEC 1
#endif

/* The .uwgcfg section: Go patcher scans the ptloader binary for
 * UWG_PTLOADER_MAGIC to locate this struct, then writes the per-exec
 * values before exec'ing the patched binary. After uwg_apply_own_relocations
 * runs, this global is accessible at its correct VMA. */
static struct uwg_ptloader_cfg
    __attribute__((section(".uwgcfg"), used, aligned(8)))
    uwg_ptloader_cfg_data = {
    .magic = UWG_PTLOADER_MAGIC,
    /* remaining fields zeroed; filled in by Go patcher */
};

/* ------------------------------------------------------------------ */
/* Step 2a: apply RELATIVE relocations to self.                        */
/* Called before any global variable access. Uses NO globals.          */
/* ------------------------------------------------------------------ */

static void uwg_apply_own_relocations(unsigned long base) {
    if (!base) return;

    /* Our own ELF header is at load base. */
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)base;
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(base + ehdr->e_phoff);

    /* Find PT_DYNAMIC. */
    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < (int)ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(base + phdrs[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return;

    /* Scan dynamic section for DT_RELA and DT_RELASZ. */
    const Elf64_Rela *rela = NULL;
    unsigned long relasz = 0;
    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_RELA)
            rela = (const Elf64_Rela *)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_RELASZ)
            relasz = d->d_un.d_val;
    }
    if (!rela || relasz == 0) return;

    unsigned long nrela = relasz / sizeof(Elf64_Rela);
    for (unsigned long i = 0; i < nrela; i++) {
#if defined(__x86_64__)
        if (ELF64_R_TYPE(rela[i].r_info) == R_X86_64_RELATIVE) {
            Elf64_Addr *target = (Elf64_Addr *)(base + rela[i].r_offset);
            *target = base + (unsigned long)rela[i].r_addend;
        }
#elif defined(__aarch64__)
        if (ELF64_R_TYPE(rela[i].r_info) == R_AARCH64_RELATIVE) {
            Elf64_Addr *target = (Elf64_Addr *)(base + rela[i].r_offset);
            *target = base + (unsigned long)rela[i].r_addend;
        }
#endif
    }
}

/* ------------------------------------------------------------------ */
/* Step 2b: pre-relocation bootstrap.                                  */
/* NO global variables accessed before uwg_apply_own_relocations.     */
/* ------------------------------------------------------------------ */

/* Returns AT_ENTRY (main program entry point). */
static unsigned long uwg_ptloader_run(void *initial_sp);

/* Called by assembly entry with initial_sp = value of sp at kernel entry. */
__attribute__((noinline))
unsigned long uwg_ptloader_start(void *initial_sp) {
    /* Parse auxv from the initial stack to find AT_BASE. */
    long *sp   = (long *)initial_sp;
    long  argc = *sp;
    /* argv[] immediately follows argc; then NULL; then envp[]; then NULL;
     * then the auxiliary vector {AT_type, AT_val}... pairs. */
    long **argv_start = (long **)(sp + 1);
    /* Skip argv (argc entries + NULL). */
    long **ep = argv_start + argc + 1;
    /* Skip envp (variable length; walk until NULL). */
    while (*ep) ep++;
    ep++; /* past the NULL terminator */

    /* ep now points to the start of the auxv. */
    long *av = (long *)ep;

    unsigned long base = 0;
    for (long *a = av; a[0] != AT_NULL; a += 2) {
        if (a[0] == AT_BASE) {
            base = (unsigned long)a[1];
            break;
        }
    }

    /* Apply own RELATIVE relocations so globals are accessible. */
    uwg_apply_own_relocations(base);

    /* Now safe to call normal C code that touches globals. */
    return uwg_ptloader_run(initial_sp);
}

/* ------------------------------------------------------------------ */
/* Step 3: main ptloader logic (after relocations applied).           */
/* ------------------------------------------------------------------ */

static unsigned long uwg_ptloader_run(void *initial_sp) {
    long *sp   = (long *)initial_sp;
    long  argc = *sp;
    long **ep  = (long **)(sp + 1) + argc + 1;
    while (*ep) ep++;
    ep++;
    long *av = (long *)ep;

    unsigned long at_entry = 0;
    unsigned long at_base  = 0;
    long         *at_phdr_ptr  = NULL;
    long         *at_phnum_ptr = NULL;

    for (long *a = av; a[0] != AT_NULL; a += 2) {
        switch (a[0]) {
        case AT_ENTRY: at_entry       = (unsigned long)a[1]; break;
        case AT_BASE:  at_base        = (unsigned long)a[1]; break;
        case AT_PHDR:  at_phdr_ptr    = &a[1]; break;
        case AT_PHNUM: at_phnum_ptr   = &a[1]; break;
        }
    }

    /* Compute correct AT_PHDR from the cfg struct.
     *
     * correct_AT_PHDR = phdr_base_vma + original_e_phoff + load_bias
     *
     * where:
     *   phdr_base_vma = (p_vaddr - p_offset) of the PT_LOAD containing
     *                   the original e_phoff. Stored in cfg by Go patcher.
     *     - For ET_EXEC (non-PIE): typically 0x400000 (no ASLR).
     *     - For ET_DYN  (PIE):     typically 0 (first PT_LOAD at p_vaddr=0).
     *
     *   load_bias = ASLR shift applied to the main binary's load address.
     *     - For ET_EXEC: 0  (AT_ENTRY == e_entry, no ASLR).
     *     - For ET_DYN:  AT_ENTRY - e_entry_in_file.
     *
     * Our patched binary moved e_phoff to EOF (not within any PT_LOAD),
     * so the kernel could not set AT_PHDR; we fix it here.
     */
    if (uwg_ptloader_cfg_data.magic == UWG_PTLOADER_MAGIC) {
        unsigned long load_bias = 0;
        if (uwg_ptloader_cfg_data.e_type_is_pie && at_entry) {
            load_bias = at_entry - uwg_ptloader_cfg_data.e_entry_in_file;
        }
        unsigned long correct_phdr =
            uwg_ptloader_cfg_data.phdr_base_vma +
            uwg_ptloader_cfg_data.original_e_phoff +
            load_bias;
        if (at_phdr_ptr)  *at_phdr_ptr  = (long)correct_phdr;
        if (at_phnum_ptr) *at_phnum_ptr = (long)uwg_ptloader_cfg_data.original_e_phnum;

        /* Re-arm CLOEXEC on interp_fd: the kernel un-CLOEXEC'd it so
         * the interpreter could be loaded; we re-arm it so it doesn't
         * leak to unrelated child processes. */
        int ifd = uwg_ptloader_cfg_data.interp_fd;
        if (ifd >= 0) {
            uwg_syscall3(SYS_fcntl, ifd, F_SETFD, FD_CLOEXEC);
            /* Store for re-exec detection in execve_docker.c. */
            uwg_ptloader_my_fd = ifd;
        }
    }
    (void)at_base; /* used implicitly via uwg_apply_own_relocations earlier */

    /* Set environ for uwg_core_init to read UWGS_* env vars. */
    extern char **uwg_environ;
    /* envp follows argv (ep currently points at auxv, rewind to envp). */
    uwg_environ = (char **)((long **)(sp + 1) + argc + 1);

    uwg_ptloader_docker_init(); /* read UWGS_PTLOADER_* env vars */
    uwg_core_init();

    return at_entry;
}

/* ------------------------------------------------------------------ */
/* Step 1: assembly entry point.                                       */
/* Called by the kernel with sp pointing to the initial process stack. */
/* ------------------------------------------------------------------ */

#if defined(__x86_64__)
__asm__(
    ".global uwg_ptloader_entry\n"
    ".type uwg_ptloader_entry, @function\n"
    "uwg_ptloader_entry:\n"
    "  xorl %ebp, %ebp\n"          /* clear frame pointer (ABI) */
    "  movq %rsp, %rbx\n"          /* save initial_sp in callee-saved %rbx */
    "  andq $-16, %rsp\n"          /* align stack for the CALL below */
    "  movq %rbx, %rdi\n"          /* arg1 = initial_sp */
    "  callq uwg_ptloader_start\n" /* returns AT_ENTRY in %rax */
    "  movq %rbx, %rsp\n"          /* restore initial_sp as stack pointer */
    "  xorl %edx, %edx\n"          /* rdx=0: tell _start rtld_fini=NULL */
    "  jmpq *%rax\n"               /* jump to main binary entry */
);
#elif defined(__aarch64__)
__asm__(
    ".global uwg_ptloader_entry\n"
    ".type uwg_ptloader_entry, @function\n"
    "uwg_ptloader_entry:\n"
    "  mov x19, sp\n"              /* save initial_sp in callee-saved x19 */
    "  mov x0, sp\n"               /* arg0 = initial_sp */
    "  bl uwg_ptloader_start\n"    /* returns AT_ENTRY in x0 */
    "  mov x20, x0\n"              /* save AT_ENTRY; x0 must be 0 for _start */
    "  mov x0, #0\n"               /* x0=0: tell _start rtld_fini=NULL */
    "  mov sp, x19\n"              /* restore initial_sp as stack pointer */
    "  br x20\n"                   /* jump to main binary entry */
);
#else
#error "ptloader_entry.c: unsupported architecture"
#endif
