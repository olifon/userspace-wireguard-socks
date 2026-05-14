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
 *      patches AT_PHDR/AT_PHNUM/AT_BASE in the auxv stack, re-arms CLOEXEC
 *      on cfg.interp_fd, calls uwg_core_init(), then jumps to AT_ENTRY.
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
 *
 * AT_BASE patching for static-PIE (ET_DYN) binaries:
 *   When PT_INTERP is present the kernel sets AT_BASE to the interpreter's
 *   (ptloader's) load base, not the main binary's.  Musl's _start_c uses
 *   AT_BASE to self-relocate: if AT_BASE != 0 it trusts that value as the
 *   load_bias and applies DT_RELA relocations with it.  If the value is
 *   wrong (it gets ptloader's base instead of the main binary's), all global
 *   pointer fixups land at garbage addresses → SIGSEGV on first dereference.
 *
 *   The correct fix is to force AT_BASE back to 0.  Musl's AT_BASE=0 path
 *   uses AT_PHDR to find the main binary's program headers, computes the
 *   actual load_bias from there, and applies DT_RELA correctly.  We already
 *   patch AT_PHDR to the correct phdr table address (cfg.phdr_base_vma +
 *   cfg.original_e_phoff + load_bias), so the AT_BASE=0 path gets a valid
 *   AT_PHDR and succeeds.
 *
 *   ET_EXEC (non-PIE) binaries are unaffected: their startup code does not
 *   use AT_BASE for self-relocation since all addresses are absolute.
 */

#include <elf.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "ptloader_cfg.h"
#include "syscall.h"
#include "dispatch.h"

#ifndef O_RDONLY
#  define O_RDONLY   0
#endif
#ifndef O_CLOEXEC
#  define O_CLOEXEC  0x80000
#endif
#ifndef AT_FDCWD
#  define AT_FDCWD   (-100)
#endif
#ifndef F_SETFD
#  define F_SETFD    2
#endif
#ifndef FD_CLOEXEC
#  define FD_CLOEXEC 1
#endif
#ifndef PROT_READ
#  define PROT_READ  1
#endif
#ifndef PROT_WRITE
#  define PROT_WRITE 2
#endif
#ifndef PROT_EXEC
#  define PROT_EXEC  4
#endif
#ifndef PROT_NONE
#  define PROT_NONE  0
#endif
#ifndef MAP_PRIVATE
#  define MAP_PRIVATE    0x2
#endif
#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS  0x20
#endif
#ifndef MAP_FIXED
#  define MAP_FIXED      0x10
#endif
#ifndef PF_R
#  define PF_R 4
#endif
#ifndef PF_W
#  define PF_W 2
#endif
#ifndef PF_X
#  define PF_X 1
#endif
#ifndef SIG_UNBLOCK
#  define SIG_UNBLOCK 1
#endif
#ifndef SIGSYS
#  define SIGSYS 31
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
/* ELF loader: map an ET_DYN binary (real ld.so) into memory.         */
/* Used in dynamic mode to hand off to the original interpreter after  */
/* uwg_core_init() has installed the SIGSYS handler.                  */
/* ------------------------------------------------------------------ */

static long uwg_ptl_pread(int fd, long off, void *buf, long len) {
    long done = 0;
    char *p = (char *)buf;
    while (done < len) {
        long r = uwg_syscall4(SYS_pread64, fd, (long)(p + done), len - done, off + done);
        if (r <= 0) return r == 0 ? -5 : r;
        done += r;
    }
    return 0;
}

/* Map an ET_DYN ELF at an OS-chosen base.  Returns load_base (the
 * virtual address at which p_vaddr=0 maps), or 0 on error.
 * *out_entry is set to load_base + ehdr.e_entry. */
static unsigned long uwg_load_dyn_elf(const char *path, unsigned long *out_entry) {
    long fd_l = uwg_syscall4(SYS_openat, AT_FDCWD, (long)path,
                              (long)(O_RDONLY | O_CLOEXEC), 0);
    if (fd_l < 0) return 0;
    int fd = (int)fd_l;

    Elf64_Ehdr eh;
    if (uwg_ptl_pread(fd, 0, &eh, sizeof(eh)) < 0) goto fail;
    if (eh.e_type != ET_DYN || eh.e_phentsize < sizeof(Elf64_Phdr) ||
        eh.e_phnum == 0 || eh.e_phnum > 64) goto fail;

    /* Find virtual address range needed across all PT_LOADs. */
    unsigned long vmin = ~0UL, vmax = 0;
    Elf64_Phdr ph;
    for (int i = 0; i < (int)eh.e_phnum; i++) {
        long phoff = (long)(eh.e_phoff + (unsigned)i * eh.e_phentsize);
        if (uwg_ptl_pread(fd, phoff, &ph, sizeof(ph)) < 0) goto fail;
        if (ph.p_type != PT_LOAD) continue;
        if ((unsigned long)ph.p_vaddr < vmin) vmin = (unsigned long)ph.p_vaddr;
        unsigned long end = (unsigned long)ph.p_vaddr +
                            (unsigned long)ph.p_memsz;
        if (end > vmax) vmax = end;
    }
    if (vmin == ~0UL) goto fail;

    /* Round vmax to page boundary. */
    vmax = (vmax + 0xfffUL) & ~0xfffUL;

    /* Reserve the entire range to get a contiguous base. */
    long range = uwg_syscall6(SYS_mmap, 0, (long)(vmax - vmin),
                               PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (range < 0) goto fail;
    unsigned long base = (unsigned long)range - vmin;

    /* Map each PT_LOAD over the reservation. */
    for (int i = 0; i < (int)eh.e_phnum; i++) {
        long phoff = (long)(eh.e_phoff + (unsigned)i * eh.e_phentsize);
        if (uwg_ptl_pread(fd, phoff, &ph, sizeof(ph)) < 0) {
            uwg_syscall2(SYS_munmap, range, (long)(vmax - vmin));
            goto fail;
        }
        if (ph.p_type != PT_LOAD) continue;

        int prot = 0;
        if (ph.p_flags & PF_R) prot |= PROT_READ;
        if (ph.p_flags & PF_W) prot |= PROT_WRITE;
        if (ph.p_flags & PF_X) prot |= PROT_EXEC;

        /* Page-align the file-backed portion. */
        unsigned long va_pg  = (unsigned long)ph.p_vaddr & ~0xfffUL;
        unsigned long off_pg = (unsigned long)ph.p_offset & ~0xfffUL;
        unsigned long filesz = (unsigned long)ph.p_filesz +
                               ((unsigned long)ph.p_vaddr - va_pg);

        if (filesz > 0) {
            long r = uwg_syscall6(SYS_mmap,
                                   (long)(base + va_pg), (long)filesz,
                                   prot, MAP_PRIVATE | MAP_FIXED,
                                   fd, (long)off_pg);
            if (r < 0) {
                uwg_syscall2(SYS_munmap, range, (long)(vmax - vmin));
                goto fail;
            }
        }

        /* Anonymous pages for BSS (p_memsz > p_filesz). */
        if (ph.p_memsz > ph.p_filesz) {
            unsigned long bss_start = base + (unsigned long)ph.p_vaddr +
                                      (unsigned long)ph.p_filesz;
            unsigned long bss_end   = base + (unsigned long)ph.p_vaddr +
                                      (unsigned long)ph.p_memsz;
            unsigned long bss_pg    = (bss_start + 0xfffUL) & ~0xfffUL;
            if (bss_pg < bss_end) {
                uwg_syscall6(SYS_mmap, (long)bss_pg, (long)(bss_end - bss_pg),
                              prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                              -1, 0);
            }
        }
    }

    if (out_entry) *out_entry = base + (unsigned long)eh.e_entry;
    uwg_syscall1(SYS_close, fd);
    return base;

fail:
    uwg_syscall1(SYS_close, fd);
    return 0;
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
    long         *at_base_ptr  = NULL;
    long         *at_phdr_ptr  = NULL;
    long         *at_phnum_ptr = NULL;

    for (long *a = av; a[0] != AT_NULL; a += 2) {
        switch (a[0]) {
        case AT_ENTRY: at_entry       = (unsigned long)a[1]; break;
        case AT_BASE:  at_base_ptr    = &a[1]; break;
        case AT_PHDR:  at_phdr_ptr    = &a[1]; break;
        case AT_PHNUM: at_phnum_ptr   = &a[1]; break;
        }
    }

    /* Set environ so uwg_core_init can read UWGS_* env vars. */
    extern char **uwg_environ;
    uwg_environ = (char **)((long **)(sp + 1) + argc + 1);

    if (uwg_ptloader_cfg_data.magic == UWG_PTLOADER_MAGIC) {
        /* Re-arm CLOEXEC on interp_fd in all modes. */
        int ifd = uwg_ptloader_cfg_data.interp_fd;
        if (ifd >= 0) {
            uwg_syscall3(SYS_fcntl, ifd, F_SETFD, FD_CLOEXEC);
            uwg_ptloader_my_fd = ifd;
        }

        if (uwg_ptloader_cfg_data.is_dynamic) {
            /* Dynamic mode: install SIGSYS handler NOW, before ld.so loads
             * any DT_NEEDED library.  Then map the real ld.so and jump to it.
             * AT_PHDR/AT_PHNUM/AT_ENTRY are already correct (kernel set them
             * from the on-disk phdrs which we didn't move).  Only AT_BASE
             * needs updating to the ld.so's load address so it can
             * self-relocate. */
            uwg_ptloader_docker_init();
            uwg_core_init();

            /* Unblock SIGSYS so queued BPF traps deliver to our handler
             * rather than SIG_DFL (it may have been blocked by the parent). */
            {
                unsigned long sigsys_bit = (unsigned long)1 << (SIGSYS - 1);
                uwg_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                             (long)&sigsys_bit, 0L, 8L);
            }

            unsigned long ldso_entry = 0;
            unsigned long ldso_base  = uwg_load_dyn_elf(
                uwg_ptloader_cfg_data.orig_interp, &ldso_entry);

            if (ldso_base == 0) {
                /* Cannot load the real ld.so — abort. */
                uwg_syscall1(SYS_exit_group, 127);
                __builtin_unreachable();
            }

            /* Patch AT_BASE to ld.so's load base so ld.so can self-relocate. */
            if (at_base_ptr) *at_base_ptr = (long)ldso_base;

            return ldso_entry;
        }

        /* Static mode: patch AT_PHDR/AT_PHNUM/AT_BASE. */
        unsigned long load_bias = 0;
        if (uwg_ptloader_cfg_data.e_type_is_pie && at_entry) {
            load_bias = at_entry - uwg_ptloader_cfg_data.e_entry_in_file;
        }

        /* Patch AT_PHDR: correct_phdr = phdr_base_vma + original_e_phoff +
         * load_bias.  The kernel left AT_PHDR wrong because we moved e_phoff
         * past all PT_LOAD segments (appended at EOF). */
        unsigned long correct_phdr =
            uwg_ptloader_cfg_data.phdr_base_vma +
            uwg_ptloader_cfg_data.original_e_phoff +
            load_bias;
        if (at_phdr_ptr)  *at_phdr_ptr  = (long)correct_phdr;
        if (at_phnum_ptr) *at_phnum_ptr = (long)uwg_ptloader_cfg_data.original_e_phnum;

        /* Patch AT_BASE to 0 for static-PIE (ET_DYN) binaries.
         * See file-level comment for full rationale. */
        if (at_base_ptr && uwg_ptloader_cfg_data.e_type_is_pie)
            *at_base_ptr = 0;
    }

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
