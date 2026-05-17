/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Shared config struct written by the Go patcher into the ptloader
 * memfd at the .uwgcfg section file offset before exec'ing the
 * patched binary. The ptloader entry reads it at startup via the
 * global symbol (after applying own relocations).
 */

#ifndef UWG_PTLOADER_CFG_H
#define UWG_PTLOADER_CFG_H

#include <stdint.h>

/* Sentinel value at cfg.magic. The Go patcher scans the ptloader
 * binary for this magic to locate the .uwgcfg section file offset. */
#define UWG_PTLOADER_MAGIC 0x5557474346470001ULL

/* Config written per-exec. First 48 bytes written by the Go patcher for
 * static targets; C-side execve_docker.c fills the full struct for dynamic
 * targets (is_dynamic=1).
 *
 * Static mode (is_dynamic=0):
 *   correct AT_PHDR = phdr_base_vma + original_e_phoff + load_bias
 *   where load_bias = AT_ENTRY - e_entry_in_file  (PIE/ET_DYN)
 *   and   load_bias = 0                            (non-PIE/ET_EXEC)
 *   phdr_base_vma is (p_vaddr - p_offset) of the PT_LOAD containing
 *   e_phoff. ET_EXEC ≈ 0x400000; ET_DYN (PIE) ≈ 0.
 *
 * Dynamic mode (is_dynamic=1):
 *   ptloader installs the SIGSYS handler before ld.so loads any
 *   DT_NEEDED library, then maps the real ld.so from orig_interp and
 *   jumps to it. AT_PHDR/AT_PHNUM are already correct (kernel set them);
 *   only AT_BASE needs to be patched to the ld.so load base.
 */
struct uwg_ptloader_cfg {
    uint64_t magic;                /* 0:8   sentinel: UWG_PTLOADER_MAGIC    */
    uint64_t original_e_phoff;     /* 8:16  original phdr table file offset  */
    uint16_t original_e_phnum;     /* 16:18 original phdr entry count        */
    uint16_t original_e_phentsize; /* 18:20 sizeof(Elf64_Phdr)               */
    uint8_t  e_type_is_pie;        /* 20    1=ET_DYN, 0=ET_EXEC             */
    uint8_t  is_dynamic;           /* 21    1=dynamic-binary prefix mode     */
    uint8_t  _pad0[2];             /* 22:24 padding                          */
    uint64_t e_entry_in_file;      /* 24:32 e_entry (for PIE load_bias calc) */
    uint64_t phdr_base_vma;        /* 32:40 (p_vaddr-p_offset) of PT_LOAD holding e_phoff */
    int32_t  interp_fd;            /* 40:44 fd# of this ptloader memfd       */
    int32_t  _pad1;                /* 44:48 */
    char     orig_interp[256];     /* 48:304  original ld.so path (dynamic mode) */
    char     orig_exec_path[256];  /* 304:560 original execve pathname — used to
                                    * patch AT_EXECFN so ld.so resolves $ORIGIN
                                    * correctly when exec'd via a memfd path */
};

#endif /* UWG_PTLOADER_CFG_H */
