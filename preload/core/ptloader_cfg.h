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

/* Config written per-exec by the Go patcher. 48 bytes total.
 *
 * correct AT_PHDR = phdr_base_vma + original_e_phoff + load_bias
 *   where load_bias = AT_ENTRY - e_entry_in_file (for PIE/ET_DYN)
 *   and   load_bias = 0                          (for non-PIE/ET_EXEC)
 *
 * phdr_base_vma is (p_vaddr - p_offset) of the PT_LOAD that contains
 * the original e_phoff. For ET_EXEC this is typically 0x400000; for
 * ET_DYN (PIE) it is typically 0 (first PT_LOAD is at p_vaddr=0).
 */
struct uwg_ptloader_cfg {
    uint64_t magic;                /* sentinel: UWG_PTLOADER_MAGIC    */
    uint64_t original_e_phoff;     /* original phdr table file offset  */
    uint16_t original_e_phnum;     /* original phdr entry count        */
    uint16_t original_e_phentsize; /* sizeof(Elf64_Phdr)               */
    uint8_t  e_type_is_pie;        /* 1=ET_DYN, 0=ET_EXEC             */
    uint8_t  _pad0[3];             /* padding to align e_entry_in_file */
    uint64_t e_entry_in_file;      /* e_entry (for PIE load_bias calc) */
    uint64_t phdr_base_vma;        /* (p_vaddr-p_offset) of PT_LOAD holding e_phoff */
    int32_t  interp_fd;            /* fd# of this ptloader memfd       */
    int32_t  _pad1;
};

#endif /* UWG_PTLOADER_CFG_H */
