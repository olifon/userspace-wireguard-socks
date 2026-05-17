/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * execve_docker.c — ELF PT_INTERP injection for systrap-docker mode.
 *
 * Intercepts execve/execveat when UWGS_SYSTRAP_DOCKER=1. Static binaries
 * (no PT_INTERP) are patched in-memory via two memfds:
 *
 *   ptl_fd: copy of the ptloader .so with the per-exec cfg struct written
 *           at ptloader_cfg_off. NOT O_CLOEXEC so the kernel can open it
 *           as the PT_INTERP interpreter.
 *
 *   bin_fd: copy of the original binary with the phdr table and a new
 *           PT_INTERP phdr appended at EOF, and the ELF header updated to
 *           point e_phoff at the appended table. O_CLOEXEC.
 *
 * The patched binary is exec'd via /proc/self/fd/<bin_fd>. The kernel loads
 * the ptloader via /proc/self/fd/<ptl_fd>; the ptloader installs systrap
 * and jumps to the original binary's entry point.
 *
 * Binaries with an existing PT_INTERP are passed through unchanged. The
 * re-exec case (static binary exec'ing itself via /proc/self/exe) is handled
 * by detecting our own ptloader fd path in the PT_INTERP field and clearing
 * CLOEXEC on that fd before the passthrough so the kernel can reopen it.
 *
 * ALL code here is async-signal-safe: no malloc, raw syscalls only,
 * IO buffers via mmap(MAP_ANONYMOUS), stack vars ≤ 512 bytes.
 */

#include <elf.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "ptloader_cfg.h"
#include "syscall.h"
#include "freestanding.h"

#ifndef O_RDONLY
#  define O_RDONLY   0
#endif
#ifndef O_CLOEXEC
#  define O_CLOEXEC  0x80000
#endif
#ifndef AT_FDCWD
#  define AT_FDCWD   (-100)
#endif
#ifndef F_GETFD
#  define F_GETFD    1
#endif
#ifndef F_SETFD
#  define F_SETFD    2
#endif
#ifndef FD_CLOEXEC
#  define FD_CLOEXEC 1
#endif
#ifndef SEEK_END
#  define SEEK_END   2
#endif
#ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 1U
#endif
#ifndef PF_R
#  define PF_R       4
#endif
#ifndef AT_EMPTY_PATH
#  define AT_EMPTY_PATH 0x1000
#endif
#ifndef SIG_BLOCK
#  define SIG_BLOCK   0
#endif
#ifndef SIG_UNBLOCK
#  define SIG_UNBLOCK 1
#endif
#ifndef SIGSYS
#  define SIGSYS 31
#endif

/* Max phdrs handled per binary. Static binaries have < 20; Go statics
 * up to ~30. 64 is a comfortable ceiling (64 * 56 = 3584 bytes). */
#define UWG_DOCKER_MAX_PHDRS 64

/* Work buffer layout: phdr storage + IO copy buffer. One mmap, both
 * regions live in it for the duration of the patching operation. */
#define UWG_DOCKER_PHDR_BUF  (UWG_DOCKER_MAX_PHDRS * (int)sizeof(Elf64_Phdr))
#define UWG_DOCKER_IO_BUF    (64 * 1024)
#define UWG_DOCKER_BUF_TOTAL (UWG_DOCKER_PHDR_BUF + UWG_DOCKER_IO_BUF)

/* ------------------------------------------------------------------ */
/* Module globals set by uwg_ptloader_docker_init() at core init time. */
/* ------------------------------------------------------------------ */

/* fd of the master ptloader memfd (non-CLOEXEC). Inherited across execs. */
static int  uwg_ptloader_master_fd = -1;
/* File offset of the .uwgcfg section inside the ptloader binary. */
static long uwg_ptloader_cfg_off   = -1;
/* Byte size of the ptloader binary. */
static long uwg_ptloader_size      = 0;
/* In-memory copy of ptloader binary. mmap'd at init time so injection
 * survives fork+close_fds (e.g. Python subprocess): anonymous mmaps are
 * not file-descriptors and are not closed by close_range/close_fds. */
static void *uwg_ptloader_buf = NULL;

/* fd of THIS process's ptloader memfd, set only by ptloader_entry.c
 * when the ptloader is running as PT_INTERP. Used to detect re-exec:
 * the ptloader re-arms CLOEXEC on this fd after loading; when the
 * wrapped binary exec's itself via /proc/self/exe we must temporarily
 * clear CLOEXEC so the kernel can re-open it as the interpreter. */
int uwg_ptloader_my_fd = -1;

/* ------------------------------------------------------------------ */
/* Helpers (all async-signal-safe)                                     */
/* ------------------------------------------------------------------ */

static int uwg_docker_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* Write "/proc/self/fd/<fd>" into buf. Returns path length (no NUL)
 * or -1 if buf is too small. */
static int uwg_make_proc_fd_path(int fd, char *buf, int bufsz) {
    const char pfx[] = "/proc/self/fd/";
    int plen = (int)(sizeof(pfx) - 1);
    if (bufsz <= plen + 1) return -1;
    for (int i = 0; i < plen; i++) buf[i] = pfx[i];
    /* Convert fd to decimal string. */
    char digits[12];
    int dlen = 0;
    int n = fd;
    if (n == 0) { digits[dlen++] = '0'; }
    while (n > 0) { digits[dlen++] = (char)('0' + n % 10); n /= 10; }
    if (plen + dlen + 1 > bufsz) return -1;
    for (int i = 0; i < dlen; i++) buf[plen + i] = digits[dlen - 1 - i];
    buf[plen + dlen] = '\0';
    return plen + dlen;
}

/* Return 1 if interp_path is "/proc/self/fd/<my_fd>". */
static int uwg_is_my_ptloader_path(const char *interp_path, int my_fd) {
    if (my_fd < 0) return 0;
    char expected[32];
    int elen = uwg_make_proc_fd_path(my_fd, expected, sizeof(expected));
    if (elen <= 0) return 0;
    const char *a = interp_path;
    const char *b = expected;
    while (*b && *a == *b) { a++; b++; }
    return (*b == '\0' && *a == '\0');
}

/* Read exactly len bytes from fd at offset off into buf.
 * Returns 0 on success or negative -errno. */
static long uwg_pread_exact(int fd, long off, void *buf, long len) {
    long done = 0;
    char *p = (char *)buf;
    while (done < len) {
        long r = uwg_syscall4(SYS_pread64, fd, (long)(p + done),
                              len - done, off + done);
        if (r <= 0) return r == 0 ? -5 : r;
        done += r;
    }
    return 0;
}

/* Write exactly len bytes from buf to fd at offset off.
 * Returns 0 on success or negative -errno. */
static long uwg_pwrite_exact(int fd, long off, const void *buf, long len) {
    long done = 0;
    const char *p = (const char *)buf;
    while (done < len) {
        long r = uwg_syscall4(SYS_pwrite64, fd, (long)(p + done),
                              len - done, off + done);
        if (r <= 0) return r == 0 ? -5 : r;
        done += r;
    }
    return 0;
}

/* Copy [src_off, src_off+size) from src_fd to [dst_off, dst_off+size)
 * in dst_fd using iobuf (io_bufsz bytes) as the transfer buffer. */
static long uwg_copy_fd(int dst_fd, long dst_off,
                         int src_fd, long src_off, long size,
                         char *iobuf, int io_bufsz) {
    long done = 0;
    while (done < size) {
        long chunk = size - done;
        if (chunk > io_bufsz) chunk = io_bufsz;
        long r = uwg_syscall4(SYS_pread64, src_fd, (long)iobuf,
                              chunk, src_off + done);
        if (r <= 0) return r == 0 ? -5 : r;
        long w = 0;
        while (w < r) {
            long wr = uwg_syscall4(SYS_pwrite64, dst_fd,
                                    (long)(iobuf + w), r - w,
                                    dst_off + done + w);
            if (wr <= 0) return wr == 0 ? -5 : wr;
            w += wr;
        }
        done += r;
    }
    return 0;
}

/* Get the file size of fd via lseek(SEEK_END). */
static long uwg_file_size(int fd) {
    return uwg_syscall3(SYS_lseek, fd, 0, SEEK_END);
}

/* Write the ptloader binary to dst_fd at offset 0.
 * Prefers the in-memory buffer (survives fork+close_fds); falls back to
 * the master fd if the buffer was not populated at init time. */
static long uwg_write_ptloader(int dst_fd, char *io_buf) {
    if (uwg_ptloader_buf) {
        long done = 0;
        const char *src = (const char *)uwg_ptloader_buf;
        while (done < uwg_ptloader_size) {
            long w = uwg_syscall4(SYS_pwrite64, dst_fd,
                                   (long)(src + done),
                                   uwg_ptloader_size - done, done);
            if (w <= 0) return w ? w : -5;
            done += w;
        }
        return 0;
    }
    return uwg_copy_fd(dst_fd, 0, uwg_ptloader_master_fd, 0,
                       uwg_ptloader_size, io_buf, UWG_DOCKER_IO_BUF);
}

/* ------------------------------------------------------------------ */
/* Init: read Go-wrapper env vars. Called from uwg_core_init().       */
/* ------------------------------------------------------------------ */

extern char **uwg_environ;

static const char *uwg_docker_getenv(const char *name) {
    if (!uwg_environ) return NULL;
    int nlen = uwg_docker_strlen(name);
    for (char **e = uwg_environ; *e; e++) {
        const char *p = *e;
        int ok = 1;
        for (int i = 0; i < nlen; i++) {
            if (p[i] != name[i]) { ok = 0; break; }
        }
        if (ok && p[nlen] == '=') return p + nlen + 1;
    }
    return NULL;
}

static long uwg_docker_parse_long(const char *s) {
    if (!s || !*s) return -1;
    long v = 0;
    for (; *s >= '0' && *s <= '9'; s++) v = v * 10 + (*s - '0');
    return *s ? -1 : v;
}

void uwg_ptloader_docker_init(void) {
    const char *fd_s  = uwg_docker_getenv("UWGS_PTLOADER_FD");
    const char *off_s = uwg_docker_getenv("UWGS_PTLOADER_CFG_OFF");
    const char *sz_s  = uwg_docker_getenv("UWGS_PTLOADER_SIZE");
    if (!fd_s || !off_s || !sz_s) return;
    long fd  = uwg_docker_parse_long(fd_s);
    long off = uwg_docker_parse_long(off_s);
    long sz  = uwg_docker_parse_long(sz_s);
    if (fd < 0 || off < 0 || sz <= 0) return;
    uwg_ptloader_master_fd = (int)fd;
    uwg_ptloader_cfg_off   = off;
    uwg_ptloader_size      = sz;

    /* Load ptloader into anonymous memory so injection survives fork+close_fds.
     * Python's subprocess.Popen(close_fds=True) calls close_range(3,MAX,0) in
     * the fork-child before execve — closing uwg_ptloader_master_fd.  Without
     * this buffer the SIGSYS-handler copy would get EBADF, fall to passthrough,
     * and exec the original binary unmodified: its LD_PRELOAD constructor runs
     * AFTER libselinux's constructor (glibc ld.so initialises DT_NEEDED in
     * reverse link-map order), so the first BPF trap fires before the SIGSYS
     * handler is installed, killing the child with SIG_DFL. */
    if (uwg_ptloader_buf) return; /* already loaded (e.g. called twice) */
    long mm = uwg_syscall6(SYS_mmap, 0, sz,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mm < 0) return; /* best-effort; fd fallback used if buf stays NULL */
    long done = 0;
    char *dst = (char *)mm;
    while (done < sz) {
        long r = uwg_syscall4(SYS_pread64, (int)fd, (long)(dst + done),
                               sz - done, done);
        if (r <= 0) { uwg_syscall2(SYS_munmap, mm, sz); return; }
        done += r;
    }
    uwg_ptloader_buf = (void *)mm;
}

/* ------------------------------------------------------------------ */
/* Patch and exec (only called when binary has no PT_INTERP).         */
/* Work buffer mm must be UWG_DOCKER_BUF_TOTAL bytes;                 */
/* phdr_buf and io_buf are sub-regions of mm.                         */
/* ------------------------------------------------------------------ */

static long uwg_docker_patch_exec(int orig_fd, long orig_size,
                                   const Elf64_Ehdr *ehdr,
                                   const Elf64_Phdr *phdrs,
                                   const char * const *argv,
                                   const char * const *envp,
                                   char *io_buf) {
    if (uwg_ptloader_size <= 0 || uwg_ptloader_cfg_off < 0 ||
        (uwg_ptloader_buf == NULL && uwg_ptloader_master_fd < 0)) {
        return -12; /* -ENOMEM: ptloader info not initialized */
    }

    long rc;

    /* Create ptl_fd: copy of ptloader. NO O_CLOEXEC — must survive exec. */
    long ptl_fd_l = uwg_syscall2(SYS_memfd_create, (long)"uwgptl", 0);
    if (ptl_fd_l < 0) return ptl_fd_l;
    int ptl_fd = (int)ptl_fd_l;

    rc = uwg_write_ptloader(ptl_fd, io_buf);
    if (rc < 0) goto out_ptl;

    /* Compute phdr_base_vma: the (p_vaddr - p_offset) of the PT_LOAD
     * segment that contains the original e_phoff. This is needed by the
     * ptloader to reconstruct correct AT_PHDR after we moved e_phoff to
     * EOF (where the kernel won't map it into a PT_LOAD, so AT_PHDR is
     * not set by the kernel).
     *
     * For ET_EXEC (non-PIE): typically 0x400000 (p_vaddr=0x400000, p_offset=0).
     * For ET_DYN  (PIE):     typically 0 (p_vaddr=0, p_offset=0).
     */
    uint64_t phdr_base_vma = 0;
    for (int pi = 0; pi < (int)ehdr->e_phnum; pi++) {
        if (phdrs[pi].p_type != PT_LOAD) continue;
        if (phdrs[pi].p_offset > ehdr->e_phoff) continue;
        if (ehdr->e_phoff >= phdrs[pi].p_offset + phdrs[pi].p_filesz) continue;
        phdr_base_vma = phdrs[pi].p_vaddr - phdrs[pi].p_offset;
        break;
    }

    /* Build the cfg struct and write it into ptl_fd. */
    struct uwg_ptloader_cfg cfg;
    cfg.magic               = UWG_PTLOADER_MAGIC;
    cfg.original_e_phoff    = ehdr->e_phoff;
    cfg.original_e_phnum    = ehdr->e_phnum;
    cfg.original_e_phentsize = ehdr->e_phentsize;
    cfg.e_type_is_pie       = (ehdr->e_type == ET_DYN) ? 1 : 0;
    cfg.is_dynamic          = 0;
    cfg._pad0[0] = cfg._pad0[1] = 0;
    cfg.e_entry_in_file     = ehdr->e_entry;
    cfg.phdr_base_vma       = phdr_base_vma;
    cfg.interp_fd           = ptl_fd;
    cfg._pad1               = 0;

    rc = uwg_pwrite_exact(ptl_fd, uwg_ptloader_cfg_off, &cfg, sizeof(cfg));
    if (rc < 0) goto out_ptl;

    /* Build ptl_path. */
    char ptl_path[32];
    int ptl_path_len = uwg_make_proc_fd_path(ptl_fd, ptl_path,
                                              sizeof(ptl_path));
    if (ptl_path_len <= 0) { rc = -22; goto out_ptl; }

    /* Create bin_fd: patched copy of the original binary. O_CLOEXEC. */
    long bin_fd_l = uwg_syscall2(SYS_memfd_create,
                                  (long)"uwgbin", (long)MFD_CLOEXEC);
    if (bin_fd_l < 0) { rc = bin_fd_l; goto out_ptl; }
    int bin_fd = (int)bin_fd_l;

    /* Copy original binary content. */
    rc = uwg_copy_fd(bin_fd, 0, orig_fd, 0, orig_size,
                     io_buf, UWG_DOCKER_IO_BUF);
    if (rc < 0) goto out_bin;

    /* Append at EOF:
     *   [orig_size]                         original phdrs
     *   [orig_size + phnum * sizeof(phdr)]  new PT_INTERP phdr
     *   [orig_size + (phnum+1) * sizeof]    ptl_path string (+ NUL) */
    long phdrs_append_off = orig_size;
    long interp_phdr_off  = phdrs_append_off +
                            (long)ehdr->e_phnum * (long)sizeof(Elf64_Phdr);
    long path_str_off     = interp_phdr_off + (long)sizeof(Elf64_Phdr);

    rc = uwg_pwrite_exact(bin_fd, phdrs_append_off, phdrs,
                          (long)ehdr->e_phnum * (long)sizeof(Elf64_Phdr));
    if (rc < 0) goto out_bin;

    Elf64_Phdr ip;
    ip.p_type   = PT_INTERP;
    ip.p_flags  = PF_R;
    ip.p_offset = (Elf64_Off)path_str_off;
    ip.p_vaddr  = 0;
    ip.p_paddr  = 0;
    ip.p_filesz = (Elf64_Xword)(ptl_path_len + 1);
    ip.p_memsz  = (Elf64_Xword)(ptl_path_len + 1);
    ip.p_align  = 1;
    rc = uwg_pwrite_exact(bin_fd, interp_phdr_off, &ip, sizeof(ip));
    if (rc < 0) goto out_bin;

    rc = uwg_pwrite_exact(bin_fd, path_str_off, ptl_path, ptl_path_len + 1);
    if (rc < 0) goto out_bin;

    /* Patch ELF header: update e_phoff and e_phnum in bin_fd. */
    Elf64_Ehdr new_ehdr;
    rc = uwg_pread_exact(bin_fd, 0, &new_ehdr, sizeof(new_ehdr));
    if (rc < 0) goto out_bin;
    new_ehdr.e_phoff = (Elf64_Off)phdrs_append_off;
    new_ehdr.e_phnum = ehdr->e_phnum + 1;
    rc = uwg_pwrite_exact(bin_fd, 0, &new_ehdr, sizeof(new_ehdr));
    if (rc < 0) goto out_bin;

    /* Build bin_path and exec. */
    char bin_path[32];
    if (uwg_make_proc_fd_path(bin_fd, bin_path, sizeof(bin_path)) <= 0) {
        rc = -22;
        goto out_bin;
    }

    /* Block SIGSYS before exec. The new process inherits the signal mask
     * across execve; keeping SIGSYS blocked until uwg_core_init() installs
     * the handler ensures any BPF trap in the ld.so startup window queues
     * rather than firing with SIG_DFL and killing the child. Unblocking is
     * done in uwg_core_init() immediately after handler installation.
     *
     * Use passthrough_syscall4 (bypass secret in arg6) so the layer-2 BPF
     * filter allows this call rather than intercepting it and stripping SIGSYS
     * from the block mask. */
    {
        uint64_t _sigsys_mask = (uint64_t)1 << (SIGSYS - 1);
        uwg_passthrough_syscall4(SYS_rt_sigprocmask, SIG_BLOCK,
                                  (long)&_sigsys_mask, 0L, 8L);
    }

    /* Bypass-secret in arg6 so the seccomp filter ALLOWs this execve
     * without re-trapping it through the SIGSYS handler. */
    rc = uwg_passthrough_execve_syscall3(SYS_execve, (long)bin_path,
                                          (long)argv, (long)envp);
    /* On execve success this point is never reached. */

out_bin:
    uwg_syscall1(SYS_close, bin_fd);
out_ptl:
    uwg_syscall1(SYS_close, ptl_fd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* RPATH $ORIGIN expansion → LD_LIBRARY_PATH injection                */
/*                                                                     */
/* When a dynamic binary is exec'd via a memfd path (systrap-elf       */
/* mode), glibc's _dl_get_origin() calls readlink("/proc/self/exe")    */
/* which returns "/memfd:uwgbin (deleted)".  dirname of that is "/"   */
/* not the binary's real directory, so any RPATH component like        */
/* "$ORIGIN/../lib" (Java, Chromium, etc.) resolves under "/" rather   */
/* than under the real binary location.                                */
/*                                                                     */
/* Fix: read the binary's DT_RPATH / DT_RUNPATH, resolve $ORIGIN via  */
/* readlinkat on /proc/self/fd/<orig_fd> (which gives the canonical    */
/* path before the binary is replaced by the memfd copy), expand each  */
/* $ORIGIN occurrence, and prepend the result to LD_LIBRARY_PATH.      */
/* glibc searches LD_LIBRARY_PATH before DT_RUNPATH and after DT_RPATH */
/* so the expanded paths win in both cases.                            */
/*                                                                     */
/* Returns the original envp unchanged when no $ORIGIN expansion is    */
/* needed (fast path).  All working storage lives in the 64 KiB io_buf */
/* which is free after the binary-copy step and stays live until exec  */
/* replaces the process image.  No heap allocation; no mmap.          */
/* ------------------------------------------------------------------ */

static const char * const *
uwg_expand_rpath_env(int orig_fd, const Elf64_Ehdr *ehdr,
                     const Elf64_Phdr *phdrs, const char *exec_path,
                     const char * const *envp, char *io_buf)
{
    /* io_buf layout (offsets within the 64 KiB buffer):
     *   [0 .. dyn_sz)   temporary PT_DYNAMIC entries (freed after scan)
     *   [0 .. 511]      RPATH string from file (reused after scan)
     *   [512 .. 1535]   $ORIGIN-expanded RPATH  (1024 bytes max)
     *   [1536 .. 3535]  "LD_LIBRARY_PATH=..." entry string (2000 bytes max)
     *   [3536 ..]       new_envp[] pointer array                          */

    /* 1. Resolve canonical path via readlinkat(/proc/self/fd/<orig_fd>). */
    char proc_fd_buf[40];
    char canon[512]; /* canonical binary path, then reused as dirname */
    int  origin_len = 0; /* length of dirname = index of last '/' */

    if (uwg_make_proc_fd_path(orig_fd, proc_fd_buf, sizeof(proc_fd_buf)) <= 0)
        return envp;
    {
        long rlen = uwg_syscall4(SYS_readlinkat, AT_FDCWD,
                                 (long)proc_fd_buf,
                                 (long)canon, (long)(sizeof(canon) - 1));
        if (rlen > 0) {
            canon[rlen] = '\0';
        } else {
            /* Fallback: exec_path may be a symlink but is better than nothing. */
            int n = uwg_docker_strlen(exec_path);
            if (n >= (int)sizeof(canon)) n = (int)sizeof(canon) - 1;
            for (int i = 0; i < n; i++) canon[i] = exec_path[i];
            canon[n] = '\0';
        }
        for (int i = 0; canon[i]; i++) {
            if (canon[i] == '/') origin_len = i;
        }
        /* canon[0..origin_len-1] = dirname (chars before last '/') */
    }

    /* 2. Find PT_DYNAMIC. */
    int dyn_idx = -1;
    for (int pi = 0; pi < (int)ehdr->e_phnum; pi++) {
        if (phdrs[pi].p_type == PT_DYNAMIC) { dyn_idx = pi; break; }
    }
    if (dyn_idx < 0) return envp;

    /* 3. Read dynamic section into io_buf (temp). */
    long dyn_off = (long)phdrs[dyn_idx].p_offset;
    long dyn_sz  = (long)phdrs[dyn_idx].p_filesz;
    if (dyn_sz <= 0) return envp;
    if (dyn_sz > UWG_DOCKER_IO_BUF) dyn_sz = UWG_DOCKER_IO_BUF;
    if (uwg_pread_exact(orig_fd, dyn_off, io_buf, dyn_sz) < 0) return envp;

    /* 4. Find DT_STRTAB vaddr and DT_RUNPATH / DT_RPATH offset. */
    Elf64_Dyn *dynp         = (Elf64_Dyn *)io_buf;
    long       n_dyn        = dyn_sz / (long)sizeof(Elf64_Dyn);
    uint64_t   dt_strtab_va = 0;
    uint64_t   dt_rpath_idx = 0;
    int        has_rpath    = 0;

    for (long di = 0; di < n_dyn; di++) {
        Elf64_Sxword tag = dynp[di].d_tag;
        if (tag == DT_NULL) break;
        if (tag == DT_STRTAB)
            dt_strtab_va = dynp[di].d_un.d_val;
        if (tag == DT_RUNPATH)
            { dt_rpath_idx = dynp[di].d_un.d_val; has_rpath = 1; }
        if (tag == DT_RPATH && !has_rpath)
            { dt_rpath_idx = dynp[di].d_un.d_val; has_rpath = 1; }
    }
    if (!has_rpath || !dt_strtab_va) return envp;

    /* 5. Convert DT_STRTAB virtual address to file offset via PT_LOAD. */
    long strtab_foff = -1;
    for (int pi = 0; pi < (int)ehdr->e_phnum; pi++) {
        if (phdrs[pi].p_type != PT_LOAD) continue;
        if (dt_strtab_va < phdrs[pi].p_vaddr) continue;
        if (dt_strtab_va >= phdrs[pi].p_vaddr + phdrs[pi].p_memsz) continue;
        strtab_foff = (long)(dt_strtab_va - phdrs[pi].p_vaddr
                             + phdrs[pi].p_offset);
        break;
    }
    if (strtab_foff < 0) return envp;

    /* 6. Read RPATH string into io_buf[0..511] (overwrites dynamic data,
     *    which is no longer needed after step 4). */
    char *rpath_in  = io_buf;       /* [0..511]    raw RPATH string */
    char *rpath_out = io_buf + 512; /* [512..1535] $ORIGIN-expanded */
    {
        long foff = strtab_foff + (long)dt_rpath_idx;
        long nr   = uwg_syscall4(SYS_pread64, orig_fd, (long)rpath_in, 511, foff);
        if (nr <= 0) return envp;
        if (nr > 511) nr = 511;
        rpath_in[nr] = '\0';
    }

    /* 7. Quick check: bail early if $ORIGIN not present (most binaries). */
    {
        int found = 0;
        for (int i = 0; rpath_in[i]; i++) {
            if (rpath_in[i]   == '$' && rpath_in[i+1] == 'O' &&
                rpath_in[i+2] == 'R' && rpath_in[i+3] == 'I' &&
                rpath_in[i+4] == 'G' && rpath_in[i+5] == 'I' &&
                rpath_in[i+6] == 'N')
                { found = 1; break; }
        }
        if (!found) return envp;
    }

    /* 8. Expand $ORIGIN occurrences in rpath_in → rpath_out. */
    {
        int out = 0;
        for (int i = 0; rpath_in[i] && out < 1023; ) {
            if (rpath_in[i]   == '$' && rpath_in[i+1] == 'O' &&
                rpath_in[i+2] == 'R' && rpath_in[i+3] == 'I' &&
                rpath_in[i+4] == 'G' && rpath_in[i+5] == 'I' &&
                rpath_in[i+6] == 'N') {
                if (origin_len > 0) {
                    for (int j = 0; j < origin_len && out < 1023; j++)
                        rpath_out[out++] = canon[j];
                } else {
                    if (out < 1023) rpath_out[out++] = '/';
                }
                i += 7; /* skip "$ORIGIN" */
            } else {
                rpath_out[out++] = rpath_in[i++];
            }
        }
        rpath_out[out] = '\0';
    }

    /* 9. Build "LD_LIBRARY_PATH=<rpath_out>[:<existing>]" in io_buf[1536..3535]. */
    char *llp_str = io_buf + 1536;
    int   llp_len = 0;
    {
        const char pfx[] = "LD_LIBRARY_PATH=";
        for (int i = 0; pfx[i] && llp_len < 1999; i++) llp_str[llp_len++] = pfx[i];
        for (int i = 0; rpath_out[i] && llp_len < 1999; i++) llp_str[llp_len++] = rpath_out[i];
    }

    int n_env   = 0;
    int llp_idx = -1;
    if (envp) {
        for (; envp[n_env]; n_env++) {
            if (llp_idx < 0) {
                const char *e = envp[n_env];
                const char  k[] = "LD_LIBRARY_PATH";
                int j = 0;
                while (j < 15 && e[j] == k[j]) j++;
                if (j == 15 && e[j] == '=') llp_idx = n_env;
            }
        }
    }
    if (llp_idx >= 0 && llp_len < 1999) {
        llp_str[llp_len++] = ':';
        const char *ev = envp[llp_idx] + 16; /* skip "LD_LIBRARY_PATH=" */
        for (int i = 0; ev[i] && llp_len < 1999; i++) llp_str[llp_len++] = ev[i];
    }
    llp_str[llp_len] = '\0';

    /* 10. Build new_envp[] in io_buf[3536..].
     *     3536 = 8*442 (8-byte aligned).  Capacity: (64K-3536)/8 = 7750 ptrs. */
    const char **new_envp = (const char **)(io_buf + 3536);
    int idx = 0;
    for (int i = 0; i < n_env; i++) {
        new_envp[idx++] = (i == llp_idx) ? llp_str : envp[i];
    }
    if (llp_idx < 0) new_envp[idx++] = llp_str;
    new_envp[idx] = NULL;

    return (const char * const *)new_envp;
}

/* ------------------------------------------------------------------ */
/* Dynamic-binary injection: replace PT_INTERP with ptloader path.    */
/*                                                                     */
/* Problem: on glibc 2.39 (Ubuntu 24.04), some binaries (e.g. uname)  */
/* link against libselinux.so.1. glibc's _dl_init initialises          */
/* DT_NEEDED libs in reverse link-map order, so libselinux's           */
/* constructor fires BEFORE uwgpreload.so's constructor.  libselinux   */
/* calls socket(AF_NETLINK, ...) in its constructor, which hits the    */
/* BPF SECCOMP_RET_TRAP filter → SIGSYS → SIG_DFL (handler not yet    */
/* installed) → process killed.                                        */
/*                                                                     */
/* Fix: replace the binary's PT_INTERP path with the ptloader path.   */
/* ptloader runs as PT_INTERP before ANY DT_NEEDED library is loaded,  */
/* calls uwg_core_init() to install the SIGSYS handler, then maps the  */
/* original ld.so and jumps to it.  By the time libselinux's           */
/* constructor fires, the handler is already installed.                */
/* ------------------------------------------------------------------ */

static long uwg_docker_patch_exec_dynamic(int orig_fd, long orig_size,
                                           const Elf64_Ehdr *ehdr,
                                           const Elf64_Phdr *phdrs,
                                           int interp_idx,
                                           const char *orig_interp_path,
                                           const char *exec_path,
                                           const char * const *argv,
                                           const char * const *envp,
                                           char *io_buf) {
    if (uwg_ptloader_size <= 0 || uwg_ptloader_cfg_off < 0 ||
        (uwg_ptloader_buf == NULL && uwg_ptloader_master_fd < 0)) {
        return -12;
    }

    long rc;

    /* Create ptl_fd: copy of ptloader. NOT O_CLOEXEC — must survive exec. */
    long ptl_fd_l = uwg_syscall2(SYS_memfd_create, (long)"uwgptl", 0);
    if (ptl_fd_l < 0) return ptl_fd_l;
    int ptl_fd = (int)ptl_fd_l;

    rc = uwg_write_ptloader(ptl_fd, io_buf);
    if (rc < 0) goto out_ptl;

    /* Build ptl_path: "/proc/self/fd/<ptl_fd>". */
    char ptl_path[32];
    int ptl_path_len = uwg_make_proc_fd_path(ptl_fd, ptl_path, sizeof(ptl_path));
    if (ptl_path_len <= 0) { rc = -22; goto out_ptl; }

    /* Compute phdr_base_vma: (p_vaddr - p_offset) of PT_LOAD containing
     * the original e_phoff.  Needed by ptloader to rebuild correct AT_PHDR
     * for binaries that lack PT_PHDR (rare for dynamic binaries, but safe
     * to compute and store unconditionally). */
    uint64_t phdr_base_vma = 0;
    for (int pi = 0; pi < (int)ehdr->e_phnum; pi++) {
        if (phdrs[pi].p_type != PT_LOAD) continue;
        if (phdrs[pi].p_offset > ehdr->e_phoff) continue;
        if (ehdr->e_phoff >= phdrs[pi].p_offset + phdrs[pi].p_filesz) continue;
        phdr_base_vma = phdrs[pi].p_vaddr - phdrs[pi].p_offset;
        break;
    }

    /* Build and write cfg. Dynamic mode: is_dynamic=1, orig_interp filled,
     * original phdr location stored for ptloader AT_PHDR patching. */
    struct uwg_ptloader_cfg cfg;
    cfg.magic                = UWG_PTLOADER_MAGIC;
    cfg.original_e_phoff     = ehdr->e_phoff;
    cfg.original_e_phnum     = ehdr->e_phnum;
    cfg.original_e_phentsize = ehdr->e_phentsize;
    cfg.e_type_is_pie        = (ehdr->e_type == ET_DYN) ? 1 : 0;
    cfg.is_dynamic           = 1;
    cfg._pad0[0]             = 0;
    cfg._pad0[1]             = 0;
    cfg.e_entry_in_file      = ehdr->e_entry;
    cfg.phdr_base_vma        = phdr_base_vma;
    cfg.interp_fd            = ptl_fd;
    cfg._pad1                = 0;
    {
        int n = uwg_docker_strlen(orig_interp_path);
        if (n >= (int)sizeof(cfg.orig_interp))
            n = (int)sizeof(cfg.orig_interp) - 1;
        for (int i = 0; i < n; i++) cfg.orig_interp[i] = orig_interp_path[i];
        cfg.orig_interp[n] = '\0';
    }
    {
        /* Store the original execve pathname so the ptloader can patch
         * AT_EXECFN, restoring $ORIGIN resolution for RPATH entries like
         * Java's "$ORIGIN/../lib" that would otherwise resolve to /proc/self/fd
         * (the memfd path passed to the kernel). */
        int n = uwg_docker_strlen(exec_path);
        if (n >= (int)sizeof(cfg.orig_exec_path))
            n = (int)sizeof(cfg.orig_exec_path) - 1;
        for (int i = 0; i < n; i++) cfg.orig_exec_path[i] = exec_path[i];
        cfg.orig_exec_path[n] = '\0';
    }

    rc = uwg_pwrite_exact(ptl_fd, uwg_ptloader_cfg_off, &cfg, sizeof(cfg));
    if (rc < 0) goto out_ptl;

    /* Create bin_fd: copy of the original binary. O_CLOEXEC. */
    long bin_fd_l = uwg_syscall2(SYS_memfd_create, (long)"uwgbin", (long)MFD_CLOEXEC);
    if (bin_fd_l < 0) { rc = bin_fd_l; goto out_ptl; }
    int bin_fd = (int)bin_fd_l;

    rc = uwg_copy_fd(bin_fd, 0, orig_fd, 0, orig_size, io_buf, UWG_DOCKER_IO_BUF);
    if (rc < 0) goto out_bin;

    /* Expand $ORIGIN in the binary's RPATH and inject LD_LIBRARY_PATH so
     * glibc can find shared libraries despite /proc/self/exe pointing to
     * the memfd path rather than the real binary directory. */
    envp = uwg_expand_rpath_env(orig_fd, ehdr, phdrs, exec_path, envp, io_buf);

    /* Append at EOF:
     *   [orig_size]                         new phdr table (copy of originals,
     *                                        PT_INTERP[interp_idx] replaced)
     *   [orig_size + phnum * sizeof(phdr)]  ptl_path string (+ NUL)
     *
     * The original phdrs remain at their original file offset (within a
     * PT_LOAD segment) so the kernel maps them normally and AT_PHDR via
     * PT_PHDR points to the in-memory original phdrs (which contain the
     * real ld.so path).  The kernel reads our new phdr table from EOF to
     * find PT_INTERP = ptloader, but ld.so reads phdrs via AT_PHDR and
     * sees the original PT_INTERP (real ld.so path).  No glibc crash. */
    long phdrs_append_off = orig_size;
    long path_str_off     = phdrs_append_off +
                            (long)ehdr->e_phnum * (long)sizeof(Elf64_Phdr);

    for (int i = 0; i < (int)ehdr->e_phnum; i++) {
        Elf64_Phdr ph = phdrs[i];
        if (i == interp_idx) {
            /* Replace PT_INTERP entry: point to ptloader path appended at EOF.
             * p_vaddr = 0: the string is not in a PT_LOAD, file-only.
             * The kernel reads PT_INTERP via p_offset (not p_vaddr). */
            ph.p_offset = (Elf64_Off)path_str_off;
            ph.p_vaddr  = 0;
            ph.p_paddr  = 0;
            ph.p_filesz = (Elf64_Xword)(ptl_path_len + 1);
            ph.p_memsz  = (Elf64_Xword)(ptl_path_len + 1);
        }
        rc = uwg_pwrite_exact(bin_fd,
                              phdrs_append_off + (long)i * (long)sizeof(Elf64_Phdr),
                              &ph, sizeof(ph));
        if (rc < 0) goto out_bin;
    }

    /* Append ptl_path string. */
    rc = uwg_pwrite_exact(bin_fd, path_str_off, ptl_path, ptl_path_len + 1);
    if (rc < 0) goto out_bin;

    /* Patch ELF header: redirect e_phoff to new phdr table; e_phnum unchanged. */
    Elf64_Ehdr new_ehdr;
    rc = uwg_pread_exact(bin_fd, 0, &new_ehdr, sizeof(new_ehdr));
    if (rc < 0) goto out_bin;
    new_ehdr.e_phoff = (Elf64_Off)phdrs_append_off;
    rc = uwg_pwrite_exact(bin_fd, 0, &new_ehdr, sizeof(new_ehdr));
    if (rc < 0) goto out_bin;

    /* Build bin_path and exec.
     *
     * Block SIGSYS before the exec so any BPF trap that fires before the
     * SIGSYS handler is installed queues rather than delivers to SIG_DFL.
     *
     * Two-layer handler installation:
     *   1. ptloader (preferred): installs the SIGSYS handler before ld.so
     *      loads any DT_NEEDED library, then unblocks SIGSYS.
     *   2. LD_PRELOAD fallback: if the ptloader's uwg_core_init() returns
     *      early for any reason (e.g. on some glibc versions), our
     *      uwgpreload.so constructor still runs, installs the handler, and
     *      unblocks SIGSYS — at which point queued traps deliver to it.
     *
     * This mirrors what uwg_docker_patch_exec() does for static binaries. */
    {
        uint64_t _sigsys_mask = (uint64_t)1 << (SIGSYS - 1);
        uwg_passthrough_syscall4(SYS_rt_sigprocmask, SIG_BLOCK,
                                  (long)&_sigsys_mask, 0L, 8L);
    }
    char bin_path[32];
    if (uwg_make_proc_fd_path(bin_fd, bin_path, sizeof(bin_path)) <= 0) {
        rc = -22; goto out_bin;
    }
    rc = uwg_passthrough_execve_syscall3(SYS_execve, (long)bin_path,
                                          (long)argv, (long)envp);
out_bin:
    uwg_syscall1(SYS_close, bin_fd);
out_ptl:
    uwg_syscall1(SYS_close, ptl_fd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Env-var injection helpers                                           */
/* ------------------------------------------------------------------ */

/* Check if envp contains an entry with the given key (klen chars)
 * followed immediately by '='. Async-signal-safe. */
static int uwg_env_has_key(const char * const *envp,
                            const char *key, int klen) {
    if (!envp) return 0;
    for (int i = 0; envp[i]; i++) {
        const char *e = envp[i];
        int j = 0;
        while (j < klen && e[j] == key[j]) j++;
        if (j == klen && e[j] == '=') return 1;
    }
    return 0;
}

/* Write v as a decimal string into buf, NUL-terminated.
 * buf must be at least 21 bytes (max uint64_t = 20 digits + NUL). */
static void uwg_u64dec(uint64_t v, char *buf) {
    if (v == 0) { buf[0] = '0'; buf[1] = '\0'; return; }
    char tmp[20];
    int len = 0;
    while (v > 0) { tmp[len++] = (char)('0' + (v % 10)); v /= 10; }
    int i;
    for (i = 0; i < len; i++) buf[i] = tmp[len - 1 - i];
    buf[i] = '\0';
}

/* Copy a NUL-terminated string src into dst. Returns number of bytes
 * written including the NUL. Async-signal-safe. */
static int uwg_strcopy(char *dst, const char *src) {
    int i = 0;
    while (src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
    return i + 1;
}

/*
 * Ensure UWGS_TRACE_SECRET, UWGS_SYSTRAP_DOCKER, and
 * UWGS_SECCOMP_INSTALLED are present in the environment passed to
 * exec'd children.
 *
 * When an application calls execve with a custom envp that strips UWGS_*
 * vars (e.g. exec("/bin/uname", argv, minimal_env)), ptloader's
 * uwg_core_init() cannot find UWGS_TRACE_SECRET and returns early without
 * installing the SIGSYS handler — then any BPF-trapped syscall kills the
 * child.
 *
 * This mirrors what systrap-supervised's ptrace patcher does: it always
 * re-injects the UWGS_* vars via PTRACE_POKEDATA on the exec'd child's
 * envp. We do the equivalent in the SIGSYS handler by building an
 * augmented envp backed by an anonymous mmap (freed automatically when
 * exec replaces the process image).
 *
 * Returns the augmented envp (mmap-backed), or the original envp if all
 * vars are already present or if mmap fails (best-effort fallback).
 */
static const char * const *uwg_inject_uwgs_env(const char * const *envp) {
    /* "UWGS_TRACE_SECRET" = 17 chars */
    int has_secret    = uwg_env_has_key(envp, "UWGS_TRACE_SECRET",    17);
    /* "UWGS_SYSTRAP_DOCKER" = 19 chars */
    int has_docker    = uwg_env_has_key(envp, "UWGS_SYSTRAP_DOCKER",  19);
    /* "UWGS_SECCOMP_INSTALLED" = 22 chars */
    int has_installed = uwg_env_has_key(envp, "UWGS_SECCOMP_INSTALLED", 22);

    if (has_secret && has_docker && has_installed) return envp;

    /* Don't inject a zero secret — it would cause the early-return in
     * uwg_core_init() anyway, and a zero bypass_secret is a misconfigured
     * launcher. */
    if (uwg_bypass_secret == 0) return envp;

    /* Count existing entries. */
    int n = 0;
    if (envp) { while (envp[n]) n++; }

    int n_add = (!has_secret) + (!has_docker) + (!has_installed);
    /* Pointer array: (n + n_add + 1) entries.
     * String data budget per entry:
     *   UWGS_TRACE_SECRET=<decimal u64>\0 → 18 + 20 + 1 = 39 bytes max
     *   UWGS_SYSTRAP_DOCKER=1\0           → 22 bytes
     *   UWGS_SECCOMP_INSTALLED=1\0        → 25 bytes
     * Use 40 bytes per added entry to cover the largest case. */
    long arr_sz = (long)(n + n_add + 1) * (long)sizeof(char *);
    long str_sz = (long)n_add * 40L;
    long total  = arr_sz + str_sz;
    long mm = uwg_syscall6(SYS_mmap, 0, total,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mm < 0) return envp; /* best-effort: proceed with original env */

    const char **new_envp = (const char **)mm;
    char *strs = (char *)(mm + arr_sz);
    int idx = 0;

    /* Copy original pointers. */
    for (int i = 0; i < n; i++) new_envp[idx++] = envp[i];

    /* Append missing vars. */
    if (!has_secret) {
        char *s = strs; strs += 40;
        /* "UWGS_TRACE_SECRET=<decimal>\0" — must use decimal to match
         * parse_u64() in init.c which only accepts '0'..'9'. */
        int plen = uwg_strcopy(s, "UWGS_TRACE_SECRET=") - 1; /* 18, excl NUL */
        uwg_u64dec(uwg_bypass_secret, s + plen);
        new_envp[idx++] = s;
    }
    if (!has_docker) {
        char *s = strs; strs += 22;
        uwg_strcopy(s, "UWGS_SYSTRAP_DOCKER=1");
        new_envp[idx++] = s;
    }
    if (!has_installed) {
        char *s = strs; strs += 25;
        uwg_strcopy(s, "UWGS_SECCOMP_INSTALLED=1");
        new_envp[idx++] = s;
    }
    new_envp[idx] = NULL;
    return (const char * const *)new_envp;
}

/* ------------------------------------------------------------------ */
/* Main dispatch entry points                                          */
/* ------------------------------------------------------------------ */

long uwg_execve_docker_dispatch(const char *path,
                                 const char * const *argv,
                                 const char * const *envp) {
    if (!path) return -14; /* -EFAULT */

    /* Guarantee UWGS_* vars survive even if the caller passed a stripped
     * envp. The augmented envp is mmap-backed and freed by exec(). */
    envp = uwg_inject_uwgs_env(envp);

    long fd_l = uwg_syscall4(SYS_openat, AT_FDCWD, (long)path,
                              O_RDONLY | O_CLOEXEC, 0);
    if (fd_l < 0) return fd_l;
    int fd = (int)fd_l;

    /* Allocate phdr + IO work buffer. */
    long mm = uwg_syscall6(SYS_mmap, 0, UWG_DOCKER_BUF_TOTAL,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mm < 0) {
        uwg_syscall1(SYS_close, fd);
        return (long)mm;
    }
    Elf64_Phdr *phdr_buf = (Elf64_Phdr *)mm;
    char       *io_buf   = (char *)(mm + UWG_DOCKER_PHDR_BUF);

    long rc = -22;

    /* Read and validate ELF header. */
    Elf64_Ehdr ehdr;
    if (uwg_pread_exact(fd, 0, &ehdr, sizeof(ehdr)) < 0) goto passthrough;
    if (ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F' ||
        ehdr.e_ident[4] != ELFCLASS64)
        goto passthrough;
#if defined(__x86_64__)
    if (ehdr.e_machine != EM_X86_64) goto passthrough;
#elif defined(__aarch64__)
    if (ehdr.e_machine != EM_AARCH64) goto passthrough;
#else
    goto passthrough;
#endif
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) goto passthrough;
    if (ehdr.e_phnum == 0 || ehdr.e_phnum > UWG_DOCKER_MAX_PHDRS ||
        ehdr.e_phentsize < sizeof(Elf64_Phdr))
        goto passthrough;

    /* Read phdrs. */
    if (uwg_pread_exact(fd, (long)ehdr.e_phoff, phdr_buf,
                        (long)ehdr.e_phnum * (long)sizeof(Elf64_Phdr)) < 0)
        goto passthrough;

    /* Scan for PT_INTERP. */
    for (int i = 0; i < (int)ehdr.e_phnum; i++) {
        if (phdr_buf[i].p_type != PT_INTERP) continue;

        /* Read PT_INTERP path string (up to 255 chars + NUL). */
        char interp_path[256];
        long plen = (long)phdr_buf[i].p_filesz;
        if (plen <= 0 || plen >= (long)sizeof(interp_path))
            plen = (long)sizeof(interp_path) - 1;
        long r = uwg_syscall4(SYS_pread64, fd, (long)interp_path,
                               plen, (long)phdr_buf[i].p_offset);
        if (r > 0) interp_path[r] = '\0';
        else       interp_path[0] = '\0';

        if (uwg_is_my_ptloader_path(interp_path, uwg_ptloader_my_fd)) {
            /* Re-exec: binary already has our ptloader as interpreter.
             * Clear CLOEXEC so the kernel can reopen it. */
            long flags = uwg_syscall3(SYS_fcntl, uwg_ptloader_my_fd, F_GETFD, 0);
            if (flags >= 0 && (flags & FD_CLOEXEC)) {
                uwg_syscall3(SYS_fcntl, uwg_ptloader_my_fd,
                             F_SETFD, flags & ~(long)FD_CLOEXEC);
            }
            goto passthrough;
        }

        /* Regular dynamic binary: inject ptloader as PT_INTERP so the SIGSYS
         * handler is installed before any DT_NEEDED constructor fires. */
        {
            long orig_size = uwg_file_size(fd);
            if (orig_size > (long)sizeof(Elf64_Ehdr)) {
                rc = uwg_docker_patch_exec_dynamic(fd, orig_size, &ehdr, phdr_buf,
                                                    i, interp_path, path,
                                                    argv, envp, io_buf);
            }
        }
        goto passthrough;
    }

    /* No PT_INTERP: static binary. Get file size and patch. */
    {
        long orig_size = uwg_file_size(fd);
        if (orig_size <= (long)sizeof(Elf64_Ehdr)) goto passthrough;

        rc = uwg_docker_patch_exec(fd, orig_size, &ehdr, phdr_buf,
                                    argv, envp, io_buf);
    }
    uwg_syscall2(SYS_munmap, mm, UWG_DOCKER_BUF_TOTAL);
    uwg_syscall1(SYS_close, fd);
    return rc;

passthrough:
    uwg_syscall2(SYS_munmap, mm, UWG_DOCKER_BUF_TOTAL);
    uwg_syscall1(SYS_close, fd);
    /* Block SIGSYS before exec so BPF traps in the post-exec pre-constructor
     * window queue rather than deliver to SIG_DFL (which would kill the
     * child). For dynamic binaries the SIGSYS handler comes from our
     * LD_PRELOAD constructor — not from ptloader — so there is a window
     * between exec and the constructor running where the handler is SIG_DFL.
     *
     * Blocking is safe because:
     *   - The execve itself uses the bypass secret (BPF ALLOWS it, no trap).
     *   - rt_sigaction(SIGSYS=31) now uses SECCOMP_RET_ERRNO|0, so the old
     *     concern about force_sig overriding the block for that call is gone.
     *   - ld.so and our constructor do not call execve/execveat, so the
     *     docker-mode execve BPF trap cannot fire with SIGSYS blocked and
     *     force_sig the child during the startup window.
     *   - uwg_core_init() unblocks SIGSYS immediately after installing the
     *     handler, so queued traps deliver to our handler rather than SIG_DFL.
     *
     * This mirrors what uwg_docker_patch_exec() does for static binaries. */
    {
        uint64_t _sigsys_mask = (uint64_t)1 << (SIGSYS - 1);
        uwg_passthrough_syscall4(SYS_rt_sigprocmask, SIG_BLOCK,
                                  (long)&_sigsys_mask, 0L, 8L);
    }
    return uwg_passthrough_execve_syscall3(SYS_execve, (long)path,
                                            (long)argv, (long)envp);
}

long uwg_execveat_docker_dispatch(int dirfd, const char *path,
                                   const char * const *argv,
                                   const char * const *envp,
                                   int flags) {
    envp = uwg_inject_uwgs_env(envp);

    /* AT_EMPTY_PATH: target is dirfd itself (e.g. fexecve from Python subprocess).
     * Open the binary via /proc/self/fd/<dirfd> so uwg_execve_docker_dispatch can
     * inject the ptloader. Without injection the post-exec pre-constructor window
     * has no SIGSYS handler; any BPF-trapped syscall (e.g. libselinux socket() in
     * its .so constructor) hits force_sig_info with no handler installed → killed. */
    if ((flags & AT_EMPTY_PATH) && (!path || !path[0])) {
        char fdpath[32];
        uwg_make_proc_fd_path(dirfd, fdpath, sizeof(fdpath));
        return uwg_execve_docker_dispatch(fdpath, argv, envp);
    }
    /* Relative path with non-FDCWD dirfd: passthrough. */
    if (dirfd != AT_FDCWD && path && path[0] != '/') {
        uint64_t _sigsys_mask = (uint64_t)1 << (SIGSYS - 1);
        uwg_passthrough_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&_sigsys_mask, 0L, 8L);
        return uwg_passthrough_execve_syscall5(SYS_execveat, dirfd, (long)path,
                                               (long)argv, (long)envp, flags);
    }
    return uwg_execve_docker_dispatch(path, argv, envp);
}
