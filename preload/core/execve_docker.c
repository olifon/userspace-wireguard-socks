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
    if (uwg_ptloader_master_fd < 0 || uwg_ptloader_size <= 0 ||
        uwg_ptloader_cfg_off < 0) {
        return -12; /* -ENOMEM: ptloader info not initialized */
    }

    long rc;

    /* Create ptl_fd: copy of ptloader. NO O_CLOEXEC — must survive exec. */
    long ptl_fd_l = uwg_syscall2(SYS_memfd_create, (long)"uwgptl", 0);
    if (ptl_fd_l < 0) return ptl_fd_l;
    int ptl_fd = (int)ptl_fd_l;

    rc = uwg_copy_fd(ptl_fd, 0, uwg_ptloader_master_fd, 0,
                     uwg_ptloader_size, io_buf, UWG_DOCKER_IO_BUF);
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
    cfg._pad0[0] = cfg._pad0[1] = cfg._pad0[2] = 0;
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
     * done in uwg_core_init() immediately after handler installation. */
    {
        uint64_t _sigsys_mask = (uint64_t)1 << (SIGSYS - 1);
        uwg_syscall4(SYS_rt_sigprocmask, SIG_BLOCK,
                     (long)&_sigsys_mask, 0L, 8L);
    }

    /* Bypass-secret in arg6 so the seccomp filter ALLOWs this execve
     * without re-trapping it through the SIGSYS handler. */
    rc = uwg_passthrough_syscall3(SYS_execve, (long)bin_path,
                                   (long)argv, (long)envp);
    /* On execve success this point is never reached. */

out_bin:
    uwg_syscall1(SYS_close, bin_fd);
out_ptl:
    uwg_syscall1(SYS_close, ptl_fd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Main dispatch entry points                                          */
/* ------------------------------------------------------------------ */

long uwg_execve_docker_dispatch(const char *path,
                                 const char * const *argv,
                                 const char * const *envp) {
    if (!path) return -14; /* -EFAULT */

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

        /* PT_INTERP present: check for re-exec case. */
        char interp_path[64];
        long plen = (long)phdr_buf[i].p_filesz;
        if (plen <= 0 || plen >= (long)sizeof(interp_path))
            plen = (long)sizeof(interp_path) - 1;
        long r = uwg_syscall4(SYS_pread64, fd, (long)interp_path,
                               plen, (long)phdr_buf[i].p_offset);
        if (r > 0) {
            interp_path[r] = '\0';
            if (uwg_is_my_ptloader_path(interp_path, uwg_ptloader_my_fd)) {
                long flags = uwg_syscall3(SYS_fcntl,
                                          uwg_ptloader_my_fd, F_GETFD, 0);
                if (flags >= 0 && (flags & FD_CLOEXEC)) {
                    uwg_syscall3(SYS_fcntl, uwg_ptloader_my_fd,
                                 F_SETFD, flags & ~(long)FD_CLOEXEC);
                }
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
        uwg_syscall4(SYS_rt_sigprocmask, SIG_BLOCK,
                     (long)&_sigsys_mask, 0L, 8L);
    }
    return uwg_passthrough_syscall3(SYS_execve, (long)path,
                                     (long)argv, (long)envp);
}

long uwg_execveat_docker_dispatch(int dirfd, const char *path,
                                   const char * const *argv,
                                   const char * const *envp,
                                   int flags) {
    /* AT_EMPTY_PATH: target is dirfd itself. Passthrough — we'd need
     * to inspect the fd to handle this, and it's uncommon enough to
     * not be worth the complexity in the initial implementation. */
    if ((flags & AT_EMPTY_PATH) && (!path || !path[0])) {
        /* Block SIGSYS for the same reason as the execve passthrough path:
         * the new process may be dynamic and our constructor hasn't run yet.
         * See the block comment in uwg_execve_docker_dispatch passthrough. */
        uint64_t _sigsys_mask = (uint64_t)1 << (SIGSYS - 1);
        uwg_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&_sigsys_mask, 0L, 8L);
        return uwg_passthrough_syscall5(SYS_execveat, dirfd, (long)path,
                                         (long)argv, (long)envp, flags);
    }
    /* Relative path with non-FDCWD dirfd: passthrough. */
    if (dirfd != AT_FDCWD && path && path[0] != '/') {
        uint64_t _sigsys_mask = (uint64_t)1 << (SIGSYS - 1);
        uwg_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&_sigsys_mask, 0L, 8L);
        return uwg_passthrough_syscall5(SYS_execveat, dirfd, (long)path,
                                         (long)argv, (long)envp, flags);
    }
    return uwg_execve_docker_dispatch(path, argv, envp);
}
