// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"golang.org/x/sys/unix"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgshared"
)

// uwgPtloaderCfg mirrors the first 48 bytes of struct uwg_ptloader_cfg in
// preload/core/ptloader_cfg.h. Layout must match the C struct exactly.
// The C struct has an additional orig_interp[256] at offset 48 used only in
// dynamic mode (IsDynamic=1); the Go patcher only handles static targets so
// it writes 48 bytes with IsDynamic=0 and orig_interp stays zero-initialised.
//
//	correct_AT_PHDR = PhrBaseVma + OriginalEPhoff + load_bias
//	  where load_bias = AT_ENTRY - EEntryInFile  (PIE/ET_DYN)
//	  or    load_bias = 0                         (non-PIE/ET_EXEC)
type uwgPtloaderCfg struct {
	Magic              uint64   // 0
	OriginalEPhoff     uint64   // 8
	OriginalEPhnum     uint16   // 16
	OriginalEPhentsize uint16   // 18
	ETypeIsPie         uint8    // 20
	IsDynamic          uint8    // 21 — 0 for static targets (Go always writes 0)
	Pad0               [2]uint8 // 22
	EEntryInFile       uint64   // 24
	PhdrBaseVma        uint64   // 32 — (p_vaddr−p_offset) of PT_LOAD containing e_phoff
	InterpFd           int32    // 40
	Pad1               int32    // 44
}

const uwgPtloaderMagic = uint64(0x5557474346470001)

func selectPtloaderBytes() ([]byte, error) {
	if len(embeddedPtloaderBytes) == 0 {
		return nil, fmt.Errorf("embedded ptloader-%s.so missing (run build_ptloader.sh first)", runtime.GOARCH)
	}
	return embeddedPtloaderBytes, nil
}

// findPtloaderCfgSection returns the file offset and size of the .uwgcfg
// section in the embedded ptloader binary. The caller uses the offset to
// write a per-exec uwgPtloaderCfg struct into a ptloader memfd copy.
func findPtloaderCfgSection(data []byte) (offset uint64, size uint64, err error) {
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return 0, 0, fmt.Errorf("parse ptloader ELF: %w", err)
	}
	defer ef.Close()
	s := ef.Section(".uwgcfg")
	if s == nil {
		return 0, 0, errors.New("ptloader has no .uwgcfg section")
	}
	return s.Offset, s.Size, nil
}

// writePtloaderCfg writes a uwgPtloaderCfg struct into fd at the given
// file offset using little-endian byte order (both amd64 and aarch64 are LE).
func writePtloaderCfg(fd int, offset uint64, cfg *uwgPtloaderCfg) error {
	var buf [48]byte
	b := buf[:]
	binary.LittleEndian.PutUint64(b[0:], cfg.Magic)           // 0:8
	binary.LittleEndian.PutUint64(b[8:], cfg.OriginalEPhoff)  // 8:16
	binary.LittleEndian.PutUint16(b[16:], cfg.OriginalEPhnum) // 16:18
	binary.LittleEndian.PutUint16(b[18:], cfg.OriginalEPhentsize) // 18:20
	b[20] = cfg.ETypeIsPie                                     // 20
	b[21] = cfg.IsDynamic                                      // 21
	copy(b[22:24], cfg.Pad0[:])                                // 22:24
	binary.LittleEndian.PutUint64(b[24:], cfg.EEntryInFile)   // 24:32
	binary.LittleEndian.PutUint64(b[32:], cfg.PhdrBaseVma)    // 32:40
	binary.LittleEndian.PutUint32(b[40:], uint32(cfg.InterpFd)) // 40:44
	binary.LittleEndian.PutUint32(b[44:], uint32(cfg.Pad1))   // 44:48
	_, err := unix.Pwrite(fd, buf[:], int64(offset))
	return err
}

// writeAll writes all of p to fd starting at file offset off.
func writeAll(fd int, off int64, p []byte) error {
	for len(p) > 0 {
		n, err := unix.Pwrite(fd, p, off)
		if err != nil {
			return err
		}
		p = p[n:]
		off += int64(n)
	}
	return nil
}

// readAll reads exactly len(p) bytes from fd at offset off.
func readAll(fd int, off int64, p []byte) error {
	for len(p) > 0 {
		n, err := unix.Pread(fd, p, off)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		p = p[n:]
		off += int64(n)
	}
	return nil
}

// patchStaticELFForDockerExec creates the three memfds needed to exec a static
// binary under systrap-docker:
//
//   - binFD (CLOEXEC): copy of the original binary with phdrs + PT_INTERP +
//     ptloader path appended at EOF, ELF header patched to point e_phoff there.
//   - ptlFD (NOT CLOEXEC): copy of ptloaderBytes with the per-exec
//     uwgPtloaderCfg written at cfgOff. The kernel opens this as PT_INTERP.
//   - masterFD (NOT CLOEXEC): bare copy of ptloaderBytes (no per-exec cfg).
//     Inherited across execs; used by execve_docker_dispatch as the template.
//
// The caller execs "/proc/self/fd/<binFD>" with argv[0] = target.
// binFD, ptlFD, and masterFD must be closed on error (they're left open on
// success — binFD is CLOEXEC so the kernel closes it after exec; ptlFD and
// masterFD survive exec intentionally).
func patchStaticELFForDockerExec(
	target string,
	ptloaderBytes []byte,
	cfgOff uint64,
) (binFD, ptlFD, masterFD int, err error) {
	binFD, ptlFD, masterFD = -1, -1, -1

	origFile, openErr := os.Open(target)
	if openErr != nil {
		return -1, -1, -1, fmt.Errorf("open target %q: %w", target, openErr)
	}
	defer origFile.Close()

	// Read ELF header.
	var ehdrRaw [64]byte // sizeof Elf64_Ehdr
	if _, rerr := io.ReadFull(origFile, ehdrRaw[:]); rerr != nil {
		return -1, -1, -1, fmt.Errorf("read ELF header: %w", rerr)
	}
	if ehdrRaw[0] != 0x7f || ehdrRaw[1] != 'E' || ehdrRaw[2] != 'L' || ehdrRaw[3] != 'F' {
		return -1, -1, -1, errors.New("target is not an ELF binary")
	}
	if ehdrRaw[4] != byte(elf.ELFCLASS64) {
		return -1, -1, -1, errors.New("target is not a 64-bit ELF binary")
	}
	origPhoff := binary.LittleEndian.Uint64(ehdrRaw[32:40])
	origPhnum := binary.LittleEndian.Uint16(ehdrRaw[56:58])
	origPhentsize := binary.LittleEndian.Uint16(ehdrRaw[54:56])
	eEntry := binary.LittleEndian.Uint64(ehdrRaw[24:32])
	eType := binary.LittleEndian.Uint16(ehdrRaw[16:18])

	if origPhnum == 0 {
		return -1, -1, -1, errors.New("target ELF has no program headers")
	}
	if int(origPhentsize) < 56 { // sizeof Elf64_Phdr
		return -1, -1, -1, fmt.Errorf("unexpected e_phentsize %d", origPhentsize)
	}

	// Read original program headers.
	phdrSize := int(origPhnum) * int(origPhentsize)
	phdrs := make([]byte, phdrSize)
	if rerr := readAll(int(origFile.Fd()), int64(origPhoff), phdrs); rerr != nil {
		return -1, -1, -1, fmt.Errorf("read phdrs: %w", rerr)
	}

	// Compute phdr_base_vma: (p_vaddr - p_offset) for the PT_LOAD segment
	// that contains e_phoff. This lets the ptloader reconstruct AT_PHDR
	// correctly for both PIE (phdr_base_vma ≈ 0) and non-PIE (≈ 0x400000).
	var phdrBaseVma uint64
	const ptLoad = 1 // PT_LOAD
	for i := 0; i < int(origPhnum); i++ {
		off := i * int(origPhentsize)
		pType := binary.LittleEndian.Uint32(phdrs[off:])
		if pType != ptLoad {
			continue
		}
		pOffset := binary.LittleEndian.Uint64(phdrs[off+8:])
		pVaddr := binary.LittleEndian.Uint64(phdrs[off+16:])
		pFilesz := binary.LittleEndian.Uint64(phdrs[off+32:])
		if origPhoff >= pOffset && origPhoff < pOffset+pFilesz {
			phdrBaseVma = pVaddr - pOffset
			break
		}
	}

	// Get file size.
	origSize, seekErr := origFile.Seek(0, io.SeekEnd)
	if seekErr != nil {
		return -1, -1, -1, fmt.Errorf("seek end: %w", seekErr)
	}

	// --- create ptlFD (non-CLOEXEC): ptloader copy + cfg ---
	ptl, cErr := unix.MemfdCreate("uwgptl", 0) // 0 = no flags = non-CLOEXEC
	if cErr != nil {
		return -1, -1, -1, fmt.Errorf("memfd_create ptl: %w", cErr)
	}
	ptlFD = ptl
	if werr := writeAll(ptlFD, 0, ptloaderBytes); werr != nil {
		unix.Close(ptlFD)
		return -1, -1, -1, fmt.Errorf("write ptloader to ptlFD: %w", werr)
	}
	ptlPath := fmt.Sprintf("/proc/self/fd/%d", ptlFD)

	cfg := uwgPtloaderCfg{
		Magic:              uwgPtloaderMagic,
		OriginalEPhoff:     origPhoff,
		OriginalEPhnum:     origPhnum,
		OriginalEPhentsize: origPhentsize,
		EEntryInFile:       eEntry,
		PhdrBaseVma:        phdrBaseVma,
		InterpFd:           int32(ptlFD),
	}
	if eType == uint16(elf.ET_DYN) {
		cfg.ETypeIsPie = 1
	}
	if werr := writePtloaderCfg(ptlFD, cfgOff, &cfg); werr != nil {
		unix.Close(ptlFD)
		return -1, -1, -1, fmt.Errorf("write ptloader cfg: %w", werr)
	}

	// --- create masterFD (non-CLOEXEC): bare ptloader copy (no cfg) ---
	mst, cErr := unix.MemfdCreate("uwgptl_master", 0) // non-CLOEXEC
	if cErr != nil {
		unix.Close(ptlFD)
		return -1, -1, -1, fmt.Errorf("memfd_create master: %w", cErr)
	}
	masterFD = mst
	if werr := writeAll(masterFD, 0, ptloaderBytes); werr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		return -1, -1, -1, fmt.Errorf("write ptloader to masterFD: %w", werr)
	}

	// --- create binFD (CLOEXEC): patched binary ---
	binFDRaw, cErr := unix.MemfdCreate("uwgbin", unix.MFD_CLOEXEC)
	if cErr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		return -1, -1, -1, fmt.Errorf("memfd_create bin: %w", cErr)
	}
	binFD = binFDRaw

	// Copy original binary content to binFD using sendfile or io.Copy.
	_, rerr := origFile.Seek(0, io.SeekStart)
	if rerr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		unix.Close(binFD)
		return -1, -1, -1, fmt.Errorf("seek to start: %w", rerr)
	}
	binFile := os.NewFile(uintptr(binFD), "uwgbin")
	if _, cerr := io.Copy(binFile, origFile); cerr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		unix.Close(binFD)
		return -1, -1, -1, fmt.Errorf("copy binary to binFD: %w", cerr)
	}

	// Append at EOF (offset = origSize):
	//   - original phdrs  (origPhnum * origPhentsize bytes)
	//   - new PT_INTERP phdr  (56 bytes)
	//   - ptlPath string + NUL
	appendOff := origSize
	interpPhdrOff := appendOff + int64(phdrSize)
	pathStrOff := interpPhdrOff + 56 // sizeof Elf64_Phdr

	if werr := writeAll(binFD, appendOff, phdrs); werr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		unix.Close(binFD)
		return -1, -1, -1, fmt.Errorf("write phdrs: %w", werr)
	}

	// Build PT_INTERP phdr (Elf64_Phdr, all LE).
	var interpPhdr [56]byte
	binary.LittleEndian.PutUint32(interpPhdr[0:], 3)          // p_type = PT_INTERP
	binary.LittleEndian.PutUint32(interpPhdr[4:], 4)          // p_flags = PF_R
	binary.LittleEndian.PutUint64(interpPhdr[8:], uint64(pathStrOff))  // p_offset
	binary.LittleEndian.PutUint64(interpPhdr[16:], 0)         // p_vaddr
	binary.LittleEndian.PutUint64(interpPhdr[24:], 0)         // p_paddr
	pathLen := uint64(len(ptlPath) + 1) // include NUL
	binary.LittleEndian.PutUint64(interpPhdr[32:], pathLen)   // p_filesz
	binary.LittleEndian.PutUint64(interpPhdr[40:], pathLen)   // p_memsz
	binary.LittleEndian.PutUint64(interpPhdr[48:], 1)         // p_align

	if werr := writeAll(binFD, interpPhdrOff, interpPhdr[:]); werr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		unix.Close(binFD)
		return -1, -1, -1, fmt.Errorf("write interp phdr: %w", werr)
	}

	// Write ptlPath + NUL terminator.
	pathBytes := append([]byte(ptlPath), 0)
	if werr := writeAll(binFD, pathStrOff, pathBytes); werr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		unix.Close(binFD)
		return -1, -1, -1, fmt.Errorf("write interp path: %w", werr)
	}

	// Patch ELF header in binFD: update e_phoff and e_phnum.
	var newEhdr [64]byte
	if rerr2 := readAll(binFD, 0, newEhdr[:]); rerr2 != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		unix.Close(binFD)
		return -1, -1, -1, fmt.Errorf("read ehdr from binFD: %w", rerr2)
	}
	binary.LittleEndian.PutUint64(newEhdr[32:40], uint64(appendOff)) // e_phoff
	binary.LittleEndian.PutUint16(newEhdr[56:58], origPhnum+1)       // e_phnum
	if werr := writeAll(binFD, 0, newEhdr[:]); werr != nil {
		unix.Close(ptlFD)
		unix.Close(masterFD)
		unix.Close(binFD)
		return -1, -1, -1, fmt.Errorf("patch ehdr: %w", werr)
	}

	return binFD, ptlFD, masterFD, nil
}

// systrapDockerRun implements the systrap-docker transport.
//
// For dynamic targets (have PT_INTERP / dynamic linker): installs LD_PRELOAD
// with UWGS_SYSTRAP_DOCKER=1 and passes a non-CLOEXEC master ptloader memfd as
// fd 3 (via ExtraFiles) so execve_docker_dispatch can patch static children.
//
// For static targets (no PT_INTERP): patches the binary with Go-level ELF
// patching (appending PT_INTERP pointing at the ptloader), then syscall.Execs
// the patched binary directly (replacing the current process). The ptloader
// runs as PT_INTERP, installs the SIGSYS handler + seccomp filter, and jumps
// to the original entry point.
//
// Neither path needs ptrace — that is the whole point of this mode.
func systrapDockerRun(target string, progArgs []string, env []string,
	preloadPath string, shared *uwgshared.Table) {

	ptloaderBytes, err := selectPtloaderBytes()
	if err != nil {
		log.Fatalf("systrap-docker: %v", err)
	}
	cfgOff, _, err := findPtloaderCfgSection(ptloaderBytes)
	if err != nil {
		log.Fatalf("systrap-docker: %v", err)
	}

	if isStaticELF(target) {
		// Static target: patch ELF in Go, exec the patched binary directly.
		// syscall.Exec replaces the current process; all non-CLOEXEC fds
		// survive (kernel closes only CLOEXEC fds on exec).
		binFD, ptlFD, masterFD, pErr := patchStaticELFForDockerExec(target, ptloaderBytes, cfgOff)
		if pErr != nil {
			log.Fatalf("systrap-docker: patch static binary %q: %v", target, pErr)
		}

		env = setEnv(env, "UWGS_SYSTRAP_DOCKER", "1")
		env = setEnv(env, "UWGS_PTLOADER_FD", fmt.Sprintf("%d", masterFD))
		env = setEnv(env, "UWGS_PTLOADER_CFG_OFF", fmt.Sprintf("%d", cfgOff))
		env = setEnv(env, "UWGS_PTLOADER_SIZE", fmt.Sprintf("%d", len(ptloaderBytes)))
		// Propagate LD_PRELOAD so that static→dynamic exec chains pick up the
		// preload shim in the dynamic child. Static binaries ignore LD_PRELOAD
		// (no dynamic linker), so this is a no-op for the initial process.
		env = setEnv(env, "UWGS_PRELOAD_PATH", preloadPath)
		env = prependEnvPath(env, "LD_PRELOAD", preloadPath)

		statePath := shared.Path()
		_ = shared.Close(false)

		binPath := fmt.Sprintf("/proc/self/fd/%d", binFD)
		argv := append([]string{target}, progArgs...)
		execErr := syscall.Exec(binPath, argv, env)

		// Only reached on error.
		_ = os.Remove(statePath)
		_ = unix.Close(ptlFD)
		_ = unix.Close(masterFD)
		log.Fatalf("systrap-docker: exec patched static %q: %v", target, execErr)
	}

	// Dynamic target: LD_PRELOAD path. Create master_fd, pass as fd 3 via
	// ExtraFiles so the preload.so can use it for static children.
	masterFD, cErr := unix.MemfdCreate("uwgptl_master", 0) // non-CLOEXEC
	if cErr != nil {
		log.Fatalf("systrap-docker: memfd_create master: %v", cErr)
	}
	if werr := writeAll(masterFD, 0, ptloaderBytes); werr != nil {
		unix.Close(masterFD)
		log.Fatalf("systrap-docker: write master ptloader: %v", werr)
	}

	// fd 3 in the child = ExtraFiles[0] (after stdin=0, stdout=1, stderr=2).
	const childMasterFD = 3
	env = setEnv(env, "UWGS_SYSTRAP_DOCKER", "1")
	env = setEnv(env, "UWGS_PTLOADER_FD", fmt.Sprintf("%d", childMasterFD))
	env = setEnv(env, "UWGS_PTLOADER_CFG_OFF", fmt.Sprintf("%d", cfgOff))
	env = setEnv(env, "UWGS_PTLOADER_SIZE", fmt.Sprintf("%d", len(ptloaderBytes)))

	envPreload := prependEnvPath(append([]string{}, env...), "LD_PRELOAD", preloadPath)

	statePath := shared.Path()
	_ = shared.Close(false)

	masterFile := os.NewFile(uintptr(masterFD), "uwgptl_master")
	defer masterFile.Close()

	cmdArgs := append([]string{"--mode=exec-helper", "--", target}, progArgs...)
	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = envPreload
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	cmd.ExtraFiles = []*os.File{masterFile} // → fd 3 in child
	runErr := cmd.Run()

	if statePath != "" {
		_ = os.Remove(statePath)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Exited() {
					os.Exit(status.ExitStatus())
				}
				if status.Signaled() {
					os.Exit(128 + int(status.Signal()))
				}
			}
		}
		log.Fatalf("systrap-docker: run %s: %v", target, runErr)
	}
	os.Exit(0)
}
