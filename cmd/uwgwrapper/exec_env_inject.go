// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// Force-preserve UWGS_* env vars across captured execve / execveat.
//
// The systrap-supervised seccomp filter routes execve/execveat to
// RET_TRACE, giving us a PTRACE_EVENT_SECCOMP at syscall entry — before
// the kernel processes the call. Programs that rebuild their argv/envp
// (chromium's sandbox launcher, sudo, su, certain CI runners) drop or
// scrub the parent's env. That's fatal for the wrapper's children-
// tracking machinery: UWGS_TRACE_SECRET, UWGS_FDPROXY, UWGS_API,
// UWGS_SOCKET_PATH, UWGS_SHARED_STATE_PATH, UWGS_DNS_MODE,
// UWGS_SUPERVISED, UWGS_SECCOMP_INSTALLED — without these the new image
// can't bypass the inherited seccomp filter, can't reach fdproxy, can't
// share state. The dynamic-linker LD_PRELOAD path also breaks because
// LD_PRELOAD itself rides in env.
//
// Strategy: at the SECCOMP-event for execve/execveat, walk the tracee's
// envp, identify which UWGS_* (and LD_PRELOAD) vars are missing, build a
// merged envp + string blob in supervisor memory, allocate a single
// page-aligned buffer in the tracee via remoteSyscall(SYS_mmap), copy
// the blob in via writeMem, and rewrite the syscall's envp register to
// point at the new array. The kernel reads from the new pointer when it
// continues the call. This is a one-time cost per execve and keeps the
// wrapper's session-state coherent regardless of what the executable
// does to envp.

// Linux x86_64 / arm64 syscall numbers for execve and execveat. The
// kernel ABI is stable; these don't change. Defined locally so we don't
// pull in arch-conditional unix.SYS_* constants the way the rest of the
// supervisor does.
const (
	sysExecveAMD64   = 59
	sysExecveatAMD64 = 322
	sysExecveARM64   = 221
	sysExecveatARM64 = 281
)

func sysExecve() uintptr {
	if runtime.GOARCH == "amd64" {
		return sysExecveAMD64
	}
	return sysExecveARM64
}

func sysExecveat() uintptr {
	if runtime.GOARCH == "amd64" {
		return sysExecveatAMD64
	}
	return sysExecveatARM64
}

// envVarsToForcePreserve is the set of env-var KEY prefixes the
// supervisor will inject if the new image's envp drops them. UWGS_* is
// the bulk; LD_PRELOAD is added because the wrapper's preload .so path
// is set in env and dropping it would silently disable interception.
//
// Note we use a prefix match for "UWGS_" so any future UWGS_* additions
// are covered automatically.
var envVarsToForcePreserve = []string{
	"UWGS_",
	"LD_PRELOAD=",
}

// captureSupervisorPreserveSet snapshots the supervisor's own
// environment at handler-entry time, returning the subset we want to
// inject if missing from the tracee's envp.
//
// Falls back to the supervisor's own os.Environ() — sufficient for
// LD_PRELOAD which the wrapper inherits, but UWGS_* vars are set on
// the SPAWNED child's env (not on the wrapper itself) by main.go's
// setEnv calls. To capture those we'd need the spawn-env list to be
// threaded through runSystrapSupervised. That plumbing is a follow-
// up; for now any UWGS_* present in the wrapper's own env (e.g.
// UWGS_TRACE_SECRET that nested wrappers might re-inherit) gets
// preserved, and LD_PRELOAD is the load-bearing one anyway since
// dropping it silently disables interception.
func captureSupervisorPreserveSet(extra []string) []string {
	var out []string
	for _, e := range os.Environ() {
		for _, p := range envVarsToForcePreserve {
			if strings.HasPrefix(e, p) {
				out = append(out, e)
				break
			}
		}
	}
	for _, e := range extra {
		// Avoid duplicates: if extra has the same key as something
		// we already pulled from os.Environ, prefer the extra one
		// (it's the spawn-env value, which is what the wrapper
		// actually set on the child).
		eq := strings.IndexByte(e, '=')
		if eq <= 0 {
			continue
		}
		key := e[:eq+1]
		matched := false
		for _, p := range envVarsToForcePreserve {
			if strings.HasPrefix(e, p) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		// Replace any existing entry with the same key.
		replaced := false
		for i, existing := range out {
			if strings.HasPrefix(existing, key) {
				out[i] = e
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, e)
		}
	}
	return out
}

// readTraceeCStringAt reads a NUL-terminated C string at addr from the
// tracee's address space. Returns the bytes WITHOUT the terminating NUL.
// Bounded at maxLen to keep a corrupted pointer from blowing the loop.
func readTraceeCStringAt(pid int, addr uintptr, maxLen int) ([]byte, error) {
	const wordSize = 8
	var out []byte
	for read := 0; read < maxLen; read += wordSize {
		var word [wordSize]byte
		if _, err := unix.PtracePeekData(pid, addr+uintptr(read), word[:]); err != nil {
			return nil, fmt.Errorf("PtracePeekData @%#x: %w", addr+uintptr(read), err)
		}
		if i := bytes.IndexByte(word[:], 0); i >= 0 {
			return append(out, word[:i]...), nil
		}
		out = append(out, word[:]...)
	}
	return nil, fmt.Errorf("string at %#x exceeds maxLen %d (no NUL)", addr, maxLen)
}

// readTraceeEnvp walks a NULL-terminated array of char* pointers
// starting at envpAddr and returns the strings (bytes, no NUL).
// Bounded at maxEntries.
func readTraceeEnvp(pid int, envpAddr uintptr, maxEntries int) ([][]byte, error) {
	const wordSize = 8
	var entries [][]byte
	for i := 0; i < maxEntries; i++ {
		var word [wordSize]byte
		if _, err := unix.PtracePeekData(pid, envpAddr+uintptr(i*wordSize), word[:]); err != nil {
			return nil, fmt.Errorf("PtracePeekData envp[%d]: %w", i, err)
		}
		ptr := uintptr(binary.LittleEndian.Uint64(word[:]))
		if ptr == 0 {
			return entries, nil
		}
		s, err := readTraceeCStringAt(pid, ptr, 4096)
		if err != nil {
			return nil, fmt.Errorf("envp[%d]: %w", i, err)
		}
		entries = append(entries, s)
	}
	return nil, fmt.Errorf("envp exceeds %d entries; refusing to walk further", maxEntries)
}

// envpRegArg returns the syscall-arg index that holds the envp pointer
// for the given syscall number (execve vs execveat).
func envpRegArg(syscallNr uintptr) (int, bool) {
	switch syscallNr {
	case sysExecve():
		// execve(filename, argv, envp) → arg2
		return 2, true
	case sysExecveat():
		// execveat(dirfd, pathname, argv, envp, flags) → arg3
		return 3, true
	default:
		return 0, false
	}
}

// readSyscallArg / writeSyscallArg / syscallNrFromRegs are arch-
// specific; their implementations live in exec_env_inject_amd64.go and
// exec_env_inject_arm64.go.

// preserveUWGSEnvAtExecve is invoked at the PTRACE_EVENT_SECCOMP stop
// for execve/execveat. It walks the tracee's envp, computes which
// supervisor-side UWGS_* (and LD_PRELOAD) vars are missing, and if any
// are, allocates a buffer in the tracee, writes a merged envp into it,
// and rewrites the syscall's envp arg to point at the new array.
//
// Returns nil on success — and ALSO nil if no injection was needed
// (the common case when the program preserves env). On error the
// supervisor logs and continues; the child runs with whatever env it
// got, and may not be able to participate in the wrapper's tracking.
func preserveUWGSEnvAtExecve(pid int, spawnEnv []string) error {
	preserve := captureSupervisorPreserveSet(spawnEnv)
	if len(preserve) == 0 {
		// Supervisor itself has nothing UWGS_-y to preserve — caller
		// of uwgwrapper invoked us without any of the well-known env.
		// Nothing to do.
		return nil
	}

	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("PtraceGetRegs: %w", err)
	}

	syscallNr := syscallNrFromRegs(&regs)
	argIdx, ok := envpRegArg(syscallNr)
	if !ok {
		return fmt.Errorf("preserveUWGSEnvAtExecve: not an execve/execveat (nr=%d)", syscallNr)
	}

	envpAddr := uintptr(readSyscallArg(&regs, argIdx))
	if envpAddr == 0 {
		// envp = NULL means the kernel will treat env as empty. The
		// program explicitly cleared it. We need to inject the full
		// preserve set into a fresh buffer.
	}

	var existing [][]byte
	if envpAddr != 0 {
		var err error
		existing, err = readTraceeEnvp(pid, envpAddr, 4096)
		if err != nil {
			return fmt.Errorf("read tracee envp: %w", err)
		}
	}

	// Build a "have we seen this key?" set from the existing envp.
	have := make(map[string]bool, len(existing))
	for _, e := range existing {
		if eq := bytes.IndexByte(e, '='); eq >= 0 {
			have[string(e[:eq+1])] = true // include the trailing '='
		}
	}

	// Determine which preserve-set entries are missing (key-wise).
	var toInject [][]byte
	for _, p := range preserve {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		key := p[:eq+1]
		if !have[key] {
			toInject = append(toInject, []byte(p))
		}
	}
	if len(toInject) == 0 {
		// All UWGS_* (and LD_PRELOAD) vars the supervisor cares about
		// already in the tracee's envp. Common case: program preserved
		// env wholesale.
		return nil
	}

	// Build a single contiguous blob with:
	//   [pointer array: existing pointers + new pointers + NULL terminator]
	//   [string area: NUL-terminated copies of each NEW string]
	// Existing strings stay where they are in the tracee — we just
	// reuse their pointers in the new pointer array. That means we
	// don't need to copy potentially-megabytes of unchanged env into
	// our buffer; only the deltas.
	totalEntries := len(existing) + len(toInject) // plus 1 NULL terminator
	pointerArraySize := (totalEntries + 1) * 8
	stringAreaSize := 0
	for _, b := range toInject {
		stringAreaSize += len(b) + 1 // +1 for NUL
	}
	blobSize := pointerArraySize + stringAreaSize

	// Round up to a page (4096) so mmap(MAP_ANONYMOUS) is happy.
	const pageSize = 4096
	mmapSize := (blobSize + pageSize - 1) &^ (pageSize - 1)
	if mmapSize < pageSize {
		mmapSize = pageSize
	}

	addr, err := remoteSyscall(pid, unix.SYS_MMAP,
		0, uintptr(mmapSize),
		unix.PROT_READ|unix.PROT_WRITE,
		uintptr(unix.MAP_ANONYMOUS|unix.MAP_PRIVATE),
		^uintptr(0), 0)
	if err != nil {
		return fmt.Errorf("remote mmap for envp: %w", err)
	}
	if int64(addr) < 0 && int64(addr) >= -4095 {
		return fmt.Errorf("remote mmap returned errno %d", -int64(addr))
	}
	if addr == 0 {
		return fmt.Errorf("remote mmap returned 0 at execve seccomp-event stop")
	}

	// Build the blob in supervisor memory.
	// Layout:
	//   blob[0..pointerArraySize)   = pointer array
	//   blob[pointerArraySize..end) = new string contents
	blob := make([]byte, blobSize)

	// Compute string addresses (in tracee space) for the new entries.
	stringBase := addr + uintptr(pointerArraySize)
	stringOff := 0
	pointerOff := 0
	// Existing pointers first — copy verbatim (each char* in tracee
	// memory is already a valid pointer).
	for i := 0; i < len(existing); i++ {
		// Read the original pointer from the tracee's envp array.
		var word [8]byte
		if _, err := unix.PtracePeekData(pid, envpAddr+uintptr(i*8), word[:]); err != nil {
			return fmt.Errorf("re-read envp[%d]: %w", i, err)
		}
		copy(blob[pointerOff:pointerOff+8], word[:])
		pointerOff += 8
	}
	// New pointers → point into the string area we're about to write.
	for _, s := range toInject {
		newPtr := uint64(stringBase + uintptr(stringOff))
		binary.LittleEndian.PutUint64(blob[pointerOff:pointerOff+8], newPtr)
		pointerOff += 8
		// String content (NUL-terminated).
		copy(blob[pointerArraySize+stringOff:], s)
		stringOff += len(s)
		blob[pointerArraySize+stringOff] = 0
		stringOff++
	}
	// NULL terminator for the pointer array.
	binary.LittleEndian.PutUint64(blob[pointerOff:pointerOff+8], 0)

	if err := writeMem(pid, addr, blob); err != nil {
		return fmt.Errorf("writeMem envp blob: %w", err)
	}

	// Rewrite the syscall's envp arg to point at our new pointer array.
	writeSyscallArg(&regs, argIdx, uint64(addr))
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return fmt.Errorf("PtraceSetRegs after envp rewrite: %w", err)
	}
	return nil
}
