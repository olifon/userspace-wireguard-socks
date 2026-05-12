// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// Phase 2 step 5b: remote-syscall primitive.
//
// Executes one syscall in the tracee's address space from the
// supervisor. The tracee must be in a ptrace-stop (e.g., post-execve
// or syscall-entry stop) when this is called.
//
// Algorithm:
//   1. Save the tracee's register state.
//   2. Locate or write a syscall instruction in the tracee.
//   3. Set PC/RIP to that instruction; load syscall number + args
//      into the ABI-mandated registers.
//   4. PTRACE_SINGLESTEP — kernel executes the instruction.
//   5. Wait for the post-syscall stop, read the return value from
//      RAX/X0.
//   6. Restore the original registers (and original bytes if we
//      overwrote any).
//
// We pick the instruction location by overwriting 4 bytes at the
// tracee's current PC with the architecture's syscall opcode, then
// restoring after. Both x86_64's `0F 05` and arm64's `D4 00 00 01`
// fit. PC is guaranteed to be on an executable page since we're
// in a ptrace-stop on a running process.

const (
	x86SyscallOpcode  = uint32(0x000005_0F)       // 0F 05 (low 16 bits)
	arm64SVC0Encoding = uint32(0xD4000001)        // svc #0
)

// remoteSyscall executes one syscall inside the ptraced tracee and
// returns its return value (or -errno as a negative number, mirroring
// the kernel's raw return).
//
// `pid` must be a stopped tracee. The syscall is identified by `nr`
// with up to 6 args.
func remoteSyscall(pid int, nr uintptr, args ...uintptr) (uintptr, error) {
	if len(args) > 6 {
		return 0, fmt.Errorf("remoteSyscall: max 6 args, got %d", len(args))
	}
	var padded [6]uintptr
	for i, a := range args {
		padded[i] = a
	}

	// Save current regs so we can restore at the end.
	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceGetRegs: %w", err)
	}

	// Save the bytes we're about to overwrite.
	pc := getPC(&saved)
	var origInsn [8]byte
	if _, err := unix.PtracePeekData(pid, uintptr(pc), origInsn[:]); err != nil {
		return 0, fmt.Errorf("PtracePeekData orig: %w", err)
	}

	// Overlay the syscall instruction.
	var insn [8]byte
	copy(insn[:], origInsn[:])
	switch runtime.GOARCH {
	case "amd64":
		insn[0] = 0x0F
		insn[1] = 0x05
	case "arm64":
		// little-endian arm64 word: D4 00 00 01 → 01 00 00 D4
		insn[0] = 0x01
		insn[1] = 0x00
		insn[2] = 0x00
		insn[3] = 0xD4
	}
	if _, err := unix.PtracePokeData(pid, uintptr(pc), insn[:]); err != nil {
		return 0, fmt.Errorf("PtracePokeData syscall: %w", err)
	}

	// Build the register state for the syscall, preserving everything
	// except the syscall ABI registers + PC.
	regs := saved
	loadSyscallRegs(&regs, nr, padded)

	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("PtraceSetRegs: %w", err)
	}

	// Single-step the syscall.
	if err := unix.PtraceSingleStep(pid); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("PtraceSingleStep: %w", err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("Wait4 after syscall: %w", err)
	}
	if !ws.Stopped() {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("tracee not stopped after syscall (status=%v)", ws)
	}

	// Read result.
	var post unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &post); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("PtraceGetRegs post: %w", err)
	}

	// Restore the overwritten bytes.
	if _, err := unix.PtracePokeData(pid, uintptr(pc), origInsn[:]); err != nil {
		return 0, fmt.Errorf("PtracePokeData restore: %w", err)
	}

	// Restore the saved registers.
	if err := unix.PtraceSetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceSetRegs restore: %w", err)
	}

	return readSyscallResult(&post), nil
}

// remoteSyscallAtSIGSYS executes a syscall in the tracee at a SIGSYS
// signal-delivery-stop, WITHOUT modifying any process memory.
//
// The trick: at a RET_TRAP-induced SIGSYS stop, the kernel has already
// advanced PC past the SYSCALL/SVC #0 instruction that caused the trap.
// The original instruction bytes are still in place. We rewind PC by
// syscallInstSize so PTRACE_SINGLESTEP re-executes that same syscall
// instruction; setting arg5 to the bypass-secret makes the BPF filter
// return SECCOMP_RET_ALLOW instead of trapping again, so the syscall
// runs for real.
//
// Why this is the SIGSYS-stop-only fix and not a drop-in for the
// general remoteSyscall:
//
//   - remoteSyscall (the original) is also used at PTRACE_EVENT_EXEC
//     stops where PC points at the new binary's entry point, NOT
//     immediately after a SYSCALL instruction. There's no syscall byte
//     sequence to rewind to, so the original code overwrites the
//     bytes at PC with SYSCALL. That's safe in the post-exec context
//     because the tracee is the only thread of the process (execve
//     killed all siblings atomically).
//
//   - At a SIGSYS-stop from systrap-supervised's hot path, the tracee
//     IS multi-threaded — other threads are running normally and any
//     of them can fetch instructions from the same .text page that
//     remoteSyscall is poking. The original poke-and-restore race
//     surfaces as random SIGILL when a sibling thread executes the
//     overlayed bytes. See memory:project_caddy_sigill_systrap_
//     supervised.md for the architectural deep-dive.
//
// This rewind-only variant has zero process-wide instruction-memory
// side effects, so other threads can keep running concurrently.
//
// Caller MUST guarantee:
//   - pid is in a SIGSYS signal-delivery-stop (cause==0, sig==SIGSYS)
//   - PC was auto-advanced past a SYSCALL/SVC #0 instruction (always
//     true at RET_TRAP-induced SIGSYS-stops per seccomp(2))
//   - args[5] is set to the bypass-secret so the BPF filter ALLOWs
//     the re-issued syscall.
func remoteSyscallAtSIGSYS(pid int, nr uintptr, args ...uintptr) (uintptr, error) {
	if len(args) > 6 {
		return 0, fmt.Errorf("remoteSyscallAtSIGSYS: max 6 args, got %d", len(args))
	}
	var padded [6]uintptr
	for i, a := range args {
		padded[i] = a
	}

	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceGetRegs: %w", err)
	}

	// Rewind PC to the original SYSCALL/SVC instruction.
	rewindPC := getPC(&saved) - uint64(syscallInstSize)

	regs := saved
	setPC(&regs, rewindPC)
	loadSyscallRegs(&regs, nr, padded)

	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return 0, fmt.Errorf("PtraceSetRegs: %w", err)
	}

	if err := unix.PtraceSingleStep(pid); err != nil {
		return 0, fmt.Errorf("PtraceSingleStep: %w", err)
	}

	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("Wait4 after syscall: %w", err)
	}
	if !ws.Stopped() {
		return 0, fmt.Errorf("tracee not stopped after syscall (status=%v)", ws)
	}

	var post unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &post); err != nil {
		return 0, fmt.Errorf("PtraceGetRegs post: %w", err)
	}

	// Restore the saved regs so the tracee's view at SIGSYS-delivery
	// is exactly as it was — PC = past_syscall, original arg regs.
	// The caller (handleSIGSYSStop) will then overlay RAX/X0 with the
	// syscall result via writeSyscallReturn.
	if err := unix.PtraceSetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceSetRegs restore: %w", err)
	}

	return readSyscallResult(&post), nil
}
