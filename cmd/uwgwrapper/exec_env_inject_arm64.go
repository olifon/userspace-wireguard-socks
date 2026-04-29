// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && arm64

package main

import "golang.org/x/sys/unix"

// arm64 syscall ABI: nr in x8, args in x0..x5. PtraceRegs.Regs is
// [31]uint64 holding x0..x30.

func syscallNrFromRegs(regs *unix.PtraceRegs) uintptr {
	return uintptr(regs.Regs[8])
}

func readSyscallArg(regs *unix.PtraceRegs, n int) uint64 {
	if n < 0 || n > 5 {
		return 0
	}
	return regs.Regs[n]
}

// writeSyscallReturn sets the syscall return register (X0 on arm64).
func writeSyscallReturn(regs *unix.PtraceRegs, v uint64) {
	regs.Regs[0] = v
}

func writeSyscallArg(regs *unix.PtraceRegs, n int, v uint64) {
	if n < 0 || n > 5 {
		return
	}
	regs.Regs[n] = v
}

// stackScratchAddr returns a tracee stack address safe for writing a blob
// of the given size at a PTRACE_EVENT_SECCOMP stop. arm64 (AAPCS64) has
// no red zone; write immediately below SP, aligned to 16 bytes.
func stackScratchAddr(regs *unix.PtraceRegs, size uintptr) uintptr {
	return uintptr(regs.Sp) - (size+15)&^15
}
