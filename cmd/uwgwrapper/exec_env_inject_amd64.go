// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && amd64

package main

import "golang.org/x/sys/unix"

// x86_64 syscall ABI: nr in rax (Orig_rax for entry stops), args in
// rdi rsi rdx r10 r8 r9.

func syscallNrFromRegs(regs *unix.PtraceRegs) uintptr {
	return uintptr(regs.Orig_rax)
}

func readSyscallArg(regs *unix.PtraceRegs, n int) uint64 {
	switch n {
	case 0:
		return regs.Rdi
	case 1:
		return regs.Rsi
	case 2:
		return regs.Rdx
	case 3:
		return regs.R10
	case 4:
		return regs.R8
	case 5:
		return regs.R9
	}
	return 0
}

// writeSyscallReturn sets the syscall return register (RAX on amd64).
// Used by the SIGSYS-stop handler to inject a passthrough syscall's
// result into the tracee's view.
func writeSyscallReturn(regs *unix.PtraceRegs, v uint64) {
	regs.Rax = v
}

func writeSyscallArg(regs *unix.PtraceRegs, n int, v uint64) {
	switch n {
	case 0:
		regs.Rdi = v
	case 1:
		regs.Rsi = v
	case 2:
		regs.Rdx = v
	case 3:
		regs.R10 = v
	case 4:
		regs.R8 = v
	case 5:
		regs.R9 = v
	}
}

// stackScratchAddr returns a tracee stack address safe for writing a blob
// of the given size at a PTRACE_EVENT_SECCOMP stop. The x86-64 SysV ABI
// reserves 128 bytes below RSP as a red zone for leaf functions; we write
// below that so no live data is disturbed even if execve fails and the
// tracee continues running in the original image.
func stackScratchAddr(regs *unix.PtraceRegs, size uintptr) uintptr {
	return uintptr(regs.Rsp) - 128 - (size+15)&^15
}
