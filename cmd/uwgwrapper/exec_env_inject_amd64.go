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
