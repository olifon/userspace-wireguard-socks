// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && amd64

package main

import "golang.org/x/sys/unix"

// x86_64 syscall ABI: nr=rax, args = rdi rsi rdx r10 r8 r9.
// Result in rax.
func loadSyscallRegs(regs *unix.PtraceRegs, nr uintptr, args [6]uintptr) {
	regs.Rax = uint64(nr)
	regs.Rdi = uint64(args[0])
	regs.Rsi = uint64(args[1])
	regs.Rdx = uint64(args[2])
	regs.R10 = uint64(args[3])
	regs.R8 = uint64(args[4])
	regs.R9 = uint64(args[5])
	// Original_rax is what the kernel uses to restart syscalls;
	// setting it to nr keeps our intended syscall coherent.
	regs.Orig_rax = uint64(nr)
}

func readSyscallResult(regs *unix.PtraceRegs) uintptr {
	return uintptr(regs.Rax)
}

func getPC(regs *unix.PtraceRegs) uint64 { return regs.Rip }
