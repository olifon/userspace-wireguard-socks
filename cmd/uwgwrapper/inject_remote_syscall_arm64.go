// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && arm64

package main

import "golang.org/x/sys/unix"

// arm64 syscall ABI: nr=x8, args = x0 x1 x2 x3 x4 x5. Result in x0.
func loadSyscallRegs(regs *unix.PtraceRegs, nr uintptr, args [6]uintptr) {
	regs.Regs[8] = uint64(nr)
	for i := 0; i < 6; i++ {
		regs.Regs[i] = uint64(args[i])
	}
}

func readSyscallResult(regs *unix.PtraceRegs) uintptr {
	return uintptr(regs.Regs[0])
}

func getPC(regs *unix.PtraceRegs) uint64 { return regs.Pc }
