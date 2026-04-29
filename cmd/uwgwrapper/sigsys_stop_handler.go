// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// isSupervisedExtraSyscall returns true for the syscalls whose
// SIGSYS-stops the supervisor handles via passthrough remoteSyscall.
// MUST stay in sync with uwg_trapped_extra_supervised[] in
// preload/core/seccomp.c. Other trapped syscalls (socket-family) are
// dispatched by the in-tracee handler and must forward.
func isSupervisedExtraSyscall(nr uintptr) bool {
	switch nr {
	case unix.SYS_READ,
		unix.SYS_WRITE,
		unix.SYS_CLOSE,
		unix.SYS_DUP,
		unix.SYS_DUP3,
		unix.SYS_FCNTL:
		return true
	}
	return false
}

// handleSIGSYSStop handles a SIGSYS signal-delivery-stop by acting as
// the inert pre-init handler for the post-execve raw-asm coverage gap
// (#92). Implements Design B from preload/core/sigsys_inert_stub.c:
// supervisor-as-handler.
//
// At the post-execve window the tracee's SIGSYS sa_handler is reset
// to SIG_DFL but the inherited seccomp filter is active. Without this
// handler, every trapped syscall during libc-init terminates the
// tracee. With it, the supervisor catches the signal-stop, runs the
// syscall on the tracee's behalf via remoteSyscall (which carries the
// bypass secret in arg6 and so passes our own filter), writes the
// result into the tracee's RAX/X0, and suppresses SIGSYS.
//
// Once the LD_PRELOAD'd phase1.so constructor runs and reinstalls the
// dispatching uwg_sigsys_handler in-tracee, future SIGSYS events
// could be delivered to that handler instead. The window-detection
// design (per the doc) is conservative: we always handle here. The
// in-tracee dispatcher's logic for socket-family syscalls is reached
// via the existing RET_TRAP path with the in-tracee handler installed,
// which is unchanged. This handler only fires for the new expanded
// trap subset (read/write/close/dup/dup2/dup3/fcntl) — those calls
// are kernel-passthrough at the dispatcher layer too (no tunnel-
// framing), so supervisor passthrough is behaviorally equivalent.
//
// PC handling: at RET_TRAP-induced SIGSYS-delivery, the kernel has
// already advanced PC past the syscall instruction. PtraceCont after
// our register rewrite resumes from there, so PC needs no adjustment.
//
// Returns true if the stop was a SIGSYS we handled (caller should NOT
// re-deliver), false if it was something else (caller falls through
// to its normal sig-deliver path).
func handleSIGSYSStop(pid int, sig syscall.Signal, bypassSecret uint64) (handled bool, err error) {
	if sig != syscall.SIGSYS {
		return false, nil
	}
	if bypassSecret == 0 {
		// No secret available — can't passthrough. Forward to
		// tracee (which dies if no handler, but that's the same
		// failure mode as before this handler existed).
		return false, nil
	}

	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return true, fmt.Errorf("PtraceGetRegs at SIGSYS-stop: %w", err)
	}

	syscallNr := syscallNrFromRegs(&regs)
	if syscallNr == 0 || int64(syscallNr) < 0 {
		return false, nil
	}
	// Only handle the supervised-extra subset here. The socket-family
	// trapped syscalls have an in-tracee dispatcher (uwg_dispatch +
	// per-op handlers in preload/core/) that knows about tunnel-fd
	// state, framing, fdproxy, etc. — supervisor passthrough would
	// bypass all that and hit the kernel with non-routable tunnel
	// IPs (e.g. connect() returning ENETUNREACH on 100.64.94.x).
	// Forward those to the tracee's installed handler.
	if !isSupervisedExtraSyscall(syscallNr) {
		return false, nil
	}

	a0 := uintptr(readSyscallArg(&regs, 0))
	a1 := uintptr(readSyscallArg(&regs, 1))
	a2 := uintptr(readSyscallArg(&regs, 2))
	a3 := uintptr(readSyscallArg(&regs, 3))
	a4 := uintptr(readSyscallArg(&regs, 4))

	// Issue the syscall on the tracee's behalf via remoteSyscall.
	// remoteSyscall takes up to 6 args; we put the bypass secret in
	// the 6th positional (index 5) so the seccomp filter's bypass-
	// check at the top of the BPF program ALLOWs the call without
	// re-trapping. The original syscall's arg5 (if any) is dropped
	// — the trap-list candidates (read/write/close/dup/dup2/dup3/
	// fcntl) all have ≤ 4 args, so this is safe.
	rc, callErr := remoteSyscall(pid, syscallNr, a0, a1, a2, a3, a4, uintptr(bypassSecret))
	if callErr != nil {
		return true, fmt.Errorf("remoteSyscall on behalf of tracee at SIGSYS-stop: %w", callErr)
	}

	// remoteSyscall already restored the saved regs as part of its
	// teardown, so the tracee's view of regs is exactly as it was
	// at SIGSYS-delivery — including PC past the trapped syscall
	// instruction (kernel auto-advanced before delivering). Now
	// override RAX/X0 with our result and PtraceSetRegs.
	post := regs
	writeSyscallReturn(&post, uint64(rc))
	if err := unix.PtraceSetRegs(pid, &post); err != nil {
		return true, fmt.Errorf("PtraceSetRegs after passthrough: %w", err)
	}
	if os.Getenv("UWGS_WRAPPER_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "uwgwrapper: SIGSYS-stop pid=%d nr=%d args=[%#x %#x %#x %#x %#x] -> %d\n",
			pid, syscallNr, a0, a1, a2, a3, a4, int64(rc))
	}
	return true, nil
}
