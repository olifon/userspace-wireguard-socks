// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestDispatchTableCoverage verifies that every syscall in the preload's
// unconditional seccomp trap list is handled by the dispatch table.
//
// The test builds the phase1 preload .so and a small C exerciser program
// (testdata/dispatch_cov_client.c), then runs the exerciser under
// LD_PRELOAD.  The exerciser calls every syscall that the seccomp BPF
// filter will trap (queried via uwg_seccomp_trapped_list()) and asserts:
//
//  1. None of the trapped syscalls returns ENOSYS — ENOSYS means the
//     dispatch table has no handler for that syscall.
//  2. uwg_sigsys_stats() shows unhandled_delta == 0 — the SIGSYS path
//     (when exercised) never returned -ENOSYS for a trapped syscall.
//
// Architecture note: under LD_PRELOAD the libc shim (shim_libc/shim_socket.c)
// intercepts socket/connect/bind/etc. at the libc-symbol level, calling
// uwg_dispatch() directly without raising SIGSYS.  The uwg_sigsys_calls
// counter is therefore not incremented by this test; SIGSYS end-to-end
// is verified separately by sigsys_test.c which installs the filter
// directly (without LD_PRELOAD).
//
// This test catches the "trap list and dispatch table are out of sync"
// class of bugs: a syscall added to seccomp.c's uwg_trapped_syscalls[]
// without a matching case in dispatch.c's uwg_dispatch().
func TestDispatchTableCoverage(t *testing.T) {
	requirePhase1Toolchain(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	// Build the phase1 preload .so.
	preloadSO := filepath.Join(tmp, "uwgpreload-phase1-disp.so")
	buildCmd := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), preloadSO)
	buildCmd.Dir = repo
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}

	// Compile the C dispatch coverage exerciser.  srcPath is relative to
	// repo (the working directory for the gcc invocation), matching the
	// pattern used by buildPhase1Artifacts for stub_client.c.
	exerciser := filepath.Join(tmp, "dispatch_cov_client")
	srcPath := filepath.Join("tests", "preload", "testdata", "dispatch_cov_client.c")
	gccCmd := exec.Command("gcc", "-O2", "-Wall", "-o", exerciser, srcPath, "-ldl")
	gccCmd.Dir = repo
	if out, err := gccCmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc dispatch_cov_client.c: %v\n%s", err, out)
	}

	// Run the exerciser under LD_PRELOAD.  Point UWGS_FDPROXY to a
	// non-existent socket path so fdproxy-dependent calls fail cleanly
	// (ENOENT / ECONNREFUSED) rather than blocking on a dial attempt.
	runEnv := append(os.Environ(),
		"LD_PRELOAD="+preloadSO,
		"UWGS_FDPROXY="+filepath.Join(tmp, "nonexistent.sock"),
	)
	runCmd := exec.Command(exerciser)
	runCmd.Env = runEnv

	out, err := runCmd.CombinedOutput()
	t.Logf("dispatch_cov_client output:\n%s", out)

	output := string(out)

	// The exerciser exits 0 only on full pass; any exit != 0 is a failure.
	if err != nil {
		t.Fatalf("dispatch_cov_client failed: %v", err)
	}

	// Verify the "PASS" sentinel is present in stdout.
	if !strings.Contains(output, "PASS\n") {
		t.Fatalf("dispatch_cov_client did not print PASS")
	}

	// Double-check UNHANDLED_DELTA == 0 from the parsed output.
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "UNHANDLED_DELTA ") {
			v, perr := strconv.ParseUint(strings.TrimPrefix(line, "UNHANDLED_DELTA "), 10, 64)
			if perr != nil {
				t.Fatalf("parse UNHANDLED_DELTA: %v", perr)
			}
			if v != 0 {
				t.Fatalf("UNHANDLED_DELTA=%d: dispatch returned -ENOSYS for trapped syscalls "+
					"— trap list and dispatch table are out of sync", v)
			}
		}
	}

	// Verify that NOT_DISPATCHED lines are absent.
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "NOT_DISPATCHED") {
			t.Errorf("syscall not dispatched: %s", line)
		}
	}

	// Sanity: TRAP_LIST_LEN must be > 0.
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "TRAP_LIST_LEN ") {
			v, perr := strconv.ParseUint(strings.TrimPrefix(line, "TRAP_LIST_LEN "), 10, 64)
			if perr != nil {
				t.Fatalf("parse TRAP_LIST_LEN: %v", perr)
			}
			if v == 0 {
				t.Fatalf("TRAP_LIST_LEN=0: trap list is empty")
			}
			t.Logf("trap list covers %d syscalls", v)
		}
	}

}
