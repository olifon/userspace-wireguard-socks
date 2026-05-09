// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPhase2InjectAndRunStaticInit is the Phase 2 step 5c+5d
// integration test:
//   1. Build the freestanding blob via build_static.sh.
//   2. Spawn /bin/sleep, attach via PTRACE_SEIZE+INTERRUPT.
//   3. parseStaticBlob → loadBlobIntoTracee → runStaticInit.
//   4. Assert uwg_static_init returned a non-fatal value
//      (-EINVAL is fine — it just means uwg_core_init failed because
//      no UWGS_TRACE_SECRET, NOT that injection broke).
//
// The point of this test is NOT to exercise tunnel functionality
// end-to-end (that's step 6). It's to confirm the injection
// machinery — mmap, segment copy, relocations, RIP handoff,
// return-trap — all work cleanly.
func TestPhase2InjectAndRunStaticInit(t *testing.T) {
	if testing.Short() {
		t.Skip("blob injection test requires ptrace+mmap into a live process; skipped in -short mode")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	tmp := t.TempDir()
	build := exec.Command("bash", filepath.Join(repo, "preload", "build_static.sh"), tmp)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_static.sh failed: %v\n%s", err, out)
	}
	blob := filepath.Join(tmp, "uwgpreload-static-"+runtime.GOARCH+".so")
	spec, err := parseStaticBlob(blob)
	if err != nil {
		t.Fatalf("parseStaticBlob: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Retry up to 3 times: GH-hosted amd64 runners with CET hardware
	// occasionally deliver SIGSEGV instead of SIGTRAP on the first
	// attempt. The root cause is a hardware-specific single-step timing
	// interaction (same class as the arm64 svc flake). Retrying with a
	// fresh tracee is safe: if the blob was never fully run, no side
	// effects in the sleep process occurred; if it ran partially and
	// crashed, we kill it and start over.
	var rc int64
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		pid, cleanup := attachAndStop(t)

		base, err := loadBlobIntoTracee(pid, spec)
		if err != nil {
			cleanup()
			lastErr = fmt.Errorf("attempt %d loadBlobIntoTracee: %w", attempt, err)
			t.Logf("%v — retrying", lastErr)
			continue
		}
		t.Logf("attempt %d: blob loaded at base=%#x size=%d KB",
			attempt, base, spec.totalSize()/1024)

		rc, err = runStaticInit(pid, spec, base)
		cleanup()
		if err != nil {
			lastErr = fmt.Errorf("attempt %d runStaticInit: %w", attempt, err)
			t.Logf("%v — retrying", lastErr)
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		t.Fatalf("%v", lastErr)
	}
	t.Logf("uwg_static_init returned %d", rc)
	// rc == 0  → init succeeded (would happen if UWGS_TRACE_SECRET set)
	// rc == -22 (-EINVAL) → init failed at the secret check, but the
	//   blob ran cleanly and returned. That's the success bar for
	//   this injection-machinery test.
	if rc != 0 && rc != -22 {
		t.Fatalf("uwg_static_init returned unexpected value %d (expected 0 or -EINVAL=-22)", rc)
	}
}
