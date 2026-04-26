// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestUwgRwlockSurvivesOwnerDeath compiles and runs the C regression
// test defined in uwg_lock_owner_death_test.c. The test forks a child
// that takes the write lock and SIGKILLs itself; the parent then
// acquires the lock and asserts it returns UWG_LOCK_POISONED within a
// small deadline instead of hanging. See the C file's header comment
// for the full story.
//
// This test is the load-bearing regression for the robust-mutex
// rewrite of the C-side rwlocks. If it ever times out on a future
// libc/kernel combo, the rewrite has regressed.
func TestUwgRwlockSurvivesOwnerDeath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only: robust pthread mutexes require Linux")
	}
	bin := filepath.Join(t.TempDir(), "uwg_lock_owner_death_test")
	build := exec.Command("cc",
		"-Wall", "-Wextra", "-O2",
		"-o", bin, "uwg_lock_owner_death_test.c",
		"-pthread", "-lpthread")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		t.Fatalf("test program failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("unexpected output: %q", out)
	}
}
