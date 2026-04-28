//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSystrapSupervisedDynamicEcho is the basic happy path:
// systrap-supervised mode wrapping a *dynamic* C client. Should be
// indistinguishable from `systrap` for this case (the supervisor
// observes the post-exec stop but does nothing because the image
// has PT_INTERP — LD_PRELOAD propagation re-runs the .so
// constructor in the wrapped target itself).
func TestSystrapSupervisedDynamicEcho(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-supervised", art.stub,
		[]string{"100.64.94.1", "18080", "supervised-dynamic-tcp", "tcp"},
		wrapperRunOptions{timeout: 30 * time.Second})

	if !strings.Contains(string(out), "supervised-dynamic-tcp") {
		t.Fatalf("expected sentinel in output; got %q", out)
	}
}

// TestSystrapSupervisedDynamicExecsStatic is the load-bearing test:
// a wrapped *dynamic* shell that exec's a *static* binary. Without
// the supervisor, the static child loses interception entirely
// (the kernel inherits the seccomp filter but no SIGSYS handler is
// installed in the static child, and there's no LD_PRELOAD path).
// With the supervisor, every execve hits SECCOMP_RET_TRACE; the
// supervisor inspects the new image, sees no PT_INTERP, and
// injects the freestanding blob.
//
// We test by:
//  1. Building the C stub_client as a static binary (CGO-free).
//  2. Wrapping `/bin/sh -c "<static_stub_client> 100.64.94.1 ..."`
//     which is dynamic + exec's the static stub mid-script.
//  3. Asserting the static stub completes its tunnel TCP echo
//     successfully — possible only if the supervisor re-armed
//     interception in the static child.
func TestSystrapSupervisedDynamicExecsStatic(t *testing.T) {
	requirePhase1Toolchain(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	// Build a fresh static stub_client. Same recipe as
	// TestPhase2StaticBinaryEchoTCP.
	staticStub := filepath.Join(tmp, "stub_static")
	gccCmd := exec.Command("gcc", "-static", "-O2",
		"-o", staticStub,
		filepath.Join(repo, "tests", "preload", "testdata", "stub_client.c"))
	if out, err := gccCmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc -static failed: %v\n%s", err, out)
	}

	// Build the freestanding blob (needed by the supervisor for
	// the static child re-arm).
	build := exec.Command("bash", filepath.Join("preload", "build_static.sh"), tmp)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_static.sh: %v\n%s", err, out)
	}
	blob := filepath.Join(tmp, "uwgpreload-static-"+runtime.GOARCH+".so")
	if _, err := os.Stat(blob); err != nil {
		t.Fatalf("blob not produced: %v", err)
	}

	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	// /bin/sh -c '<static_stub> ...' — sh is dynamic, the static
	// stub is what we're trying to re-arm via the supervisor.
	shellCmd := fmt.Sprintf("%s 100.64.94.1 18080 supervised-static-tcp tcp",
		staticStub)
	args := []string{"-c", shellCmd}

	wrapperArgs := []string{
		"--transport=systrap-supervised",
		"--listen", filepath.Join(tmp, "fdproxy.sock"),
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--", "/bin/sh",
	}
	wrapperArgs = append(wrapperArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = append(os.Environ(), "UWGS_STATIC_BLOB="+blob)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== supervised dynamic→static output ===\n%s\n=== end ===", out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("timed out waiting for /bin/sh -> static child")
	}
	if err != nil {
		t.Fatalf("wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "supervised-static-tcp") {
		t.Fatalf("expected sentinel %q in output; got %q",
			"supervised-static-tcp", out)
	}
}
