// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestWrapperExitCodePassthrough verifies that uwgwrapper propagates the
// wrapped binary's exit code exactly, for preload and systrap-supervised.
//
// This doubles as the "no mode retry on non-zero exit" regression test:
// if the wrapper silently retried a mode after the binary returned non-zero,
// it would either exit with a different code or take much longer than expected.
func TestWrapperExitCodePassthrough(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	tmp, err := os.MkdirTemp(os.TempDir(), "uwgs-ec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })

	cases := []struct {
		wantCode  int
		transport string
	}{
		{0, "preload"},
		{1, "preload"},
		{42, "preload"},
		{0, "systrap-supervised"},
		{1, "systrap-supervised"},
		{42, "systrap-supervised"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%s/exit%d", tc.transport, tc.wantCode), func(t *testing.T) {
			listenSock := filepath.Join(tmp, fmt.Sprintf("fp-%s-%d.sock", tc.transport[:4], tc.wantCode))
			wrapperArgs := []string{
				"--transport=" + tc.transport,
				"--listen", listenSock,
				"--api", "unix:" + httpSock,
				"--socket-path", "/uwg/socket",
				"--", "/bin/sh", "-c", fmt.Sprintf("exit %d", tc.wantCode),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

			runErr := cmd.Run()

			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("wrapper timed out (transport=%s, exit=%d)", tc.transport, tc.wantCode)
			}

			got := 0
			if runErr != nil {
				var ee *exec.ExitError
				if errors.As(runErr, &ee) {
					got = ee.ExitCode()
				} else {
					t.Fatalf("wrapper run error (not ExitError): %v", runErr)
				}
			}
			if got != tc.wantCode {
				t.Fatalf("transport=%s: wrapped binary exit %d, wrapper exited %d (want %d)",
					tc.transport, tc.wantCode, got, tc.wantCode)
			}
		})
	}
}

// TestWrapperStaticPreloadError verifies that --transport=preload refuses to
// run a statically-linked binary and exits non-zero, and that --force-preload
// overrides the safety check.
func TestWrapperStaticPreloadError(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	tmp, err := os.MkdirTemp(os.TempDir(), "uwgs-spf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })

	// Build a minimal statically-linked binary.
	staticSrc := filepath.Join(tmp, "static_main.c")
	if err := os.WriteFile(staticSrc, []byte("int main(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	staticBin := filepath.Join(tmp, "static_main")
	if out, berr := exec.Command("gcc", "-static", "-o", staticBin, staticSrc).CombinedOutput(); berr != nil {
		t.Skipf("gcc -static not available (glibc-static may be missing): %v\n%s", berr, out)
	}

	listenSock := filepath.Join(tmp, "fp-spf.sock")

	// Without --force-preload: wrapper must exit non-zero.
	t.Run("error_without_override", func(t *testing.T) {
		cmd := exec.Command(art.wrapper,
			"--transport=preload",
			"--listen", listenSock,
			"--api", "unix:"+httpSock,
			"--socket-path", "/uwg/socket",
			"--", staticBin,
		)
		out, runErr := cmd.CombinedOutput()
		if runErr == nil {
			t.Fatalf("expected non-zero exit for preload on static binary; got 0\noutput: %s", out)
		}
		t.Logf("output: %s", out)
	})

	// With --force-preload: wrapper must not abort; binary runs (unintercepted).
	t.Run("override_with_force_preload", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, art.wrapper,
			"--transport=preload",
			"--force-preload",
			"--listen", listenSock,
			"--api", "unix:"+httpSock,
			"--socket-path", "/uwg/socket",
			"--", staticBin,
		)
		runErr := cmd.Run()
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatal("timed out")
		}
		// staticBin exits 0; wrapper should pass that through.
		if runErr != nil {
			var ee *exec.ExitError
			if errors.As(runErr, &ee) {
				t.Fatalf("static binary + --force-preload: wrapper exited %d, want 0", ee.ExitCode())
			}
			t.Fatalf("static binary + --force-preload: unexpected run error: %v", runErr)
		}
	})
}
