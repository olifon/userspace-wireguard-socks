//go:build !windows && diag

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Build with -tags diag. Diagnostic test for the curl/bare-ptrace
// hang. Runs curl -v through each ptrace-only mode and captures both
// curl's verbose output (which step it stalls at) and the wrapper's
// per-syscall trace, so we can see exactly which syscall the tracee
// makes that the tracer fails to complete. Skipped from the normal
// suite via the build tag because it leaks process state on failure
// and is intentionally tolerant of long timeouts.
//
//	go test -tags diag -run TestCurlPtraceHangDiagnostic -v ./tests/preload/

package preload_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// (TestPtraceNonblockConnectFlow lives in connect_nonblock_test.go
// — the always-on regression-pin for the bare-ptrace connect flow.)

func TestCurlPtraceHangDiagnostic(t *testing.T) {
	requireWrapperToolchain(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl required")
	}
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)
	// Same shape as TestUWGWrapperCurlAcrossTransports: real
	// http.Server on port 18083 of the tunnel side, returning a
	// fixed body. This is the configuration the failing test uses
	// and it's what we need to reproduce the wrapper-doesn't-exit
	// hang.
	ln, lerr := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18083"))
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	defer ln.Close()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "curl-over-wrapper")
		}))
	}()

	for _, transport := range []string{"ptrace-only", "ptrace-seccomp", "ptrace"} {
		t.Run(transport, func(t *testing.T) {
			diagDir := t.TempDir()
			statsPath := filepath.Join(diagDir, "trace-stats.json")
			stderrPath := filepath.Join(diagDir, "stderr.log")
			stdoutPath := filepath.Join(diagDir, "stdout.log")

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			// Two flag-shapes: verbose-on (which I saw exit 7 in 120ms)
			// and verbose-off (which the original test hung 90s on).
			// If they differ, the bug is verbose-/buffering-sensitive.
			// Use the EXACT args the failing test uses, against the
			// 18083 port that has no listener in this diag's setup
			// (the failing test has its own listener; we don't).
			// curl will fail to connect quickly, then we measure
			// how long the WRAPPER takes to exit after curl dies.
			args := []string{"--max-time", "15", "-v", "-fsS", "http://100.64.94.1:18083/"}
			runOpts := wrapperRunOptions{
				env: map[string]string{
					"UWGS_TRACE_STATS_PATH": statsPath,
					// Always enable wrapper verbose so we can see
					// syscall traces; we'll filter them out for the
					// "curl -v lines" view.
					"UWGS_TEST_DEBUG": "1",
				},
				wrapperArgs: []string{"-v"},
			}
			_ = runOpts
			base := wrappedCommand(t, art, httpSock, transport, "curl", args, runOpts)
			// Push curl's -v output to a separate file via shell
			// indirection so it doesn't interleave with the wrapper's
			// own stderr lines (which made the previous capture
			// unreadable).
			curlVerboseFile := filepath.Join(diagDir, "curl-verbose.log")
			origArgs := base.Args[1:]
			// Build a sh -c that runs the wrapper but redirects fd2
			// of curl alone. Since the wrapper takes the curl args,
			// we can't easily separate. Use trace-stderr approach
			// instead: redirect everything wrapper-stderr to one file
			// (already done), and parse curl lines (start with "* ",
			// "> ", "< ") later.
			_ = curlVerboseFile
			cmd := exec.CommandContext(ctx, base.Path, origArgs...)
			cmd.Env = base.Env
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			stdoutF, _ := os.Create(stdoutPath)
			stderrF, _ := os.Create(stderrPath)
			cmd.Stdout = stdoutF
			cmd.Stderr = stderrF
			start := time.Now()
			err := cmd.Run()
			dur := time.Since(start)
			_ = stdoutF.Close()
			_ = stderrF.Close()
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}

			stdout, _ := os.ReadFile(stdoutPath)
			stderr, _ := os.ReadFile(stderrPath)
			stats, _ := os.ReadFile(statsPath)
			// Extract curl's verbose lines: they start with "* ",
			// "> ", "< ", "} ", "{ ". Wrapper lines start with
			// "uwgwrapper:". This gives us a clean curl-only view.
			var curlOnly []byte
			for _, line := range bytes.Split(stderr, []byte("\n")) {
				trimmed := bytes.TrimLeft(line, " \t")
				if len(trimmed) >= 2 && (trimmed[0] == '*' || trimmed[0] == '>' || trimmed[0] == '<' || trimmed[0] == '}' || trimmed[0] == '{') && trimmed[1] == ' ' {
					curlOnly = append(curlOnly, line...)
					curlOnly = append(curlOnly, '\n')
				}
			}
			t.Logf("=== %s: dur=%s err=%v ===", transport, dur, err)
			t.Logf("--- curl -v lines ---\n%s", curlOnly)
			// Also dump raw stderr (last 2KB) and stdout in case
			// the curl-only filter missed lines because they
			// arrived after the kill.
			// Last 30 syscalls the tracer saw. The hang means the
			// LAST syscall is the one that blocked (or the next one
			// the tracee tried but tracer never released).
			var syscallLines [][]byte
			for _, line := range bytes.Split(stderr, []byte("\n")) {
				if bytes.Contains(line, []byte("uwgwrapper: tid=")) && bytes.Contains(line, []byte("syscall=")) {
					syscallLines = append(syscallLines, line)
				}
			}
			tailFrom := len(syscallLines) - 40
			if tailFrom < 0 {
				tailFrom = 0
			}
			t.Logf("--- last %d wrapper syscall lines (of %d) ---", len(syscallLines)-tailFrom, len(syscallLines))
			for _, l := range syscallLines[tailFrom:] {
				t.Logf("  %s", l)
			}
			t.Logf("--- raw stdout (last 512B) ---\n%s", tail(stdout, 512))
			t.Logf("--- curl stdout (last 1KB) ---\n%s", tail(stdout, 1024))
			t.Logf("--- trace stats ---\n%s", string(stats))
			if dur < 6*time.Second && err == nil {
				t.Logf("RESULT %s: completed cleanly in %s", transport, dur)
			} else {
				t.Logf("RESULT %s: HUNG or FAILED (dur=%s err=%v) — see stderr above", transport, dur, err)
			}
		})
	}
}

func tail(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return fmt.Sprintf("...[%d bytes truncated]\n%s", len(b)-n, string(b[len(b)-n:]))
}
