// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConcurrentRawSyscallSurvivesAutoCascade pins the auto-cascade
// fix for the systrap-supervised SIGILL on multi-threaded raw Go
// syscalls. The repro is exactly Caddy's net.ipStackCapabilities
// probe (and the same pattern Python's stdlib tickles in test_urllib):
// 8 concurrent goroutines each calling syscall.Socket(AF_INET6,
// SOCK_STREAM|CLOEXEC|NONBLOCK, IPPROTO_TCP) + setsockopt(IPV6_V6ONLY).
//
// Pre-fix this consistently SIGILL'd under systrap-supervised, which
// was the auto cascade's pick for dynamic targets with seccomp+ptrace.
// The current auto cascade picks systrap-elf (PT_INTERP injection, no
// ptracer at all) for dynamic targets with seccomp+memfd, which has
// no concurrency surface — the SIGSYS handler is per-thread, in-tracee,
// stateless. This test re-runs the auto cascade and asserts the repro
// doesn't crash.
//
// If a future change re-promotes systrap-supervised in the dynamic
// cascade (or otherwise breaks the multi-threaded raw-syscall path),
// this test goes red.
func TestConcurrentRawSyscallSurvivesAutoCascade(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	// Build the repro.
	repo := filepath.Clean(filepath.Join("..", ".."))
	repro := filepath.Join(t.TempDir(), "concurrent_raw_syscall")
	build := exec.Command("go", "build", "-o", repro,
		filepath.Join("tests", "preload", "testdata", "concurrent_raw_syscall.go"))
	build.Dir = repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build concurrent_raw_syscall: %v\n%s", err, out)
	}

	// Drive through the auto cascade.
	cmd := wrappedCommand(t, art, httpSock, "auto", repro, nil, wrapperRunOptions{})
	body, runErr := runCommandCombinedFileBacked(t, cmd)
	text := string(body)
	if runErr != nil {
		t.Fatalf("repro under auto cascade exited with error: %v\noutput=%s", runErr, text)
	}
	if strings.Contains(text, "SIGILL") || strings.Contains(text, "fatal error:") {
		t.Fatalf("auto cascade picked a transport that SIGILLs on concurrent raw syscalls — the supervisor concurrency bug is back. output=%s", text)
	}
	if !strings.Contains(text, "OK: concurrent_raw_syscall") {
		t.Fatalf("repro didn't reach success line. output=%s", text)
	}
}

// TestConcurrentRawSyscallExplicitSupervised pins the
// remoteSyscallAtSIGSYS fix: under EXPLICIT --transport=systrap-
// supervised, the same 8-goroutine concurrent raw-syscall repro
// (Caddy's net.ipStackCapabilities probe pattern) must complete
// without SIGILL.
//
// Pre-fix bug: remoteSyscall poked SYSCALL bytes at the tracee's PC
// via PTRACE_POKEDATA. Any sibling thread executing at the same
// .text address during the brief poke→singlestep→restore window
// would stumble through the overlayed bytes, advance into the
// middle of a wrong-decoded instruction, and SIGILL. The fix is to
// rewind PC to the original SYSCALL instruction at SIGSYS-stop (the
// bytes are still there) and SingleStep that — no memory poke = no
// process-wide instruction-text race.
//
// This test goes red if remoteSyscallAtSIGSYS regresses to memory-
// poke behaviour, or if the supervisor's wait-loop sends SIGSYS
// stops through the wrong code path.
//
// systrap-supervised is NOT in the dynamic auto cascade (see
// TestConcurrentRawSyscallSurvivesAutoCascade), so this pin only
// triggers when the user explicitly selects supervised — but that
// usage is real (browser sandboxes, scripts that exec into static
// descendants, anyone wanting ptrace-based introspection). The
// "all modes prod-ready" goal requires this to stay green.
func TestConcurrentRawSyscallExplicitSupervised(t *testing.T) {
	requirePhase1Toolchain(t)
	requireWrapperToolchain(t)
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	repro := filepath.Join(t.TempDir(), "concurrent_raw_syscall")
	build := exec.Command("go", "build", "-o", repro,
		filepath.Join("tests", "preload", "testdata", "concurrent_raw_syscall.go"))
	build.Dir = repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build concurrent_raw_syscall: %v\n%s", err, out)
	}

	cmd := wrappedCommand(t, art, httpSock, "systrap-supervised", repro, nil, wrapperRunOptions{})
	body, runErr := runCommandCombinedFileBacked(t, cmd)
	text := string(body)
	if runErr != nil {
		t.Fatalf("repro under --transport=systrap-supervised exited with error: %v\noutput=%s", runErr, text)
	}
	if strings.Contains(text, "SIGILL") || strings.Contains(text, "fatal error:") {
		t.Fatalf("systrap-supervised SIGILL'd on concurrent raw syscalls — the remoteSyscallAtSIGSYS rewind fix has regressed. output=%s", text)
	}
	if !strings.Contains(text, "OK: concurrent_raw_syscall") {
		t.Fatalf("repro didn't reach success line under systrap-supervised. output=%s", text)
	}
}

// TestCatalogRegressions pins the specific wrapper interop bugs the
// 2026-05 catalog batch fixed. Each subtest exercises one bug-prone
// syscall pattern that surfaced in a real production application:
//
//   tcp_setsockopt        — Python urllib 3.14 TCP_NODELAY EOPNOTSUPP
//                           regression. setsockopt on SOL_TCP /
//                           IPPROTO_IP / IPPROTO_IPV6 options must
//                           be silently swallowed on proxied fds;
//                           SOL_SOCKET options must still pass.
//
//   udp_getsockname       — mongod 8.0 "FailedToParse: Port 0 out
//                           of range parsing HostAndPort from
//                           0.0.0.0:0". getsockname on a bound-but-
//                           not-yet-proxied UDP fd must synthesize
//                           the tunnel-side bind addr from
//                           state.bound, not require state.proxied.
//
//   tcp_accept_inherits   — mongod accepted-fd getsockname returning
//                           0.0.0.0:0. The accepted-fd preload state
//                           must inherit bind_family/bind_port/bind_ip
//                           from its listener so the app sees a
//                           sensible "my address" answer.
//
// These regressions are silent failures in production: nothing fires
// an error log, the app just behaves wrong. They cost hours to
// diagnose in real apps. The catalog scripts caught them in the
// first place; this test ensures they never resurface.
//
// All binds use the tunnel-side WG addr (100.64.94.2 in the test
// harness), never loopback — uwgsocks's whole point is that bind
// goes through the wrapper into netstack.
func TestCatalogRegressions(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	// Build the catalog-regressions stub.
	repo := filepath.Clean(filepath.Join("..", ".."))
	stub := filepath.Join(t.TempDir(), "catalog_regressions_stub")
	build := exec.Command("gcc", "-O2", "-Wall", "-Wextra", "-o", stub,
		"tests/preload/testdata/catalog_regressions_stub.c")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build catalog_regressions_stub: %v\n%s", err, out)
	}
	art.stub = stub

	// 1. setsockopt swallow — drive the existing echo server at
	// 100.64.94.1:18080 (setupWrapperNetwork already serves it).
	t.Run("tcp_setsockopt", func(t *testing.T) {
		out, err := runStubExpectOK(t, art, httpSock, "tcp_setsockopt",
			"tcp_setsockopt", "100.64.94.1", "18080")
		if err != nil {
			t.Fatalf("tcp_setsockopt: %v\nout=%s", err, out)
		}
	})

	// 2. udp_getsockname — bind on the tunnel addr at a fresh port.
	t.Run("udp_getsockname", func(t *testing.T) {
		// Choose a stable high port not used by the echo servers.
		out, err := runStubExpectOK(t, art, httpSock, "udp_getsockname",
			"udp_getsockname", "100.64.94.2", "27101")
		if err != nil {
			t.Fatalf("udp_getsockname: %v\nout=%s", err, out)
		}
	})

	// 3. tcp_accept_inherits — stub binds + listens on tunnel addr,
	// test driver dials from serverEng (the WG peer) and writes a
	// sentry; stub asserts the accepted fd's getsockname returns the
	// listener's bind addr.
	t.Run("tcp_accept_inherits", func(t *testing.T) {
		bindIP, bindPort := "100.64.94.2", "27102"
		stdout, stderr, done := startStubAccept(t, art, httpSock,
			"tcp_accept_inherits", bindIP, bindPort)
		defer func() {
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Logf("stub did not exit; stderr=%s", stderr.String())
			}
		}()
		// Dial the wrapped listener through the WG peer.
		conn := retryTunnelDial(t, serverEng, "tcp", bindIP+":"+bindPort)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("regr-accept-inherits")); err != nil {
			conn.Close()
			t.Fatalf("write to wrapped listener: %v\nstderr=%s", err, stderr.String())
		}
		_ = conn.Close()
		// Wait for the stub to print its OK line and exit.
		ok, finalErr := waitForOK(stdout, done, 10*time.Second, "tcp_accept_inherits")
		if !ok || finalErr != nil {
			t.Fatalf("tcp_accept_inherits not OK: err=%v stderr=%s", finalErr, stderr.String())
		}
	})
}

// runStubExpectOK runs a non-listener stub subcommand through the
// wrapper, captures stdout, asserts the canonical "OK: <subname>" line.
func runStubExpectOK(t *testing.T, art wrapperArtifacts, httpSock, want string, stubArgs ...string) (string, error) {
	t.Helper()
	cmd := wrappedCommand(t, art, httpSock, "systrap", art.stub, stubArgs, wrapperRunOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out := make(chan struct {
		body []byte
		err  error
	}, 1)
	go func() {
		// Use the file-backed combined-output helper so we don't race the
		// os/exec stderr-copy goroutine.
		body, err := runCommandCombinedFileBacked(t, cmd)
		out <- struct {
			body []byte
			err  error
		}{body, err}
	}()
	select {
	case res := <-out:
		text := string(res.body)
		if res.err != nil {
			return text, fmt.Errorf("stub exit: %w", res.err)
		}
		if !strings.Contains(text, "OK: "+want) {
			return text, fmt.Errorf("missing OK: %s", want)
		}
		return text, nil
	case <-ctx.Done():
		killProcessGroup(cmd)
		return "", errors.New("stub timed out")
	}
}

// startStubAccept starts the listener stub and returns reader handles
// for its stdout + stderr. Caller dials the listener and waits for the
// OK line via waitForOK.
func startStubAccept(t *testing.T, art wrapperArtifacts, httpSock string, stubArgs ...string) (*safeBuffer, *safeBuffer, chan error) {
	t.Helper()
	cmd := wrappedCommand(t, art, httpSock, "systrap", art.stub, stubArgs, wrapperRunOptions{})
	stdoutBuf := &safeBuffer{}
	stderrBuf := &safeBuffer{}
	stdoutR, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrR, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Stream stdout + stderr into thread-safe buffers; bridge to done.
	go func() { _, _ = io.Copy(stdoutBuf, stdoutR) }()
	go func() { _, _ = io.Copy(stderrBuf, stderrR) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// Wait for the stub's LISTENING marker on stderr before returning,
	// so the caller's dial doesn't race the bind+listen.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stderrBuf.String(), "LISTENING ") {
			return stdoutBuf, stderrBuf, done
		}
		select {
		case err := <-done:
			t.Fatalf("stub exited before listening: err=%v stderr=%s", err, stderrBuf.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
	killProcessGroup(cmd)
	<-done
	t.Fatalf("stub never printed LISTENING; stderr=%s", stderrBuf.String())
	return nil, nil, nil
}

// waitForOK polls a safeBuffer until either the canonical "OK: <want>"
// appears in its contents or the stub exits / the deadline passes.
func waitForOK(stdout *safeBuffer, done chan error, timeout time.Duration, want string) (bool, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), "OK: "+want) {
			return true, nil
		}
		select {
		case err := <-done:
			if strings.Contains(stdout.String(), "OK: "+want) {
				return true, nil
			}
			return false, err
		case <-time.After(100 * time.Millisecond):
		}
	}
	return false, errors.New("timeout waiting for OK")
}

// safeBuffer is a tiny io.Writer + Stringer that locks on every
// operation. The os/exec stderr/stdout copy goroutines mutate the
// buffer while the test's main goroutine reads it for the LISTENING
// marker — `bytes.Buffer` alone would race under -race.
type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// Compile-time sanity: ensure the helpers we reference from
// ptrace_test.go are in scope (forces a compile error if a future
// refactor renames them).
var (
	_ = bufio.NewReader
	_ = (*net.TCPConn)(nil)
	_ = netip.MustParseAddrPort
)
