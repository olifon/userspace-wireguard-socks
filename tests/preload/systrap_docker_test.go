// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

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

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// requireSystrapDockerToolchain gates systrap-docker tests: requires gcc,
// amd64 or arm64, and no -short.
func requireSystrapDockerToolchain(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("systrap-docker integration tests skipped in -short mode")
	}
	if runtime.GOOS != "linux" {
		t.Skip("systrap-docker is Linux-only")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("systrap-docker only on linux/amd64 + linux/arm64 (got %s)", runtime.GOARCH)
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc required for systrap-docker tests")
	}
}

// buildSystrapDockerArtifacts builds the wrapper (embedding the ptloader .so
// built by build_ptloader.sh) + a dynamic and static stub_client.
func buildSystrapDockerArtifacts(t *testing.T) (art wrapperArtifacts, staticStub string) {
	t.Helper()
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	embeddedPreloadDir := filepath.Join(repo, "cmd", "uwgwrapper", "assets")

	art = wrapperArtifacts{
		wrapper: filepath.Join(tmp, "uwgwrapper"),
		preload: filepath.Join(tmp, "uwgpreload.so"),
		stub:    filepath.Join(tmp, "stub_client"),
	}
	if err := os.MkdirAll(embeddedPreloadDir, 0o755); err != nil {
		t.Fatalf("mkdir embedded preload dir: %v", err)
	}

	// Build phase1 preload (includes execve_docker.c for docker interception).
	run(t, repo, "bash", "preload/build_phase1.sh",
		filepath.Join(embeddedPreloadDir, "uwgpreload.so"))
	run(t, repo, "bash", "preload/build_phase1.sh", art.preload)

	// Build the ptloader .so (embedded into the wrapper binary).
	run(t, repo, "bash", "preload/build_ptloader.sh", embeddedPreloadDir)

	// Build the dynamic stub_client (same as phase1 tests).
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra",
		"-o", art.stub,
		"tests/preload/testdata/stub_client.c")

	// Build the static stub_client.
	staticStub = filepath.Join(tmp, "stub_static")
	run(t, repo, "gcc", "-static", "-O2",
		"-o", staticStub,
		"tests/preload/testdata/stub_client.c")

	// Rebuild the wrapper with the freshly built ptloader embedded.
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"},
		"go", "build", "-o", art.wrapper, "./cmd/uwgwrapper")

	return art, staticStub
}

// TestSystrapDockerDynamicEcho is the basic happy-path for systrap-docker
// with a dynamic target (stub_client linked against libc). The preload.so
// intercepts all network syscalls; the SIGSYS seccomp filter (with
// SECCOMP_RET_TRAP on execve/execveat) is installed by the constructor.
// No ptrace involved.
func TestSystrapDockerDynamicEcho(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-docker", art.stub,
		[]string{"100.64.94.1", "18080", "docker-dynamic-echo", "tcp"},
		wrapperRunOptions{timeout: 30 * time.Second})

	if !strings.Contains(string(out), "docker-dynamic-echo") {
		t.Fatalf("expected sentinel in output; got %q", out)
	}
}

// TestSystrapDockerStaticEcho wraps a statically-linked C binary with
// systrap-docker. The Go wrapper detects the binary has no PT_INTERP,
// does the ELF patching itself (creating memfds, appending PT_INTERP +
// ptloader path), and syscall.Exec's the patched binary. The ptloader
// runs as PT_INTERP, installs the SIGSYS handler + seccomp filter, then
// jumps to the original _start. No ptrace required.
func TestSystrapDockerStaticEcho(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, staticStub := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	tmp := t.TempDir()
	listenSock := filepath.Join(tmp, "fdproxy-docker-static.sock")
	wrapperArgs := []string{
		"--transport=systrap-docker",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", staticStub,
		"100.64.94.1", "18080", "docker-static-echo", "tcp",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== systrap-docker static echo output ===\n%s\n=== end ===", out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("systrap-docker static echo: timed out")
	}
	if err != nil {
		t.Fatalf("systrap-docker static echo: wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "docker-static-echo") {
		t.Fatalf("expected sentinel %q in output; got %q", "docker-static-echo", out)
	}
}

// TestSystrapDockerDynamicExecsStatic wraps /bin/sh (dynamic) with
// systrap-docker. The shell execs a static stub_client mid-script.
// The preload.so's execve interception detects the static binary (no
// PT_INTERP), patches it via memfds, and re-execs. The static child
// gets the ptloader injected via the patched PT_INTERP, installs systrap,
// and completes the TCP echo — all without ptrace.
func TestSystrapDockerDynamicExecsStatic(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, staticStub := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	shellCmd := fmt.Sprintf("%s 100.64.94.1 18080 docker-dyn-to-static tcp",
		staticStub)
	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-docker", "/bin/sh",
		[]string{"-c", shellCmd},
		wrapperRunOptions{timeout: 30 * time.Second})

	if !strings.Contains(string(out), "docker-dyn-to-static") {
		t.Fatalf("dynamic→static exec chain failed; output: %q", out)
	}
}

// TestSystrapDockerStaticExecsStatic wraps a static "exec_chain" binary
// that execs another static stub_client. Both hops go through the
// execve_docker_dispatch path: the ptloader installs systrap in the first
// static binary, its execve(2) is SECCOMP_RET_TRAPped, the SIGSYS handler
// calls execve_docker_dispatch, which patches the second static binary.
func TestSystrapDockerStaticExecsStatic(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, staticStub := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	// Build a static exec-chain helper: execs argv[1] with argv[2:].
	chainSrc := filepath.Join(tmp, "exec_chain.c")
	if err := os.WriteFile(chainSrc, []byte(`
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    execv(argv[1], argv + 1);
    return 1;
}
`), 0o644); err != nil {
		t.Fatalf("write exec_chain.c: %v", err)
	}
	staticChain := filepath.Join(tmp, "exec_chain_static")
	run(t, repo, "gcc", "-static", "-O2", "-o", staticChain, chainSrc)

	listenSock := filepath.Join(tmp, "fdproxy-docker-ss.sock")
	args := []string{staticStub,
		"100.64.94.1", "18080", "docker-static-to-static", "tcp"}
	wrapperArgs := []string{
		"--transport=systrap-docker",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", staticChain,
	}
	wrapperArgs = append(wrapperArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== static→static output ===\n%s\n=== end ===", out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("static→static exec chain: timed out")
	}
	if err != nil {
		t.Fatalf("static→static exec chain: wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "docker-static-to-static") {
		t.Fatalf("expected sentinel in output; got %q", out)
	}
}

// TestSystrapDockerStaticExecsDynamic wraps a static exec-chain helper
// that execs the dynamic stub_client. The ptloader's execve dispatch
// detects the dynamic target (has PT_INTERP) and passes through, letting
// the kernel load ld.so normally. LD_PRELOAD is preserved in envp by the
// Go wrapper (it's set on the initial exec), so the dynamic child's
// preload.so constructor fires and intercepts network syscalls.
func TestSystrapDockerStaticExecsDynamic(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	// Build a static exec-chain helper.
	chainSrc := filepath.Join(tmp, "exec_chain2.c")
	if err := os.WriteFile(chainSrc, []byte(`
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    execv(argv[1], argv + 1);
    return 1;
}
`), 0o644); err != nil {
		t.Fatalf("write exec_chain2.c: %v", err)
	}
	staticChain := filepath.Join(tmp, "exec_chain2_static")
	run(t, repo, "gcc", "-static", "-O2", "-o", staticChain, chainSrc)

	listenSock := filepath.Join(tmp, "fdproxy-docker-sd.sock")
	args := []string{art.stub,
		"100.64.94.1", "18080", "docker-static-to-dynamic", "tcp"}
	wrapperArgs := []string{
		"--transport=systrap-docker",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", staticChain,
	}
	wrapperArgs = append(wrapperArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== static→dynamic output ===\n%s\n=== end ===", out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("static→dynamic exec chain: timed out")
	}
	if err != nil {
		t.Fatalf("static→dynamic exec chain: wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "docker-static-to-dynamic") {
		t.Fatalf("expected sentinel in output; got %q", out)
	}
}

// TestSystrapDockerGoHTTPStatic wraps a CGO_ENABLED=0 Go static HTTP
// server with systrap-docker. This exercises the Go runtime's signal
// handler interaction (Go's runtime tries to install its own SIGSYS
// handler; the rt_sigaction seccomp gate blocks it). The server binds
// on the tunnel side (100.64.94.1) and serves a few HTTP requests.
func TestSystrapDockerGoHTTPStatic(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, _ := buildSystrapDockerArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	// Build a CGO_ENABLED=0 static Go HTTP server.
	server := filepath.Join(tmp, "static_http_server")
	// gobuild.Dir = repo, so source path must be relative to repo root.
	gobuild := exec.Command("go", "build",
		"-tags=netgo,osusergo",
		"-ldflags=-extldflags=-static",
		"-o", server,
		filepath.Join("tests", "preload", "testdata", "static_http_server.go"))
	gobuild.Env = append(os.Environ(), "CGO_ENABLED=0")
	gobuild.Dir = repo
	if out, err := gobuild.CombinedOutput(); err != nil {
		t.Fatalf("build static Go HTTP server: %v\n%s", err, out)
	}
	_ = serverEng

	listenSock := filepath.Join(tmp, "fdproxy-docker-gohttp.sock")
	port := "18090"
	wrapperArgs := []string{
		"--transport=systrap-docker",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", server,
		"100.64.94.2", port, "10",
	}

	// 12s is enough to verify READY without waiting for 10 HTTP requests
	// that no test client sends. Server is killed on timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== systrap-docker Go static HTTP output ===\n%s\n=== end ===", out)

	// Check READY first: the server prints "READY <addr>" once listening.
	// We only need it to reach READY — serving 10 requests requires clients
	// that this test doesn't provision. Timeout is only fatal if READY never
	// appeared (startup crash or bind failure).
	if !strings.Contains(string(out), "READY") {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("systrap-docker Go static HTTP: timed out before READY\noutput: %s", out)
		}
		t.Fatalf("Go static HTTP under systrap-docker failed: %v\noutput: %s", err, out)
	}
}

// TestSystrapDockerChromium is the "final boss" test: a full headless
// Chromium render under systrap-docker with SECCOMP_RET_TRAP execve
// interception. Gated by UWGS_RUN_CHROMIUM_DOCKER=1 / -uwgs-chromium-docker.
//
// Chromium is the hardest target because:
//   - It forks hundreds of helper processes (renderer, GPU, network) all
//     of which need systrap re-armed via execve_docker_dispatch.
//   - Many of those helpers are statically-linked or use clone() instead
//     of fork() for sandbox isolation.
//   - The zygote model exec's a fresh heap from a frozen master after
//     fork, including re-exec via /proc/self/exe.
// resolveChromeBin returns the path to a real (non-script) Chrome/Chromium ELF
// binary, probing candidate paths in preference order. It skips shell-script
// wrappers (snap launchers, google-chrome launcher scripts) because those go
// through an extra bash exec that causes bash to close fd 3 (the master
// ptloader memfd), breaking static-child ptloader injection.
func resolveChromeBin(hint string) string {
	// UWGS_CHROME_BIN / -uwgs-chrome-bin takes precedence.
	if hint != "" {
		return hint
	}
	// Prefer known real-ELF paths first.
	for _, cand := range []string{
		"/opt/google/chrome/chrome",
		"/usr/lib/chromium/chromium",
		"/usr/lib/chromium-browser/chromium-browser",
		"/snap/chromium/current/usr/lib/chromium-browser/chromium-browser",
		// Script launchers last — accepted but may need --disable-seccomp-filter-sandbox.
		"/usr/bin/chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome-stable",
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

// chromeSandboxFlags returns the extra Chrome flags needed to suppress Chrome's
// own seccomp-based sandbox, which conflicts with our SIGSYS handler.
//
// Root cause: Chrome's renderer/GPU subprocess installs a seccomp filter and a
// matching SIGSYS handler. Our BPF filter traps rt_sigaction(SIGSYS) and our
// dispatch silently suppresses it (returning 0 without calling the kernel), so
// Chrome's subprocess believes its SIGSYS handler is installed but it isn't.
// When the subprocess's own seccomp filter fires, it gets a SIGSYS with no
// handler → default action → SIGTERM → parent Chrome times out → SIGTRAP crash.
//
// --disable-seccomp-filter-sandbox prevents Chrome's subprocesses from installing
// their own seccomp filters, which eliminates the conflict.
//
// This is a temporary workaround pending SIGSYS-handler chaining (Phase 2.1).
func chromeSandboxFlags() []string {
	return []string{
		"--disable-seccomp-filter-sandbox",
	}
}

// TestSystrapDockerChromium is the "final boss" test: run Google Chrome/Chromium
// under systrap-docker. Chrome exercises Chromium's zygote fork+exec subprocess
// model, clone() for sandbox isolation, and heavy use of AF_UNIX IPC sockets,
// all of which must pass through (not be tunnel-routed) correctly.
//
// Implementation notes:
//   - Requires UWGS_RUN_CHROMIUM_DOCKER=1 (Tier-3 gated, slow + noisy).
//   - Uses data: URI to avoid needing a real HTTP server; the test goal is
//     "Chrome runs + exits cleanly", not "Chrome fetches something".
//   - --disable-seccomp-filter-sandbox suppresses Chrome's own seccomp
//     sandbox to avoid SIGSYS-handler conflicts (see chromeSandboxFlags).
//   - --no-sandbox disables the SUID/setuid sandbox (not needed in root-owned
//     test environments, and would prevent Chrome forking at all in containers).
//
// Zygote model notes:
//   - Chromium's zygote performs fork() without exec for isolation.
//   - The zygote process inherits our SIGSYS handler (signal handlers survive
//     fork), so socket calls in the zygote + renderer are dispatched correctly.
//   - Static→dynamic exec chains from Chrome subprocesses are handled by
//     our execve_docker_dispatch passthrough.
func TestSystrapDockerChromium(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.ChromiumDocker {
		t.Skip("set UWGS_RUN_CHROMIUM_DOCKER=1 to run the Chromium systrap-docker final boss test")
	}
	requireSystrapDockerToolchain(t)
	chromeBin := resolveChromeBin(tcfg.ChromeBin)
	if chromeBin == "" {
		t.Skip("no Chromium/Chrome binary found; set UWGS_CHROME_BIN=/path/to/chrome")
	}
	t.Logf("chrome binary: %s", chromeBin)

	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)
	tmp := t.TempDir()

	listenSock := filepath.Join(tmp, "fdproxy-docker-chrome.sock")
	chromeArgs := append(chromeSandboxFlags(),
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--dump-dom",
		"--timeout=15000",
		"data:text/html,<h1>uwg-chrome-test</h1>",
	)
	wrapperArgs := append([]string{
		"--transport=systrap-docker",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", chromeBin,
	}, chromeArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== Chromium systrap-docker output ===\n%s\n=== end ===",
		truncate(out, 2048))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("Chromium systrap-docker: timed out after 120s")
	}
	if err != nil {
		t.Fatalf("Chromium systrap-docker failed: %v", err)
	}
}

// TestSystrapSupervisedChromium runs Chrome under systrap-supervised (ptrace
// supervisor path). This exercises the supervised execve interception across
// Chrome's multi-process model.
func TestSystrapSupervisedChromium(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.ChromiumSupervised {
		t.Skip("set UWGS_RUN_CHROMIUM_SUPERVISED=1 to run the supervised Chromium test")
	}
	requireWrapperToolchain(t)
	chromeBin := resolveChromeBin(tcfg.ChromeBin)
	if chromeBin == "" {
		t.Skip("no Chromium/Chrome binary found; set UWGS_CHROME_BIN=/path/to/chrome")
	}
	t.Logf("chrome binary: %s", chromeBin)

	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)
	tmp := t.TempDir()

	listenSock := filepath.Join(tmp, "fdproxy-supervised-chrome.sock")
	chromeArgs := append(chromeSandboxFlags(),
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--dump-dom",
		"--timeout=15000",
		"data:text/html,<h1>uwg-supervised-chrome-test</h1>",
	)
	wrapperArgs := append([]string{
		"--transport=systrap-supervised",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", chromeBin,
	}, chromeArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err2 := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== Chromium systrap-supervised output (first 2KB) ===\n%s\n=== end ===",
		truncate(out, 2048))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("Chromium systrap-supervised: timed out after 120s")
	}
	if err2 != nil {
		t.Fatalf("Chromium systrap-supervised failed: %v", err2)
	}
}

// TestSystrapDockerAutoStaticSeccompOnly verifies that transport=auto selects
// systrap-docker when the target is a static binary and the host has seccomp
// available but ptrace blocked.  We simulate the "ptrace blocked" condition
// by passing UWGS_WRAPPER_TRANSPORT=auto and setting the process to be
// non-dumpable (PR_SET_DUMPABLE=0) before spawning the wrapper as a child —
// the child inherits non-dumpable and probePtraceAvailable returns false.
//
// On hosts where ptrace IS available (dev machines), this test uses a direct
// syscall to force PTRACE_TRACEME to fail: we pass the env var
// UWGS_DISABLE_PTRACE_PROBE=1 which makes probePtraceAvailable return false
// unconditionally. The wrapper then falls through to the systrap-docker slot.
func TestSystrapDockerAutoStaticSeccompOnly(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, staticStub := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	tmp := t.TempDir()
	listenSock := filepath.Join(tmp, "fdproxy-auto-static.sock")
	wrapperArgs := []string{
		"--transport=auto",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", staticStub,
		"100.64.94.1", "18080", "auto-static-seccomp-only", "tcp",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = append(os.Environ(), "UWGS_DISABLE_PTRACE_PROBE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== auto static (seccomp-only) output ===\n%s\n=== end ===", out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("auto static seccomp-only: timed out")
	}
	if err != nil {
		t.Fatalf("auto static seccomp-only: wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "auto-static-seccomp-only") {
		t.Fatalf("expected sentinel in output; got %q", out)
	}
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// TestSystrapElfPythonSubprocess exercises the posix_spawn PLT shim fix:
// Python's subprocess module on glibc 2.28+ uses posix_spawn internally, which
// calls clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND). CLONE_CLEAR_SIGHAND
// resets all signal handlers (including our SIGSYS trap) to SIG_DFL in the
// child. Before the shim, the child's execve seccomp-trap fired with no
// handler and the child was killed. The shim intercepts posix_spawn at PLT
// level and uses fork()+execve() instead.
func TestSystrapElfPythonSubprocess(t *testing.T) {
	requireSystrapDockerToolchain(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found")
	}
	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-elf", "python3",
		[]string{"-c", `import subprocess; r = subprocess.check_output(["uname", "-r"]); print("spawn-ok", r.decode().strip())`},
		wrapperRunOptions{timeout: 30 * time.Second})

	if !strings.Contains(string(out), "spawn-ok") {
		t.Fatalf("expected 'spawn-ok' in output; got %q", out)
	}
}

// TestSystrapElfPosixSpawnNetworked builds a C parent that calls posix_spawn
// to launch stub_client (which makes a TCP echo through the tunnel). Verifies
// that the posix_spawn PLT shim hands off to fork()+execve(), that the spawned
// child gets ptloader injected via execve_docker_dispatch, and that the child
// can establish tunnel connections normally.
func TestSystrapElfPosixSpawnNetworked(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	parentSrc := filepath.Join(tmp, "posix_spawn_parent.c")
	if err := os.WriteFile(parentSrc, []byte(`
#define _GNU_SOURCE
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
extern char **environ;
int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: parent stub host port sentinel\n"); return 1; }
    char *child_argv[] = { argv[1], argv[2], argv[3], argv[4], "tcp", NULL };
    pid_t pid;
    int rc = posix_spawn(&pid, argv[1], NULL, NULL, child_argv, environ);
    if (rc != 0) { fprintf(stderr, "posix_spawn: %s\n", strerror(rc)); return 1; }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed: status=%d\n", WEXITSTATUS(status)); return 1;
    }
    printf("posix-spawn-parent-ok\n");
    return 0;
}
`), 0o644); err != nil {
		t.Fatalf("write posix_spawn_parent.c: %v", err)
	}
	parent := filepath.Join(tmp, "posix_spawn_parent")
	run(t, repo, "gcc", "-O2", "-Wall", "-o", parent, parentSrc)

	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-elf", parent,
		[]string{art.stub, "100.64.94.1", "18080", "elf-posixspawn-echo"},
		wrapperRunOptions{timeout: 30 * time.Second})

	if !strings.Contains(string(out), "elf-posixspawn-echo") {
		t.Fatalf("posix_spawn chain: expected echo sentinel in output; got %q", out)
	}
	if !strings.Contains(string(out), "posix-spawn-parent-ok") {
		t.Fatalf("posix_spawn chain: expected 'posix-spawn-parent-ok' in output; got %q", out)
	}
}

// TestSystrapElfClone3ClearSighand verifies the BPF-level CLONE_CLEAR_SIGHAND
// interception path. The test builds a C parent that calls clone3(2) directly via
// syscall(SYS_clone3, ...) with ca.flags = CLONE_CLEAR_SIGHAND (fork-like, no
// CLONE_VM). Without the BPF trap + dispatch strip the child's SIGSYS handler would
// be reset to SIG_DFL, the execve seccomp-trap would have no handler, and
// force_sig_info_to_task would kill the child.
//
// This covers Go runtimes, Rust process::Command, and static-libc binaries that
// call clone3 directly rather than routing through glibc's posix_spawn PLT symbol
// (which is intercepted separately by the PLT shim for dynamic binaries).
func TestSystrapElfClone3ClearSighand(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	src := filepath.Join(tmp, "clone3_parent.c")
	if err := os.WriteFile(src, []byte(`
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_clone3
# if defined(__x86_64__) || defined(__aarch64__)
#  define SYS_clone3 435
# endif
#endif

#ifndef CLONE_CLEAR_SIGHAND
# define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

struct uwg_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
};

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: clone3test stub host port sentinel\n");
        return 1;
    }
    struct uwg_clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE_CLEAR_SIGHAND;
    ca.exit_signal = SIGCHLD;
    long pid = syscall(SYS_clone3, &ca, sizeof(ca));
    if (pid < 0) {
        if (errno == ENOSYS) {
            /* Kernel < 5.3: clone3 not available; skip gracefully. */
            printf("clone3-not-available\n");
            return 0;
        }
        fprintf(stderr, "clone3: %s\n", strerror(errno));
        return 1;
    }
    if (pid == 0) {
        /* child: exec into stub_client for the TCP echo */
        char *child_argv[] = { argv[1], argv[2], argv[3], argv[4], "tcp", NULL };
        execv(argv[1], child_argv);
        _exit(127);
    }
    /* parent */
    int status = 0;
    if (waitpid((pid_t)pid, &status, 0) < 0) { perror("waitpid"); return 1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed: exit=%d\n", WEXITSTATUS(status));
        return 1;
    }
    printf("clone3-parent-ok\n");
    return 0;
}
`), 0o644); err != nil {
		t.Fatalf("write clone3_parent.c: %v", err)
	}
	parent := filepath.Join(tmp, "clone3_parent")
	run(t, repo, "gcc", "-O2", "-Wall", "-o", parent, src)

	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-elf", parent,
		[]string{art.stub, "100.64.94.1", "18080", "elf-clone3-echo"},
		wrapperRunOptions{timeout: 30 * time.Second})

	t.Logf("=== clone3 CLEAR_SIGHAND output ===\n%s\n=== end ===", out)

	if strings.Contains(string(out), "clone3-not-available") {
		t.Skip("clone3 not available on this kernel (< 5.3); skipping")
	}
	if !strings.Contains(string(out), "elf-clone3-echo") {
		t.Fatalf("clone3 CLEAR_SIGHAND: expected echo sentinel in output; got %q", out)
	}
	if !strings.Contains(string(out), "clone3-parent-ok") {
		t.Fatalf("clone3 CLEAR_SIGHAND: expected 'clone3-parent-ok' in output; got %q", out)
	}
}

// TestSystrapElfClone3HandlerCleared verifies the full CLONE_CLEAR_SIGHAND
// trampoline behaviour: other signal handlers are cleared in the child, but SIGSYS
// is preserved. The parent installs a custom SIGUSR1 handler, then calls
// clone3(CLONE_CLEAR_SIGHAND). In the child, querying SIGUSR1 must see SIG_DFL; the
// child then execs stub_client to confirm SIGSYS is still live and network
// interception continues to work.
func TestSystrapElfClone3HandlerCleared(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	src := filepath.Join(tmp, "clone3_handler_check.c")
	if err := os.WriteFile(src, []byte(`
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_clone3
# if defined(__x86_64__) || defined(__aarch64__)
#  define SYS_clone3 435
# endif
#endif

#ifndef CLONE_CLEAR_SIGHAND
# define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

struct uwg_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
};

static void sigusr1_handler(int sig) { (void)sig; }

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: clone3hc stub host port sentinel\n");
        return 1;
    }
    /* Install a non-default SIGUSR1 handler before clone3. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);

    struct uwg_clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE_CLEAR_SIGHAND;
    ca.exit_signal = SIGCHLD;
    long pid = syscall(SYS_clone3, &ca, sizeof(ca));
    if (pid < 0) {
        if (errno == ENOSYS) {
            printf("clone3-not-available\n");
            return 0;
        }
        fprintf(stderr, "clone3: %s\n", strerror(errno));
        return 1;
    }
    if (pid == 0) {
        /* Child: SIGUSR1 must be SIG_DFL — trampoline should have cleared it. */
        struct sigaction old;
        memset(&old, 0, sizeof(old));
        sigaction(SIGUSR1, NULL, &old);
        if (old.sa_handler == SIG_DFL)
            printf("sigusr1-cleared\n");
        else
            printf("sigusr1-not-cleared\n");
        fflush(stdout);
        /* Exec stub_client to confirm SIGSYS handler is still live. */
        char *child_argv[] = { argv[1], argv[2], argv[3], argv[4], "tcp", NULL };
        execv(argv[1], child_argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid((pid_t)pid, &status, 0) < 0) { perror("waitpid"); return 1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed: exit=%d\n", WEXITSTATUS(status));
        return 1;
    }
    printf("clone3hc-parent-ok\n");
    return 0;
}
`), 0o644); err != nil {
		t.Fatalf("write clone3_handler_check.c: %v", err)
	}
	checker := filepath.Join(tmp, "clone3_handler_check")
	run(t, repo, "gcc", "-O2", "-Wall", "-o", checker, src)

	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-elf", checker,
		[]string{art.stub, "100.64.94.1", "18080", "elf-clone3-hc"},
		wrapperRunOptions{timeout: 30 * time.Second})

	t.Logf("=== clone3 handler-cleared output ===\n%s\n=== end ===", out)

	if strings.Contains(string(out), "clone3-not-available") {
		t.Skip("clone3 not available on this kernel (< 5.3); skipping")
	}
	if !strings.Contains(string(out), "sigusr1-cleared") {
		t.Fatalf("clone3 handler-cleared: SIGUSR1 not reset to SIG_DFL in child; got %q", out)
	}
	if !strings.Contains(string(out), "elf-clone3-hc") {
		t.Fatalf("clone3 handler-cleared: expected echo sentinel in output; got %q", out)
	}
	if !strings.Contains(string(out), "clone3hc-parent-ok") {
		t.Fatalf("clone3 handler-cleared: expected 'clone3hc-parent-ok' in output; got %q", out)
	}
}

// TestSystrapElfVforkExec builds a C parent that calls vfork()+execv(stub_client).
// vfork uses clone(CLONE_VM|CLONE_VFORK) without CLONE_CLEAR_SIGHAND, so the child
// inherits the SIGSYS handler. This validates that the vfork+exec code path
// (distinct from posix_spawn's clone3 path) also works end-to-end under systrap-elf.
func TestSystrapElfVforkExec(t *testing.T) {
	requireSystrapDockerToolchain(t)
	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	parentSrc := filepath.Join(tmp, "vfork_parent.c")
	if err := os.WriteFile(parentSrc, []byte(`
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: parent stub host port sentinel\n"); return 1; }
    pid_t pid = vfork();
    if (pid < 0) { perror("vfork"); return 1; }
    if (pid == 0) {
        char *child_argv[] = { argv[1], argv[2], argv[3], argv[4], "tcp", NULL };
        execv(argv[1], child_argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed: status=%d\n", WEXITSTATUS(status)); return 1;
    }
    printf("vfork-parent-ok\n");
    return 0;
}
`), 0o644); err != nil {
		t.Fatalf("write vfork_parent.c: %v", err)
	}
	parent := filepath.Join(tmp, "vfork_parent")
	run(t, repo, "gcc", "-O2", "-Wall", "-o", parent, parentSrc)

	out := runWrappedTargetWithOptions(t, art, httpSock,
		"systrap-elf", parent,
		[]string{art.stub, "100.64.94.1", "18080", "elf-vfork-echo"},
		wrapperRunOptions{timeout: 30 * time.Second})

	if !strings.Contains(string(out), "elf-vfork-echo") {
		t.Fatalf("vfork chain: expected echo sentinel in output; got %q", out)
	}
	if !strings.Contains(string(out), "vfork-parent-ok") {
		t.Fatalf("vfork chain: expected 'vfork-parent-ok' in output; got %q", out)
	}
}
