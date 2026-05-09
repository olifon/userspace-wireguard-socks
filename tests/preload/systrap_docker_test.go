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
func TestSystrapDockerChromium(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.ChromiumDocker {
		t.Skip("set UWGS_RUN_CHROMIUM_DOCKER=1 to run the Chromium systrap-docker final boss test")
	}
	requireSystrapDockerToolchain(t)
	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		for _, cand := range []string{
			"/usr/bin/chromium-browser",
			"/usr/bin/chromium",
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
		} {
			if _, err := os.Stat(cand); err == nil {
				chromeBin = cand
				break
			}
		}
	}
	if chromeBin == "" {
		t.Skip("no Chromium binary found (set UWGS_CHROME_BIN)")
	}

	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)
	tmp := t.TempDir()

	listenSock := filepath.Join(tmp, "fdproxy-docker-chrome.sock")
	wrapperArgs := []string{
		"--transport=systrap-docker",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", chromeBin,
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--dump-dom",
		"--timeout=10000",
		"https://100.64.94.1/",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== Chromium systrap-docker output (first 2KB) ===\n%s\n=== end ===",
		truncate(out, 2048))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("Chromium systrap-docker: timed out")
	}
	if err != nil {
		t.Fatalf("Chromium systrap-docker failed: %v", err)
	}
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
