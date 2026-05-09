// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// probePython3Sklearn returns the path to a python3 interpreter that has
// scikit-learn available, or "" if none found.
func probePython3Sklearn(t *testing.T) string {
	t.Helper()
	for _, py := range []string{"python3", "python"} {
		path, err := exec.LookPath(py)
		if err != nil {
			continue
		}
		out, err2 := exec.Command(path, "-c", "import sklearn; print('ok')").CombinedOutput()
		if err2 == nil && strings.Contains(string(out), "ok") {
			return path
		}
	}
	return ""
}

// TestPythonMLSystrapDocker runs a Python3/scikit-learn ML workload + tunnel
// echo network check under systrap-docker. Verifies:
//
//  1. sklearn RandomForestClassifier trains + infers correctly on the iris
//     dataset (CPU-only, no GPU).
//  2. Python's socket.create_connection is intercepted by the preload and
//     routed through the WireGuard tunnel echo server.
//
// Gated by UWGS_RUN_PYTHON_ML=1 / -uwgs-python-ml.
func TestPythonMLSystrapDocker(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.PythonML {
		t.Skip("set UWGS_RUN_PYTHON_ML=1 to run the Python ML systrap-docker test")
	}
	requireSystrapDockerToolchain(t)

	pyBin := probePython3Sklearn(t)
	if pyBin == "" {
		t.Skip("python3 with scikit-learn not found; install python3-sklearn or scikit-learn")
	}
	t.Logf("python binary: %s", pyBin)

	art, _ := buildSystrapDockerArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)
	tmp := t.TempDir()

	// Copy the test script into tmp so the path has no spaces/surprises.
	scriptSrc := filepath.Join("..", "..", "tests", "preload", "testdata", "ml_proxy_test.py")
	scriptDst := filepath.Join(tmp, "ml_proxy_test.py")
	scriptBytes, err := os.ReadFile(scriptSrc)
	if err != nil {
		t.Fatalf("read ml_proxy_test.py: %v", err)
	}
	if err := os.WriteFile(scriptDst, scriptBytes, 0o644); err != nil {
		t.Fatalf("write ml_proxy_test.py to tmp: %v", err)
	}

	listenSock := filepath.Join(tmp, "fdproxy-python-ml-docker.sock")
	wrapperArgs := []string{
		"--transport=systrap-docker",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", pyBin, scriptDst,
		"100.64.94.1", "18080", "ml-docker-sentinel",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, runErr := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== Python ML systrap-docker output ===\n%s\n=== end ===",
		truncate(out, 4096))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("Python ML systrap-docker: timed out after 120s")
	}
	if runErr != nil {
		t.Fatalf("Python ML systrap-docker failed: %v", runErr)
	}
	if !strings.Contains(string(out), "ML_DONE") {
		t.Fatalf("Python ML systrap-docker: missing ML_DONE sentinel; output: %s", out)
	}
	if !strings.Contains(string(out), "network echo OK") {
		t.Fatalf("Python ML systrap-docker: missing network echo confirmation; output: %s", out)
	}
}

// TestPythonMLSystrapSupervised runs the same Python ML + network test under
// systrap-supervised (ptrace-supervisor path). Exercises execve tracking across
// the Python interpreter's own dynamic startup + fork model.
//
// Gated by UWGS_RUN_PYTHON_ML=1 / -uwgs-python-ml.
func TestPythonMLSystrapSupervised(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.PythonML {
		t.Skip("set UWGS_RUN_PYTHON_ML=1 to run the Python ML systrap-supervised test")
	}
	requireWrapperToolchain(t)

	pyBin := probePython3Sklearn(t)
	if pyBin == "" {
		t.Skip("python3 with scikit-learn not found; install python3-sklearn or scikit-learn")
	}
	t.Logf("python binary: %s", pyBin)

	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)
	tmp := t.TempDir()

	scriptSrc := filepath.Join("..", "..", "tests", "preload", "testdata", "ml_proxy_test.py")
	scriptDst := filepath.Join(tmp, "ml_proxy_test.py")
	scriptBytes, err := os.ReadFile(scriptSrc)
	if err != nil {
		t.Fatalf("read ml_proxy_test.py: %v", err)
	}
	if err := os.WriteFile(scriptDst, scriptBytes, 0o644); err != nil {
		t.Fatalf("write ml_proxy_test.py to tmp: %v", err)
	}

	listenSock := filepath.Join(tmp, "fdproxy-python-ml-supervised.sock")
	wrapperArgs := []string{
		"--transport=systrap-supervised",
		"--listen", listenSock,
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--preload", art.preload,
		"--", pyBin, scriptDst,
		"100.64.94.1", "18080", "ml-supervised-sentinel",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, runErr := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== Python ML systrap-supervised output ===\n%s\n=== end ===",
		truncate(out, 4096))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("Python ML systrap-supervised: timed out after 120s")
	}
	if runErr != nil {
		t.Fatalf("Python ML systrap-supervised failed: %v", runErr)
	}
	if !strings.Contains(string(out), "ML_DONE") {
		t.Fatalf("Python ML systrap-supervised: missing ML_DONE sentinel; output: %s", out)
	}
	if !strings.Contains(string(out), "network echo OK") {
		t.Fatalf("Python ML systrap-supervised: missing network echo confirmation; output: %s", out)
	}
}
