// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Cross-platform helpers shared by all chromium smoke tests.
// No build tag — compiled on every platform.

package preload_test

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isSnapBin reports whether the given binary is snap-confined. Snap
// chromium cannot load LD_PRELOAD from /tmp and fails in headless CI.
// On non-Linux platforms this always returns false (no snap concept).
// Covers: (a) path contains /snap/, (b) symlink resolves into /snap/,
// (c) the file is a small shell wrapper referencing /snap/.
func isSnapBin(p string) bool {
	if strings.Contains(p, "/snap/") {
		return true
	}
	if real, err := filepath.EvalSymlinks(p); err == nil && strings.Contains(real, "/snap/") {
		return true
	}
	if fi, err := os.Stat(p); err == nil && fi.Size() < 4096 {
		if content, err := os.ReadFile(p); err == nil && bytes.Contains(content, []byte("/snap/")) {
			return true
		}
	}
	return false
}

// freeTCPPort picks an unused TCP port on 127.0.0.1 and returns it.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitTCPPort blocks until the given addr is accepting TCP connections
// or the timeout elapses.
func waitTCPPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %s not listening within %s", addr, timeout)
}

// abbrev returns the first and last half of b as a string, with
// "…" in the middle, capped at max bytes total.
func abbrev(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max/2]) + "\n…\n" + string(b[len(b)-max/2:])
}
