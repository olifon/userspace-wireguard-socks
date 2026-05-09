//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestChromiumPreloadWrapperSmoke runs headless Chromium under
// uwgwrapper --transport=preload against a uwgsocks HTTP proxy with
// fallback_direct enabled, navigating to a real-internet URL.
//
// Design:
//   - Chrome is launched under the preload wrapper (LD_PRELOAD loaded).
//   - Chrome's proxy connection goes to 127.0.0.1:proxyPort; the
//     preload shim bypasses loopback connects, so the proxy TCP
//     handshake goes directly via kernel — zero wrapper latency.
//   - uwgsocks handles the HTTP CONNECT and dials the origin via
//     fallback_direct.
//   - No --virtual-time-budget: Chrome waits for real I/O to complete.
//   - --no-zygote: Chrome stays single-process so LD_PRELOAD remains
//     in effect without requiring supervised exec re-arm.
//
// Gated on UWGS_CHROME_BIN only (set by CI when chrome-headless-shell
// is installed). No extra env var gate. Snap-confined binaries are
// skipped (LD_PRELOAD from /tmp is blocked by snap confinement).
func TestChromiumPreloadWrapperSmoke(t *testing.T) {
	requirePhase1Toolchain(t)

	tcfg := testconfig.Get()
	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		t.Skip("set UWGS_CHROME_BIN to a Chrome/headless_shell binary to run the preload wrapper smoke")
	}
	if isSnapBin(chromeBin) {
		t.Skipf("snap-confined chromium (%s) cannot load LD_PRELOAD from /tmp; install chrome-headless-shell", chromeBin)
	}

	art := buildPhase1Artifacts(t)
	proxyPort := freeTCPPort(t)
	httpSock := filepath.Join(t.TempDir(), "http.sock")

	// Single uwgsocks: HTTP proxy on TCP (for Chrome's CONNECT requests)
	// and HTTP listener on Unix socket (for the wrapper's fdproxy).
	// FallbackDirect is true in config.Default() — no WG peers needed.
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	cfg.Proxy.HTTP = fmt.Sprintf("127.0.0.1:%d", proxyPort)
	cfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	cfg.SocketAPI.Bind = true
	_ = mustStart(t, cfg)
	waitTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	waitPath(t, httpSock)

	chromeArgs := []string{
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-features=DBus,VizDisplayCompositor",
		"--disable-software-rasterizer",
		"--no-zygote",
		fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", proxyPort),
		"--dump-dom",
		"https://example.com/",
	}

	// UWGS_DNS_MODE=none: Chrome's internal async DNS resolver makes raw
	// UDP connects to port 53 which the preload (full mode by default)
	// would divert to the fdproxy DNS endpoint. With --proxy-server, all
	// web DNS is handled by the proxy, so there is no reason to intercept
	// Chrome's background DNS queries — and intercepting them causes the
	// navigation to fail silently (empty DOM, no error) when the test
	// uwgsocks instance has no dns_server configured.
	base := wrappedCommand(t, art, httpSock, "preload", chromeBin, chromeArgs, wrapperRunOptions{
		env: map[string]string{"UWGS_DNS_MODE": "none"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, base.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== chromium under preload (%d bytes, err=%v) ===\n%s\n=== end ===",
		len(out), err, abbrev(out, 1000))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("chromium under preload timed out — proxy or network unavailable")
	}
	if err != nil {
		t.Fatalf("chromium under preload exited non-zero: %v", err)
	}
	if !strings.Contains(string(out), "Example Domain") {
		t.Fatalf("expected 'Example Domain' in DOM output; got: %s", abbrev(out, 500))
	}
}
