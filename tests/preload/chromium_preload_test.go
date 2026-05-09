//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestChromiumPreloadWrapperSmoke validates the --transport=preload wrapper
// end-to-end using headless Chrome on linux-amd64.
//
// Design: two uwgsocks instances share a WireGuard tunnel. A Go HTTP server
// listens on the SERVER's tunnel address (100.64.94.1:18095). Chrome runs
// under the CLIENT's preload wrapper and navigates to that URL directly.
//
//   - No --proxy-server. Chrome connects to 100.64.94.1:18095 (non-loopback).
//   - The preload intercepts the connect and routes it: fdproxy →
//     client-uwgsocks → WireGuard tunnel → server-uwgsocks → Go HTTP server.
//   - This exercises the real preload socket-intercept path.
//   - No real internet needed. Reliable on GH-hosted runners.
//
// Gated on UWGS_CHROME_BIN only. No continue-on-error. Snap-confined
// binaries are skipped (LD_PRELOAD from /tmp is blocked by snap confinement).
func TestChromiumPreloadWrapperSmoke(t *testing.T) {
	requirePhase1Toolchain(t)

	tcfg := testconfig.Get()
	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		t.Skip("set UWGS_CHROME_BIN to run the preload wrapper smoke")
	}
	if isSnapBin(chromeBin) {
		t.Skipf("snap-confined chromium (%s) cannot load LD_PRELOAD from /tmp; install chrome-headless-shell", chromeBin)
	}

	art := buildPhase1Artifacts(t)

	// Server + client WireGuard pair. The client's httpSock is what
	// wrappedCommand passes as --api to uwgwrapper (fdproxy uses it).
	serverEng, httpSock := setupWrapperNetwork(t)

	// HTTP server on the server's tunnel side.
	const tunnelPort = 18095
	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort(fmt.Sprintf("100.64.94.1:%d", tunnelPort)))
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head></head><body>Preload Smoke OK</body></html>")
		}),
	}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	targetURL := fmt.Sprintf("http://100.64.94.1:%d/", tunnelPort)

	// Minimal headless Chrome flags. --no-zygote keeps Chrome
	// single-process on Linux so LD_PRELOAD stays in effect across
	// fork boundaries without requiring systrap-supervised re-arm.
	// UWGS_DNS_MODE=none disables port-53 diversion — Chrome's
	// background DNS queries are irrelevant here (no public names
	// are resolved) and diverting them to the fdproxy DNS endpoint
	// when no dns_server is configured silently fails the navigation.
	chromeArgs := []string{
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--no-zygote",
		"--dump-dom",
		targetURL,
	}

	base := wrappedCommand(t, art, httpSock, "preload", chromeBin, chromeArgs, wrapperRunOptions{
		env: map[string]string{"UWGS_DNS_MODE": "none"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, base.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	out, runErr := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== chromium under preload (%d bytes, err=%v) ===\n%s\n=== end ===",
		len(out), runErr, abbrev(out, 1000))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("chromium under preload timed out")
	}
	if runErr != nil {
		t.Fatalf("chromium under preload exited non-zero: %v", runErr)
	}
	if !strings.Contains(string(out), "Preload Smoke OK") {
		t.Fatalf("expected 'Preload Smoke OK' in DOM output; got: %s", abbrev(out, 500))
	}
}
