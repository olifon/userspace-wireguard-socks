// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// TestChromiumProxySmoke — no build tag; runs on linux, macOS, and Windows.

package preload_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestChromiumProxySmoke validates the uwgsocks HTTP proxy path end-to-end
// using headless Chromium on all supported platforms.
//
// Design: a local Go HTTP server listens on 127.0.0.1:localPort. A uwgsocks
// reverse forward maps the tunnel address 100.64.99.1:8080 → localPort. Chrome
// navigates to http://100.64.99.1:8080/ via the uwgsocks HTTP proxy.
//
// Why a local server instead of example.com: Chrome's old headless --dump-dom
// fires DocumentOnLoadCompleted on the initial empty document before the
// real-internet proxy response arrives on GH-hosted runners. A local server
// responds in < 1ms so the content is present when DOMContentLoaded fires.
//
// Why 100.64.99.1 instead of 127.x.x.x: Chrome's proxy bypass list excludes
// loopback addresses from the configured proxy, so direct loopback targets
// would bypass uwgsocks entirely. RFC 6598 (100.64.x.x) addresses are not on
// the bypass list and are routed through the proxy.
//
// Gated on UWGS_CHROME_BIN only. No continue-on-error on linux-amd64 and
// macOS (chrome-headless-shell from Chrome for Testing is deterministic).
func TestChromiumProxySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("chromium proxy smoke skipped in -short mode")
	}

	tcfg := testconfig.Get()
	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		t.Skip("set UWGS_CHROME_BIN to run the chromium proxy smoke")
	}

	// Local HTTP server — responds instantly, no network latency.
	localPort := freeTCPPort(t)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>Proxy Smoke OK</title></head><body>Proxy Smoke OK</body></html>")
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	proxyPort := freeTCPPort(t)

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	cfg.Proxy.HTTP = fmt.Sprintf("127.0.0.1:%d", proxyPort)
	// Reverse forward routes 100.64.99.1:8080 to the local HTTP server.
	// The proxy's dial path checks reverse forwards before fallback_direct,
	// so the GET request to http://100.64.99.1:8080/ reaches the local server.
	cfg.ReverseForwards = []config.Forward{{
		Proto:  "tcp",
		Listen: "100.64.99.1:8080",
		Target: fmt.Sprintf("127.0.0.1:%d", localPort),
	}}
	_ = mustStart(t, cfg)
	waitTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Minimal flag set: no --no-zygote (breaks macOS headless renderer),
	// no --disable-software-rasterizer (combined with --disable-gpu it
	// leaves Chrome with no render backend → empty DOM on all platforms).
	args := []string{
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", proxyPort),
		"--dump-dom",
		"http://100.64.99.1:8080/",
	}

	cmd := exec.CommandContext(ctx, chromeBin, args...)
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("chromium timed out\npartial output: %s", abbrev(out, 500))
	}
	if err != nil {
		t.Fatalf("chromium exited non-zero: %v\noutput: %s", err, abbrev(out, 1000))
	}
	if !strings.Contains(string(out), "Proxy Smoke OK") {
		t.Fatalf("expected 'Proxy Smoke OK' in DOM; got: %s", abbrev(out, 500))
	}
	t.Logf("OK: %d bytes of DOM", len(out))
}
