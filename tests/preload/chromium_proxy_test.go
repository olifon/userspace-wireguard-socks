// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// TestChromiumProxySmoke — no build tag; runs on linux, macOS, and Windows.

package preload_test

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestChromiumProxySmoke validates the uwgsocks HTTP proxy path end-to-end
// using headless Chromium on all supported platforms. No wrapper involved:
// Chrome connects to the proxy over loopback (127.0.0.1) and the proxy
// dials the real internet via fallback_direct.
//
// The test is gated on UWGS_CHROME_BIN only — CI sets this whenever a
// suitable headless shell binary is available (linux64 chrome-headless-shell,
// mac-arm64 / mac-x64 chrome-headless-shell, win64 chrome-headless-shell,
// or google-chrome-stable on linux-arm64). No additional env var gate.
//
// This complements TestChromiumPreloadWrapperSmoke (linux/amd64 only):
// that test proves LD_PRELOAD loading works; this one proves the HTTP
// proxy path is correct on every CI platform.
func TestChromiumProxySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("chromium proxy smoke skipped in -short mode")
	}

	tcfg := testconfig.Get()
	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		t.Skip("set UWGS_CHROME_BIN to run the chromium proxy smoke")
	}

	proxyPort := freeTCPPort(t)

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	cfg.Proxy.HTTP = fmt.Sprintf("127.0.0.1:%d", proxyPort)
	_ = mustStart(t, cfg)
	waitTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// --no-zygote avoids the zygote fork+exec model (not needed for a
	// single-navigate-and-dump test). --disable-features=DBus prevents
	// long retry loops in stripped CI containers (and snap-confined
	// chromium on Ubuntu arm64). No --virtual-time-budget so Chrome
	// waits for the real proxy I/O to complete before dumping the DOM.
	args := []string{
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

	cmd := exec.CommandContext(ctx, chromeBin, args...)
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("chromium timed out — proxy or network unavailable\npartial output: %s", abbrev(out, 500))
	}
	if err != nil {
		t.Fatalf("chromium exited non-zero: %v\noutput: %s", err, abbrev(out, 1000))
	}
	if !strings.Contains(string(out), "Example Domain") {
		t.Fatalf("expected 'Example Domain' in DOM; got: %s", abbrev(out, 500))
	}
	t.Logf("OK: %d bytes of DOM", len(out))
}
