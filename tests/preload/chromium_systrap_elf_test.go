//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestChromiumSystrapElfRealInternet validates headless Chromium through the
// systrap-elf wrapper transport against real internet URLs.
//
// systrap-elf uses in-tracee PT_INTERP injection: each time Chromium's zygote
// execs a renderer, GPU, or utility process, the kernel atomically loads the
// ptloader via the rewritten PT_INTERP before _start. This gives every child
// process its own SIGSYS handler + seccomp filter without ptrace supervision.
// This test confirms the mechanism survives Chromium's multi-process zygote
// model while routing outbound traffic through a uwgsocks HTTP proxy.
//
// Unlike TestChromiumSystrapSupervisedRealInternet, this uses the non-ptrace
// systrap-elf path, which avoids the ptrace supervisor's SIGSYS-forward
// concurrency sensitivity that causes the known amd64 GH-runner hang.
//
// Gated by UWGS_CHROME_BIN + UWGS_RUN_CHROMIUM_SYSTRAP_ELF=1.
func TestChromiumSystrapElfRealInternet(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.ChromiumSystrapElf {
		t.Skip("set UWGS_RUN_CHROMIUM_SYSTRAP_ELF=1 or -uwgs-chromium-systrap-elf to run")
	}
	requirePhase1Toolchain(t)

	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		for _, candidate := range []string{
			"chromium", "chromium-browser", "google-chrome", "headless_shell",
		} {
			if path, err := exec.LookPath(candidate); err == nil {
				chromeBin = path
				break
			}
		}
	}
	if chromeBin == "" {
		t.Skip("no chromium binary found; set UWGS_CHROME_BIN")
	}
	if isSnapBin(chromeBin) {
		t.Skipf("snap-confined chromium (%s) cannot load LD_PRELOAD from /tmp; install chrome-headless-shell", chromeBin)
	}

	art := buildPhase1Artifacts(t)

	proxyPort := freeTCPPort(t)

	// Single uwgsocks: HTTP proxy (TCP) for chromium + socket API (Unix) for
	// fdproxy. config.Default() already sets fallback_direct:true so real-
	// internet requests go straight to the host network without a WG peer.
	tmp := t.TempDir()
	httpSock := tmp + "/uwgsocks-http.sock"

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.99.10/32"}
	cfg.Proxy.HTTP = fmt.Sprintf("127.0.0.1:%d", proxyPort)
	cfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	cfg.SocketAPI.Bind = true
	cfg.API.AllowUnauthenticatedUnix = true
	_ = mustStart(t, cfg)
	waitTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	waitPath(t, httpSock)

	for _, tc := range []struct {
		name        string
		url         string
		mustContain string
		// stretchGoal: if true, timeout and empty DOM are SKIP (not FAIL).
		// example.com is the hard gate; YouTube is best-effort on CI.
		stretchGoal bool
	}{
		// example.com: IANA-managed, always returns "Example Domain" on a
		// working connection. Empty DOM or timeout here means the systrap-elf
		// wrapper broke the proxy path — that is a real bug, not a CI timing
		// quirk, so both outcomes FAIL.
		{"example.com", "https://example.com/", "Example Domain", false},
		// youtube.com: JS-heavy; may not finish loading before --dump-dom fires
		// even with a working proxy. SKIP on timeout or empty DOM — the example.com
		// subtest is the gate, YouTube proves full-stack depth when the runner allows.
		{"youtube.com", "https://www.youtube.com/", "YouTube", true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			chromeArgs := []string{
				"--headless",
				"--no-sandbox",
				"--disable-gpu",
				"--disable-dev-shm-usage",
				fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", proxyPort),
				"--dump-dom",
				tc.url,
			}

			// wrappedCommand adds --preload, --listen, --api, --socket-path and
			// wires up the fdproxy → uwgsocks channel automatically.
			base := wrappedCommand(t, art, httpSock, "systrap-elf", chromeBin, chromeArgs, wrapperRunOptions{})
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
			cmd.Env = append([]string{}, base.Env...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

			out, err := runCommandCombinedFileBacked(t, cmd)
			t.Logf("=== chromium under systrap-elf: %s ===\n%s\n=== end (%d bytes, err=%v) ===",
				tc.url, abbrev(out, 800), len(out), err)

			if ctx.Err() == context.DeadlineExceeded {
				if tc.stretchGoal {
					t.Skipf("chromium under systrap-elf timed out fetching %s — JS-heavy page, skipping stretch goal", tc.url)
				}
				t.Fatalf("chromium under systrap-elf timed out fetching %s", tc.url)
			}

			const emptyDOM = "<html><head></head><body></body></html>"
			if strings.TrimSpace(string(out)) == emptyDOM {
				if tc.stretchGoal {
					t.Skipf("systrap-elf returned empty DOM for %s — JS-heavy page not ready at dump time", tc.url)
				}
				// example.com returning empty DOM with working internet means the
				// wrapper's proxy interception is not functioning correctly.
				t.Fatalf("systrap-elf returned empty DOM for %s — proxy interception not working (wrapper bug)", tc.url)
			}

			if err != nil {
				t.Fatalf("chromium under systrap-elf exited non-zero for %s: %v", tc.url, err)
			}
			if !strings.Contains(string(out), tc.mustContain) {
				t.Fatalf("expected %q in DOM for %s; not found\nDOM excerpt:\n%s",
					tc.mustContain, tc.url, abbrev(out, 400))
			}
			t.Logf("%s: OK — found %q in %d bytes of DOM", tc.url, tc.mustContain, len(out))
		})
	}
}
