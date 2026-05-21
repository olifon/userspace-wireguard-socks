//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

func TestUWGWrapperICMPAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	for _, transport := range []string{"preload", "systrap", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.1", "0", "icmp-wrapper", "icmp"},
				wrapperRunOptions{timeout: 60 * time.Second, wrapperArgs: shortListenArgs(t, transport)})
			if normalizedOutput(out) != "icmp-wrapper" {
				t.Fatalf("unexpected ICMP output %q", out)
			}
		})
	}
}

func TestUWGWrapperIPv6RejectsImmediatelyAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	for _, transport := range []string{"preload", "systrap", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			start := time.Now()
			out, err := runWrappedTargetExpectFailure(t, art, httpSock, transport, art.stub,
				[]string{"fd7a:115c:a1e0::99", "443", "ipv6-reject", "tcp-no-poll"},
				wrapperRunOptions{timeout: 5 * time.Second, wrapperArgs: shortListenArgs(t, transport)})
			if err == nil {
				t.Fatalf("IPv6 connect unexpectedly succeeded: %s", out)
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("IPv6 rejection took %s, output=%s", elapsed, out)
			}
			if !bytes.Contains(out, []byte("connect")) {
				t.Fatalf("IPv6 rejection output did not mention connect: %s", out)
			}
		})
	}
}

func TestUWGWrapperIPv6LinkLocalTCPAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	httpSock := setupWrapperIPv6LinkLocalNetwork(t)

	for _, transport := range []string{"preload", "systrap", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"fe80::1", "18080", "ipv6-linklocal", "tcp-no-poll"},
				wrapperRunOptions{timeout: 60 * time.Second, wrapperArgs: shortListenArgs(t, transport)})
			if normalizedOutput(out) != "ipv6-linklocal" {
				t.Fatalf("unexpected IPv6 link-local output %q", out)
			}
		})
	}
}

func setupWrapperIPv6LinkLocalNetwork(t *testing.T) string {
	t.Helper()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	allowLinkLocal := false
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"fe80::1/128"}
	serverCfg.Filtering.DropIPv6LinkLocalMulticast = &allowLinkLocal
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"fe80::2/128"},
	}}
	serverEng := mustStart(t, serverCfg)

	apiSock := filepath.Join(t.TempDir(), "api.sock")
	httpSock := filepath.Join(t.TempDir(), "http.sock")
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"fe80::2/128"}
	clientCfg.Filtering.DropIPv6LinkLocalMulticast = &allowLinkLocal
	clientCfg.API.Listen = "unix:" + apiSock
	clientCfg.API.AllowUnauthenticatedUnix = true
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoa(serverPort)),
		AllowedIPs:          []string{"fe80::1/128"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)
	_ = clientEng
	waitPath(t, httpSock)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("[fe80::1]:18080"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveEchoListener(ln)

	return httpSock
}

// TestUWGWrapperIPv6GlobalUnicastTCPAcrossTransports verifies that the wrapper
// correctly proxies a connect() to a global-unicast IPv6 tunnel address (ULA
// fd64::/128) across all transport modes. This exercises the IPv6 path in the
// preload connect handler and the ptrace AF_INET6 connect emulation, which are
// distinct code paths from the link-local test above.
func TestUWGWrapperIPv6GlobalUnicastTCPAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	httpSock := setupWrapperIPv6GlobalUnicastNetwork(t)

	for _, transport := range []string{"preload", "systrap", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"fd64::1", "18080", "ipv6-global-unicast", "tcp-no-poll"},
				wrapperRunOptions{timeout: 60 * time.Second, wrapperArgs: shortListenArgs(t, transport)})
			if normalizedOutput(out) != "ipv6-global-unicast" {
				t.Fatalf("unexpected IPv6 global unicast output %q", out)
			}
		})
	}
}

func setupWrapperIPv6GlobalUnicastNetwork(t *testing.T) string {
	t.Helper()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"fd64::1/128"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"fd64::2/128"},
	}}
	serverEng := mustStart(t, serverCfg)

	apiSock := filepath.Join(t.TempDir(), "api.sock")
	httpSock := filepath.Join(t.TempDir(), "http.sock")
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"fd64::2/128"}
	clientCfg.API.Listen = "unix:" + apiSock
	clientCfg.API.AllowUnauthenticatedUnix = true
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoa(serverPort)),
		AllowedIPs:          []string{"fd64::1/128"},
		PersistentKeepalive: 1,
	}}
	_ = mustStart(t, clientCfg)
	waitPath(t, httpSock)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("[fd64::1]:18080"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveEchoListener(ln)

	return httpSock
}

func shortListenArgs(t *testing.T, transport string) []string {
	t.Helper()
	name := fmt.Sprintf("uwg-%d-%s.sock", time.Now().UnixNano(), strings.NewReplacer("+", "-", "/", "-", " ", "-").Replace(transport))
	path := filepath.Join("/tmp", name)
	t.Cleanup(func() { _ = os.Remove(path) })
	return []string{"--listen", path}
}

func runWrappedTargetExpectFailure(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) ([]byte, error) {
	t.Helper()
	timeout := opts.timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	base := wrappedCommand(t, art, httpSock, transport, target, args, opts)
	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, base.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		killProcessGroup(cmd)
		return out, ctx.Err()
	}
	if runningRestrictedGVisor() && unsupportedWrappedMode(out) {
		t.Skipf("skipping wrapper mode %q on restricted gVisor kernel: %s", transport, strings.TrimSpace(string(out)))
	}
	if ptraceUnavailableOnArch(out) {
		t.Skipf("skipping transport %q: %s", transport, strings.TrimSpace(string(out)))
	}
	if err != nil && strings.TrimSpace(string(out)) == "" {
		return out, err
	}
	return out, err
}
