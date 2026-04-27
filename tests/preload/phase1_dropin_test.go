// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"log"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
)

// TestPhase1DropInLegacyTCP validates that preload/uwgpreload-phase1.so
// can replace the legacy preload/uwgpreload.c monolith in the LD_PRELOAD-
// only flow, with NO uwgwrapper / UWGS_TRACE_SECRET / seccomp filter
// involvement. The shim_libc layer interposes libc symbols directly,
// so the kernel-level filter from uwgwrapper isn't needed for
// correctness — only as a belt-and-braces against raw asm syscalls.
//
// This is the smallest test that asserts shim_libc actually works
// end-to-end. It runs the C stub_client with LD_PRELOAD=phase1.so
// + UWGS_FDPROXY=fdsock, exactly the way the legacy preload tests
// invoke it. If the shim doesn't override libc's connect/read/write
// (e.g. wrong symbol name, wrong signature, wrong return convention),
// this either hangs (libc's connect goes direct to the kernel and
// fails on a non-routable IP) or the bytes round-trip wrong.
func TestPhase1DropInLegacyTCP(t *testing.T) {
	requirePhase1Toolchain(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	stubBin := filepath.Join(tmp, "stub_client")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", stubBin, "tests/preload/testdata/stub_client.c")

	phase1So := filepath.Join(tmp, "uwgpreload-phase1.so")
	build := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), phase1So)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.94.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.94.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	apiSock := filepath.Join(tmp, "api.sock")
	httpSock := filepath.Join(tmp, "http.sock")
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.94.2/32"}
	clientCfg.API.Listen = "unix:" + apiSock
	clientCfg.API.AllowUnauthenticatedUnix = true
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoa(serverPort)),
		AllowedIPs:          []string{"100.64.94.1/32"},
		PersistentKeepalive: 1,
	}}
	_ = mustStart(t, clientCfg)
	waitPath(t, httpSock)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEchoListener(ln)

	udp, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.94.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go serveUDPEcho(udp)

	fdSock := filepath.Join(tmp, "fdproxy.sock")
	proxy, err := fdproxy.ListenWithSocketPath(fdSock, "unix:"+httpSock, "", "/uwg/socket", log.New(testWriter{t}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Close() })
	waitPath(t, fdSock)

	// The smoking-gun test: phase1.so as drop-in for legacy uwgpreload.so.
	// Same exact runPreloadStub helper the legacy tests use.
	out := runPreloadStub(t, phase1So, fdSock, stubBin, "100.64.94.1", "18080", "phase1-dropin-tcp")
	if strings.TrimSpace(string(out)) != "phase1-dropin-tcp" {
		t.Fatalf("expected phase1-dropin-tcp, got %q", out)
	}

	// Connected UDP via the same drop-in path.
	out = runPreloadStub(t, phase1So, fdSock, stubBin, "100.64.94.1", "18081", "phase1-dropin-udp", "udp")
	if strings.TrimSpace(string(out)) != "phase1-dropin-udp" {
		t.Fatalf("expected phase1-dropin-udp, got %q", out)
	}

	// Unconnected UDP via drop-in.
	out = runPreloadStub(t, phase1So, fdSock, stubBin, "100.64.94.1", "18081", "phase1-dropin-udp-unc", "udp-unconnected")
	if strings.TrimSpace(string(out)) != "phase1-dropin-udp-unc" {
		t.Fatalf("expected phase1-dropin-udp-unc, got %q", out)
	}
}
