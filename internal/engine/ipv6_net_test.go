// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine_test

// IPv6 network reachability tests (Layer 2).
//
// These tests require the host to have a working IPv6 loopback (::1) or routable
// IPv6 address and are gated by UWGS_RUN_IPV6_NET=1 / -uwgs-ipv6-net.
//
// Tests that use IPv6 purely in-process (WireGuard peers with fd64::/ULA
// tunnel addresses, no real host-network IPv6 required) live in other files
// and run unconditionally.

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// setupIPv6FallbackEngine starts an engine with a dual-stack tunnel address so
// that socketIPv6Enabled() returns true, and with fallback_direct=true so the
// engine can dial host IPv6 addresses directly.
func setupIPv6FallbackEngine(t *testing.T, withHTTP bool) *engine.Engine {
	t.Helper()
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	// fd7a:115c:a1e0::1/128 gives socketIPv6Enabled() a true return without
	// needing a real IPv6 WireGuard peer.
	cfg.WireGuard.Addresses = []string{"100.64.98.1/32", "fd7a:115c:a1e0::1/128"}
	fallback := true
	cfg.Proxy.FallbackDirect = &fallback
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	if withHTTP {
		cfg.Proxy.HTTP = "127.0.0.1:0"
	}
	return mustStart(t, cfg)
}

// TestHTTPProxyConnectIPv6DirectFallback verifies the HTTP proxy CONNECT path
// to an IPv6 host address ([::1]) using the engine's direct-fallback route.
//
// This exercises the HTTP proxy's CONNECT handling for IPv6 targets
// ("CONNECT [::1]:port HTTP/1.1"), which is a different code path from the
// SOCKS5 ATYP=4 path and from in-tunnel IPv6 AllowedIPs routing.
//
// Gated by UWGS_RUN_IPV6_NET: requires a working ::1 on the host.
func TestHTTPProxyConnectIPv6DirectFallback(t *testing.T) {
	if testing.Short() || !testconfig.Get().IPv6Net {
		t.Skip("set UWGS_RUN_IPV6_NET=1 or -uwgs-ipv6-net to run")
	}
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from ipv6 host"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	eng := setupIPv6FallbackEngine(t, true)
	target := net.JoinHostPort("::1", port)
	body := httpProxyConnectGet(t, eng.Addr("http"), target)
	if body != "hello from ipv6 host" {
		t.Fatalf("HTTP proxy IPv6 CONNECT body = %q, want %q", body, "hello from ipv6 host")
	}
}

// TestSOCKS5ConnectIPv6DirectFallback verifies the SOCKS5 CONNECT path with
// ATYP=4 (IPv6) to a host IPv6 address ([::1]) using the direct-fallback route.
//
// This is the engine-level complement to TestUWGWrapperIPv6DirectFallbackAcrossTransports
// in the preload suite: it tests the routing engine's ATYP=4 handling and
// socketIPv6Enabled gate without the wrapper layer.
//
// Gated by UWGS_RUN_IPV6_NET: requires a working ::1 on the host.
func TestSOCKS5ConnectIPv6DirectFallback(t *testing.T) {
	if testing.Short() || !testconfig.Get().IPv6Net {
		t.Skip("set UWGS_RUN_IPV6_NET=1 or -uwgs-ipv6-net to run")
	}
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	go serveEchoListener(ln)
	port := ln.Addr().(*net.TCPAddr).Port

	eng := setupIPv6FallbackEngine(t, false)
	dst := netip.MustParseAddrPort(net.JoinHostPort("::1", strconv.Itoa(port)))
	rep := socksConnectReply(t, eng.Addr("socks5"), dst)
	if rep != 0 {
		t.Fatalf("SOCKS5 IPv6 CONNECT to ::1 failed with SOCKS reply byte %d (want 0=success)", rep)
	}
}
