// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMarkPacketECNRejectsShortIPv4OptionsHeader(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x46 // IPv4 with IHL=6 (24-byte header expected)
	packet[1] = 0x03 // ECN-capable
	if markPacketECN(packet) {
		t.Fatal("markPacketECN unexpectedly accepted a truncated IPv4 options header")
	}
}

func TestServeSOCKSConnTimesOutAfterHandshakeBeforeRequest(t *testing.T) {
	oldDeadline := socksRequestDeadline
	socksRequestDeadline = 40 * time.Millisecond
	defer func() { socksRequestDeadline = oldDeadline }()

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		(&Engine{}).serveSOCKSConn(server)
		close(done)
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}
	if reply != [2]byte{0x05, 0x00} {
		t.Fatalf("handshake reply = %v, want [5 0]", reply)
	}

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 32)
	if _, err := client.Read(buf); err == nil {
		// The server writes a general-failure reply before closing. Getting data
		// here is fine; the important part is that the goroutine terminates.
	}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SOCKS connection did not time out after a completed handshake stall")
	}
}

func TestSocketSessionUDPPeerLimit(t *testing.T) {
	oldLimit := maxSocketUDPPeers
	maxSocketUDPPeers = 2
	defer func() { maxSocketUDPPeers = oldLimit }()

	ss := &socketSession{}
	if !ss.touchUDPPeer(netip.MustParseAddrPort("192.0.2.1:10001"), time.Hour) {
		t.Fatal("first UDP peer was unexpectedly rejected")
	}
	if !ss.touchUDPPeer(netip.MustParseAddrPort("192.0.2.2:10002"), time.Hour) {
		t.Fatal("second UDP peer was unexpectedly rejected")
	}
	if ss.touchUDPPeer(netip.MustParseAddrPort("192.0.2.3:10003"), time.Hour) {
		t.Fatal("third UDP peer unexpectedly bypassed the per-session limit")
	}

	ss.udpMu.Lock()
	defer ss.udpMu.Unlock()
	if len(ss.udpPeers) != 2 {
		t.Fatalf("udp peer table size = %d, want 2", len(ss.udpPeers))
	}
	for _, state := range ss.udpPeers {
		if state.timer != nil {
			state.timer.Stop()
		}
	}
}

func TestSocketProtocolDNSFrameHonorsInflightLimit(t *testing.T) {
	oldExchange := systemDNSExchange
	systemDNSExchange = func(req *dns.Msg, tcp bool) (*dns.Msg, error) {
		t.Fatal("socket API DNS path should refuse when dnsSem is exhausted")
		return nil, nil
	}
	defer func() { systemDNSExchange = oldExchange }()

	eng := &Engine{dnsSem: make(chan struct{}, 1)}
	eng.dnsSem <- struct{}{}

	server, client := net.Pipe()
	defer client.Close()
	go eng.serveSocketProtocol(server, netip.AddrPort{})

	req := new(dns.Msg)
	req.SetQuestion("limit.test.", dns.TypeA)
	payload, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(client, socketproto.Frame{ID: socketproto.ClientIDBase + 7, Action: socketproto.ActionDNS, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := socketproto.ReadFrame(client, socketproto.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Action != socketproto.ActionDNS {
		t.Fatalf("DNS frame action = %d, want %d", frame.Action, socketproto.ActionDNS)
	}
	var resp dns.Msg
	if err := resp.Unpack(frame.Payload); err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("DNS overflow rcode = %d, want REFUSED", resp.Rcode)
	}
}

func TestHTTPProxyClosesIdleIncompleteRequest(t *testing.T) {
	oldReadHeader := proxyHTTPReadHeaderTimeout
	oldRead := proxyHTTPReadTimeout
	oldWrite := proxyHTTPWriteTimeout
	oldIdle := proxyHTTPIdleTimeout
	proxyHTTPReadHeaderTimeout = 40 * time.Millisecond
	proxyHTTPReadTimeout = 40 * time.Millisecond
	proxyHTTPWriteTimeout = 200 * time.Millisecond
	proxyHTTPIdleTimeout = 40 * time.Millisecond
	defer func() {
		proxyHTTPReadHeaderTimeout = oldReadHeader
		proxyHTTPReadTimeout = oldRead
		proxyHTTPWriteTimeout = oldWrite
		proxyHTTPIdleTimeout = oldIdle
	}()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Proxy.HTTP = "127.0.0.1:0"
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.93.1/32"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", eng.Addr("http"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		return
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle incomplete HTTP request unexpectedly stayed open")
	}
}

func TestTunnelDNSTCPClosesIdleClient(t *testing.T) {
	oldDeadline := tunnelDNSTCPDeadline
	tunnelDNSTCPDeadline = 40 * time.Millisecond
	defer func() { tunnelDNSTCPDeadline = oldDeadline }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go (&Engine{}).serveTunnelDNSTCP(ln)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("idle DNS TCP connection unexpectedly stayed open")
	}
}
