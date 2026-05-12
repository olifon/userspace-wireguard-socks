// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

func TestSocketAPIConnectTCPUDPAndListenTCP(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.92.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.92.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.92.2/32"}
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.92.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	tcpLn, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.92.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go serveEchoListener(tcpLn)

	udpPC, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.92.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpPC.Close()
	go serveUDPEcho(udpPC)

	socketAddr := "http://" + clientEng.Addr("api")
	got := socketAPITCPEcho(t, socketAddr, "secret", netip.MustParseAddrPort("100.64.92.1:18080"), []byte("raw socket tcp"))
	if string(got) != "raw socket tcp" {
		t.Fatalf("TCP socket API echo mismatch: %q", got)
	}
	got = socketAPIUDPEcho(t, socketAddr, "secret", netip.MustParseAddrPort("100.64.92.1:18081"), []byte("raw socket udp"))
	if string(got) != "raw socket udp" {
		t.Fatalf("UDP socket API echo mismatch: %q", got)
	}
	got = socketAPIICMPEcho(t, socketAddr, "secret", netip.MustParseAddr("100.64.92.1"), []byte("raw socket icmp"))
	if string(got) != "raw socket icmp" {
		t.Fatalf("ICMP socket API echo mismatch: %q", got)
	}

	apiConn := socketAPIConn(t, socketAddr, "secret")
	defer apiConn.Close()
	listenerID := socketproto.ClientIDBase + 500
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.92.2")),
		Protocol:  socketproto.ProtoTCP,
		BindIP:    netip.MustParseAddr("100.64.92.2"),
		BindPort:  19090,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: listenerID, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionAccept || frame.ID != listenerID {
		t.Fatalf("listener accept frame = id %d action %d payload %q", frame.ID, frame.Action, frame.Payload)
	}

	serverDone := make(chan []byte, 1)
	go func() {
		conn := retryEngineDial(t, serverEng, "tcp", "100.64.92.2:19090")
		defer conn.Close()
		_, _ = conn.Write([]byte("listener inbound"))
		buf := make([]byte, len("listener reply"))
		_, _ = io.ReadFull(conn, buf)
		serverDone <- buf
	}()
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionConnect || frame.ID >= socketproto.ClientIDBase {
		t.Fatalf("inbound connect frame = id %d action %d", frame.ID, frame.Action)
	}
	inboundID := frame.ID
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: inboundID, Action: socketproto.ActionAccept}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "listener inbound" {
		t.Fatalf("inbound data frame = action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: inboundID, Action: socketproto.ActionData, Payload: []byte("listener reply")}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-serverDone:
		if string(got) != "listener reply" {
			t.Fatalf("server got reply %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for listener reply")
	}

	udpAPI := socketAPIConn(t, socketAddr, "secret")
	defer udpAPI.Close()
	udpListenerID := socketproto.ClientIDBase + 501
	payload, err = socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.92.2")),
		Protocol:  socketproto.ProtoUDP,
		BindIP:    netip.MustParseAddr("100.64.92.2"),
		BindPort:  19091,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(udpAPI, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, udpAPI)
	if frame.Action != socketproto.ActionAccept || frame.ID != udpListenerID {
		t.Fatalf("UDP listener accept frame = id %d action %d payload %q", frame.ID, frame.Action, frame.Payload)
	}
	unsolicited, err := serverEng.DialUDP(netip.AddrPort{}, netip.MustParseAddrPort("100.64.92.2:19091"))
	if err != nil {
		t.Fatal(err)
	}
	defer unsolicited.Close()
	if _, err := unsolicited.Write([]byte("unsolicited")); err != nil {
		t.Fatal(err)
	}
	_ = udpAPI.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if frame, err := socketproto.ReadFrame(udpAPI, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("UDP listener delivered unsolicited datagram with udp_inbound disabled: action %d payload %q", frame.Action, frame.Payload)
	}
	dgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(netip.MustParseAddr("100.64.92.1")),
		RemoteIP:   netip.MustParseAddr("100.64.92.1"),
		RemotePort: 18081,
		Payload:    []byte("udp listener echo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(udpAPI, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionUDPDatagram, Payload: dgram}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, udpAPI)
	if frame.Action != socketproto.ActionUDPDatagram {
		t.Fatalf("UDP listener echo frame = action %d payload %q", frame.Action, frame.Payload)
	}
	gotDgram, err := socketproto.DecodeUDPDatagram(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotDgram.Payload) != "udp listener echo" {
		t.Fatalf("UDP listener echo mismatch: %q", gotDgram.Payload)
	}
}

func TestSocketAPIRejectsICMPByACLAndUnroutedIPv6(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.93.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	cfg.ACL.Outbound = []acl.Rule{{Action: acl.Deny, Protocol: "icmp"}}
	fallback := false
	cfg.Proxy.FallbackDirect = &fallback
	eng := mustStart(t, cfg)

	conn := socketAPIConn(t, "http://"+eng.Addr("api"), "secret")
	defer conn.Close()
	id := socketproto.ClientIDBase + 710
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.93.2")),
		Protocol:  socketproto.ProtoICMP,
		DestIP:    netip.MustParseAddr("100.64.93.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionClose || !bytes.Contains(frame.Payload, []byte("blocked by outbound ACL")) {
		t.Fatalf("ICMP ACL rejection frame = action %d payload %q", frame.Action, frame.Payload)
	}

	id++
	payload, err = socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("fd7a:115c:a1e0::99")),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    netip.MustParseAddr("fd7a:115c:a1e0::99"),
		DestPort:  443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionClose || !bytes.Contains(frame.Payload, []byte("IPv6 is disabled")) {
		t.Fatalf("IPv6 rejection frame = action %d payload %q", frame.Action, frame.Payload)
	}
}

func TestSocketAPIFallbackDirectTCPUDPAndICMP(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()
	udpPC, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpPC.Close()
	go serveUDPEcho(udpPC)

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.97.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	eng := mustStart(t, cfg)

	socketAddr := "http://" + eng.Addr("api")
	got := socketAPITCPEcho(t, socketAddr, "secret", netip.MustParseAddrPort(net.JoinHostPort(hostIP.String(), echo.Port)), []byte("raw socket direct tcp"))
	if string(got) != "raw socket direct tcp" {
		t.Fatalf("TCP direct fallback echo mismatch: %q", got)
	}
	udpPort := udpPC.LocalAddr().(*net.UDPAddr).Port
	got = socketAPIUDPEcho(t, socketAddr, "secret", netip.MustParseAddrPort(net.JoinHostPort(hostIP.String(), fmt.Sprintf("%d", udpPort))), []byte("raw socket direct udp"))
	if string(got) != "raw socket direct udp" {
		t.Fatalf("UDP direct fallback echo mismatch: %q", got)
	}
	if hostPingSupported(hostIP) {
		got = socketAPIICMPEcho(t, socketAddr, "secret", hostIP, []byte("raw socket direct icmp"))
		if string(got) != "raw socket direct icmp" {
			t.Fatalf("ICMP direct fallback echo mismatch: %q", got)
		}
	}
}

func TestSocketAPIHTTPProxySocketUpgradeRequiresAndAcceptsBasicAuth(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.98.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.98.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.98.2/32"}
	clientCfg.Proxy.HTTP = "127.0.0.1:0"
	clientCfg.Proxy.Username = "alice"
	clientCfg.Proxy.Password = "secret"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.98.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	tcpLn, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.98.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go serveEchoListener(tcpLn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := socketproto.DialHTTP(ctx, "http://"+clientEng.Addr("http"), "", "/uwg/socket"); err == nil {
		t.Fatal("unauthenticated /uwg/socket upgrade unexpectedly succeeded")
	}

	conn, err := socketproto.DialHTTP(ctx, "http://alice:secret@"+clientEng.Addr("http"), "", "/uwg/socket")
	if err != nil {
		t.Fatalf("authenticated /uwg/socket upgrade failed: %v", err)
	}
	defer conn.Close()

	id := socketproto.ClientIDBase + 812
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.98.1")),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    netip.MustParseAddr("100.64.98.1"),
		DestPort:  18080,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("authenticated /uwg/socket connect failed: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: []byte("proxy socket auth")}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "proxy socket auth" {
		t.Fatalf("authenticated /uwg/socket echo mismatch: action %d payload %q", frame.Action, frame.Payload)
	}
}

func TestSocketAPIUDPBindWithoutBindPrivilegeIsEstablishedOnly(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.95.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.95.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.95.2/32"}
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.SocketAPI.Bind = false
	clientCfg.Inbound.UDPIdleTimeoutSeconds = 1
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.95.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	udpPC, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.95.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpPC.Close()
	go serveUDPEcho(udpPC)

	apiConn := socketAPIConn(t, "http://"+clientEng.Addr("api"), "secret")
	defer apiConn.Close()
	udpListenerID := socketproto.ClientIDBase + 600
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.95.2")),
		Protocol:  socketproto.ProtoUDP,
		BindIP:    netip.MustParseAddr("100.64.95.2"),
		BindPort:  19091,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionAccept || frame.ID != udpListenerID {
		t.Fatalf("UDP bind without privilege was not accepted: action %d payload %q", frame.Action, frame.Payload)
	}

	if _, err := udpPC.WriteTo([]byte("unsolicited"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.64.95.2:19091"))); err != nil {
		t.Fatal(err)
	}
	// 500ms still wasn't enough on macOS-latest under -race —
	// the unsolicited datagram took >500ms to round-trip under
	// race overhead and then leaked into the LATER established-echo
	// read at line 433. 2s gives the unsolicited path comfortable
	// budget to either (a) get correctly dropped or (b) arrive and
	// fail loudly here, never both.
	_ = apiConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if frame, err := socketproto.ReadFrame(apiConn, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("UDP bind delivered unsolicited datagram with bind=false: action %d payload %q", frame.Action, frame.Payload)
	}

	dgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(netip.MustParseAddr("100.64.95.1")),
		RemoteIP:   netip.MustParseAddr("100.64.95.1"),
		RemotePort: 18081,
		Payload:    []byte("udp established echo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionUDPDatagram, Payload: dgram}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	gotDgram, err := socketproto.DecodeUDPDatagram(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Action != socketproto.ActionUDPDatagram || string(gotDgram.Payload) != "udp established echo" {
		t.Fatalf("UDP established echo mismatch: action %d payload %q", frame.Action, gotDgram.Payload)
	}

	time.Sleep(1200 * time.Millisecond)
	if _, err := udpPC.WriteTo([]byte("expired"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.64.95.2:19091"))); err != nil {
		t.Fatal(err)
	}
	_ = apiConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if frame, err := socketproto.ReadFrame(apiConn, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("UDP bind delivered expired peer datagram with bind=false: action %d payload %q", frame.Action, frame.Payload)
	}
}

func TestSocketAPIUDPListenerCanReconnectAndDisconnect(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.96.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.96.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	udpOne, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.96.1:18101"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpOne.Close()
	go serveUDPEcho(udpOne)

	udpTwo, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.96.1:18102"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpTwo.Close()
	go serveUDPEcho(udpTwo)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.96.2/32"}
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.SocketAPI.Bind = false
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.96.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	apiConn := socketAPIConn(t, "http://"+clientEng.Addr("api"), "secret")
	defer apiConn.Close()
	id := socketproto.ClientIDBase + 700
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.96.2")),
		Protocol:  socketproto.ProtoUDP,
		BindIP:    netip.MustParseAddr("100.64.96.2"),
		BindPort:  19091,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP listener accept failed: action %d payload %q", frame.Action, frame.Payload)
	}

	socketAPIUDPReconnect(t, apiConn, id, netip.MustParseAddrPort("100.64.96.1:18101"))
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: []byte("connected-one")}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "connected-one" {
		t.Fatalf("connected UDP first echo = action %d payload %q", frame.Action, frame.Payload)
	}

	socketAPIUDPReconnect(t, apiConn, id, netip.MustParseAddrPort("100.64.96.1:18102"))
	if _, err := udpOne.WriteTo([]byte("old-remote"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.64.96.2:19091"))); err != nil {
		t.Fatal(err)
	}
	_ = apiConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if frame, err := socketproto.ReadFrame(apiConn, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("reconnected UDP delivered old remote datagram: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: []byte("connected-two")}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "connected-two" {
		t.Fatalf("connected UDP second echo = action %d payload %q", frame.Action, frame.Payload)
	}

	socketAPIUDPDisconnect(t, apiConn, id)
	dgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(netip.MustParseAddr("100.64.96.1")),
		RemoteIP:   netip.MustParseAddr("100.64.96.1"),
		RemotePort: 18101,
		Payload:    []byte("unconnected-again"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionUDPDatagram, Payload: dgram}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionUDPDatagram {
		t.Fatalf("unconnected UDP echo action = %d payload %q", frame.Action, frame.Payload)
	}
	gotDgram, err := socketproto.DecodeUDPDatagram(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotDgram.Payload) != "unconnected-again" {
		t.Fatalf("unconnected UDP echo mismatch: %q", gotDgram.Payload)
	}
}

func socketAPIUDPReconnect(t *testing.T, conn net.Conn, id uint64, dst netip.AddrPort) {
	t.Helper()
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		ListenerID: id,
		IPVersion:  socketproto.AddrVersion(dst.Addr()),
		Protocol:   socketproto.ProtoUDP,
		DestIP:     dst.Addr(),
		DestPort:   dst.Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP reconnect failed: action %d payload %q", frame.Action, frame.Payload)
	}
}

func socketAPIUDPDisconnect(t *testing.T, conn net.Conn, id uint64) {
	t.Helper()
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		ListenerID: id,
		IPVersion:  4,
		Protocol:   socketproto.ProtoUDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP disconnect failed: action %d payload %q", frame.Action, frame.Payload)
	}
}

func socketAPITCPEcho(t *testing.T, api, token string, dst netip.AddrPort, msg []byte) []byte {
	t.Helper()
	conn := socketAPIConn(t, api, token)
	defer conn.Close()
	id := socketproto.ClientIDBase + 10
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dst.Addr()),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    dst.Addr(),
		DestPort:  dst.Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("TCP connect failed: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: msg}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionData {
		t.Fatalf("TCP data failed: action %d payload %q", frame.Action, frame.Payload)
	}
	return frame.Payload
}

func socketAPIUDPEcho(t *testing.T, api, token string, dst netip.AddrPort, msg []byte) []byte {
	t.Helper()
	conn := socketAPIConn(t, api, token)
	defer conn.Close()
	id := socketproto.ClientIDBase + 11
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dst.Addr()),
		Protocol:  socketproto.ProtoUDP,
		DestIP:    dst.Addr(),
		DestPort:  dst.Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP connect failed: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: msg}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionData {
		t.Fatalf("UDP data failed: action %d payload %q", frame.Action, frame.Payload)
	}
	return frame.Payload
}

func socketAPIICMPEcho(t *testing.T, api, token string, dst netip.Addr, msg []byte) []byte {
	t.Helper()
	// Retry up to 3 times: under heavy CI load the netstack ICMP reply goroutine
	// can be starved past the per-attempt 30 s deadline even though the WG session
	// is already established (TCP and UDP echo pass first).
	const maxAttempts = 3
	for attempt := range maxAttempts {
		if attempt > 0 {
			time.Sleep(time.Second)
		}
		conn := socketAPIConn(t, api, token)
		got, ok := tryICMPEchoOnce(conn, dst, msg)
		conn.Close()
		if ok {
			return got
		}
	}
	t.Fatal("ICMP socket API echo: all attempts timed out")
	return nil
}

// tryICMPEchoOnce performs one ICMP echo exchange on conn and returns
// (reply payload, true) on success or (nil, false) on any error or timeout.
// It does not call t.Fatal so the caller can retry on a fresh connection.
func tryICMPEchoOnce(conn net.Conn, dst netip.Addr, msg []byte) ([]byte, bool) {
	id := socketproto.ClientIDBase + 12
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dst),
		Protocol:  socketproto.ProtoICMP,
		DestIP:    dst,
	})
	if err != nil {
		return nil, false
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		return nil, false
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second * testDeadlineScale))
	frame, err := socketproto.ReadFrame(conn, socketproto.DefaultMaxPayload)
	if err != nil || frame.Action != socketproto.ActionAccept {
		return nil, false
	}
	req, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0x1234, Seq: 7, Data: msg},
	}).Marshal(nil)
	if err != nil {
		return nil, false
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: req}); err != nil {
		return nil, false
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second * testDeadlineScale))
	frame, err = socketproto.ReadFrame(conn, socketproto.DefaultMaxPayload)
	if err != nil || frame.Action != socketproto.ActionData {
		return nil, false
	}
	reply, err := icmp.ParseMessage(1, frame.Payload)
	if err != nil {
		return nil, false
	}
	echo, ok := reply.Body.(*icmp.Echo)
	if !ok || reply.Type != ipv4.ICMPTypeEchoReply || echo.Seq != 7 {
		return nil, false
	}
	return echo.Data, true
}

// TestSocketAPISameHostUDPLoopback exercises the engine's same-host UDP
// shortcut. gVisor netstack does not loop UDP between two listeners bound
// to the same NIC IP (see TestSameNICLoopbackUDP in netstackex), which
// would otherwise break the udp-echo-bind production catalog test:
// wrapped server bound to 10.200.0.1:<port> + wrapped client auto-bound
// at 10.200.0.1:<eph>. The engine maintains an addr→listener registry
// and short-circuits these datagrams directly between the two
// socket-API sessions.
func TestSocketAPISameHostUDPLoopback(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.97.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	cfg.SocketAPI.Bind = true
	cfg.SocketAPI.TransparentBind = true
	cfg.SocketAPI.UDPInbound = true
	eng := mustStart(t, cfg)

	apiAddr := "http://" + eng.Addr("api")
	srvConn := socketAPIConn(t, apiAddr, "secret")
	defer srvConn.Close()
	cliConn := socketAPIConn(t, apiAddr, "secret")
	defer cliConn.Close()

	srvBind := netip.MustParseAddr("100.64.97.1")
	srvPort := uint16(19097)
	srvID := socketproto.ClientIDBase + 800
	srvPayload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(srvBind),
		Protocol:  socketproto.ProtoUDP,
		BindIP:    srvBind,
		BindPort:  srvPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(srvConn, socketproto.Frame{ID: srvID, Action: socketproto.ActionConnect, Payload: srvPayload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, srvConn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("server UDP bind not accepted: action %d payload %q", frame.Action, frame.Payload)
	}

	cliID := socketproto.ClientIDBase + 801
	cliPayload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(srvBind),
		Protocol:  socketproto.ProtoUDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(cliConn, socketproto.Frame{ID: cliID, Action: socketproto.ActionConnect, Payload: cliPayload}); err != nil {
		t.Fatal(err)
	}
	cliAccept := readSocketFrame(t, cliConn)
	if cliAccept.Action != socketproto.ActionAccept {
		t.Fatalf("client UDP listener not accepted: action %d payload %q", cliAccept.Action, cliAccept.Payload)
	}
	cliAcceptDecoded, err := socketproto.DecodeAccept(cliAccept.Payload)
	if err != nil {
		t.Fatal(err)
	}
	cliBindAddr := netip.AddrPortFrom(cliAcceptDecoded.BindIP, cliAcceptDecoded.BindPort)
	if !cliBindAddr.IsValid() {
		t.Fatalf("client listener did not return a valid bind addr: %+v", cliAcceptDecoded)
	}

	dgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(srvBind),
		RemoteIP:   srvBind,
		RemotePort: srvPort,
		Payload:    []byte("samehost-hello"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(cliConn, socketproto.Frame{ID: cliID, Action: socketproto.ActionUDPDatagram, Payload: dgram}); err != nil {
		t.Fatal(err)
	}

	srvFrame := readSocketFrame(t, srvConn)
	if srvFrame.Action != socketproto.ActionUDPDatagram {
		t.Fatalf("server did not receive same-host UDP datagram: action %d payload %q", srvFrame.Action, srvFrame.Payload)
	}
	gotDgram, err := socketproto.DecodeUDPDatagram(srvFrame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotDgram.Payload) != "samehost-hello" {
		t.Fatalf("server payload mismatch: %q", gotDgram.Payload)
	}
	gotSender := netip.AddrPortFrom(gotDgram.RemoteIP, gotDgram.RemotePort)
	if gotSender != cliBindAddr {
		t.Fatalf("server saw sender %v, want %v", gotSender, cliBindAddr)
	}

	echoDgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  gotDgram.IPVersion,
		RemoteIP:   gotDgram.RemoteIP,
		RemotePort: gotDgram.RemotePort,
		Payload:    []byte("echo:" + string(gotDgram.Payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(srvConn, socketproto.Frame{ID: srvID, Action: socketproto.ActionUDPDatagram, Payload: echoDgram}); err != nil {
		t.Fatal(err)
	}

	cliFrame := readSocketFrame(t, cliConn)
	if cliFrame.Action != socketproto.ActionUDPDatagram {
		t.Fatalf("client did not receive echo: action %d payload %q", cliFrame.Action, cliFrame.Payload)
	}
	cliDecoded, err := socketproto.DecodeUDPDatagram(cliFrame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(cliDecoded.Payload) != "echo:samehost-hello" {
		t.Fatalf("client echo payload mismatch: %q", cliDecoded.Payload)
	}
	gotEchoSender := netip.AddrPortFrom(cliDecoded.RemoteIP, cliDecoded.RemotePort)
	wantEchoSender := netip.AddrPortFrom(srvBind, srvPort)
	if gotEchoSender != wantEchoSender {
		t.Fatalf("client echo sender = %v, want %v", gotEchoSender, wantEchoSender)
	}
}

// TestSocketAPISameHostTCPLoopback exercises the same-host TCP loopback
// path added alongside the UDP one. gVisor netstack does NOT loop TCP
// between two listeners bound to the same NIC IP; without engine-level
// short-circuit, two wrapped processes on the same host both targeting
// the tunnel addr (e.g. wrapped postgres-server + wrapped psql client)
// cannot connect. The engine's tcpLoopbackRegistry hands an in-process
// net.Pipe pair to both sides on a dial hit, so the dialer's wrapped
// session sees the same observable behavior it would over a real
// netstack TCP round-trip.
//
// Test shape: register a TCP listener at the tunnel addr, dial from a
// second socket-API connection, exchange a few bytes both ways,
// confirm everything observable matches the netstack-arrived path
// (LocalAddr, RemoteAddr on both ends; ActionAccept payloads contain
// the listener's bind addr; etc).
func TestSocketAPISameHostTCPLoopback(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.97.2/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	cfg.SocketAPI.Bind = true
	cfg.SocketAPI.TransparentBind = true
	eng := mustStart(t, cfg)

	apiAddr := "http://" + eng.Addr("api")
	srvConn := socketAPIConn(t, apiAddr, "secret")
	defer srvConn.Close()
	cliConn := socketAPIConn(t, apiAddr, "secret")
	defer cliConn.Close()

	// Server side: bind a TCP listener at the tunnel addr.
	srvBind := netip.MustParseAddr("100.64.97.2")
	srvPort := uint16(19098)
	srvListenerID := socketproto.ClientIDBase + 900
	srvPayload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(srvBind),
		Protocol:  socketproto.ProtoTCP,
		BindIP:    srvBind,
		BindPort:  srvPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(srvConn, socketproto.Frame{ID: srvListenerID, Action: socketproto.ActionConnect, Payload: srvPayload}); err != nil {
		t.Fatal(err)
	}
	srvAccept := readSocketFrame(t, srvConn)
	if srvAccept.Action != socketproto.ActionAccept {
		t.Fatalf("server TCP listener not accepted: action %d payload %q", srvAccept.Action, srvAccept.Payload)
	}

	// Client side: dial the tunnel addr — should hit the loopback registry.
	cliID := socketproto.ClientIDBase + 901
	cliPayload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(srvBind),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    srvBind,
		DestPort:  srvPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(cliConn, socketproto.Frame{ID: cliID, Action: socketproto.ActionConnect, Payload: cliPayload}); err != nil {
		t.Fatal(err)
	}
	cliAccept := readSocketFrame(t, cliConn)
	if cliAccept.Action != socketproto.ActionAccept {
		t.Fatalf("client TCP dial not accepted (loopback path): action %d payload %q", cliAccept.Action, cliAccept.Payload)
	}
	cliLocal, err := socketproto.DecodeAccept(cliAccept.Payload)
	if err != nil {
		t.Fatal(err)
	}
	clientAP := netip.AddrPortFrom(cliLocal.BindIP, cliLocal.BindPort)
	if !clientAP.IsValid() {
		t.Fatalf("client did not get a synthesized source addr: %+v", cliLocal)
	}

	// Server should see an ActionConnect frame for the new accepted conn.
	srvFrame := readSocketFrame(t, srvConn)
	if srvFrame.Action != socketproto.ActionConnect {
		t.Fatalf("server did not see accepted-conn ActionConnect: action %d", srvFrame.Action)
	}
	srvAcc, err := socketproto.DecodeConnect(srvFrame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if srvAcc.ListenerID != srvListenerID {
		t.Fatalf("accepted-conn ListenerID = %d, want %d", srvAcc.ListenerID, srvListenerID)
	}
	gotSrcAP := netip.AddrPortFrom(srvAcc.DestIP, srvAcc.DestPort)
	if gotSrcAP != clientAP {
		t.Fatalf("server saw client source %v, want %v (loopback should preserve synthesized client addr)", gotSrcAP, clientAP)
	}
	acceptedID := srvFrame.ID
	// Server acknowledges the new accepted session via ActionAccept (same
	// frame the engine uses for both directions of the connect handshake).
	if err := socketproto.WriteFrame(srvConn, socketproto.Frame{ID: acceptedID, Action: socketproto.ActionAccept}); err != nil {
		t.Fatal(err)
	}

	// Client sends data → server reads.
	if err := socketproto.WriteFrame(cliConn, socketproto.Frame{ID: cliID, Action: socketproto.ActionData, Payload: []byte("ping-loopback")}); err != nil {
		t.Fatal(err)
	}
	dataFrame := readSocketFrame(t, srvConn)
	if dataFrame.Action != socketproto.ActionData || dataFrame.ID != acceptedID {
		t.Fatalf("server data frame: action=%d id=%d want ActionData id=%d", dataFrame.Action, dataFrame.ID, acceptedID)
	}
	if string(dataFrame.Payload) != "ping-loopback" {
		t.Fatalf("server payload = %q, want %q", dataFrame.Payload, "ping-loopback")
	}

	// Server echoes → client reads.
	if err := socketproto.WriteFrame(srvConn, socketproto.Frame{ID: acceptedID, Action: socketproto.ActionData, Payload: []byte("pong-loopback")}); err != nil {
		t.Fatal(err)
	}
	echoFrame := readSocketFrame(t, cliConn)
	if echoFrame.Action != socketproto.ActionData || echoFrame.ID != cliID {
		t.Fatalf("client echo frame: action=%d id=%d want ActionData id=%d", echoFrame.Action, echoFrame.ID, cliID)
	}
	if string(echoFrame.Payload) != "pong-loopback" {
		t.Fatalf("client echo payload = %q, want %q", echoFrame.Payload, "pong-loopback")
	}
}

func socketAPIConn(t *testing.T, api, token string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := socketproto.DialHTTP(ctx, api, token, "/v1/socket")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func readSocketFrame(t *testing.T, conn net.Conn) socketproto.Frame {
	t.Helper()
	// 10s normally; on macOS+race the wireguard-go + gvisor pipeline
	// repeatedly hit the 100s-scaled deadline (beta.41 on Windows, then
	// beta.49 on macOS — the test ran 103.92s, exactly at the limit).
	// 30s base × 10×race = 300s budget gives macOS+race much more
	// headroom for the established-only UDP bind path which involves
	// per-fd kernel-cap checks that are unusually slow under TSan.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second * testDeadlineScale))
	frame, err := socketproto.ReadFrame(conn, socketproto.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestSocketProtocolRejectsMalformedFrame(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.93.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	eng := mustStart(t, cfg)

	conn := socketAPIConn(t, "http://"+eng.Addr("api"), "secret")
	defer conn.Close()
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: socketproto.ClientIDBase + 1, Action: socketproto.ActionConnect, Payload: []byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionClose || !bytes.Contains(frame.Payload, []byte("bad socket protocol frame")) {
		t.Fatalf("malformed frame response = action %d payload %q", frame.Action, frame.Payload)
	}
}
