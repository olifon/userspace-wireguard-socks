//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

func TestUDPListenerGroupPeerOwnerLimit(t *testing.T) {
	g := &udpListenerGroup{
		peerOwner: make(map[string]udpPeerOwnerEntry),
	}

	first := netip.MustParseAddrPort("192.0.2.1:10000")
	for i := 0; i < maxUDPListenerPeerOwners+8; i++ {
		addr := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 250)}),
			uint16(10000+i),
		)
		g.recordPeerOwner(addr, "token")
	}

	if got := len(g.peerOwner); got != maxUDPListenerPeerOwners {
		t.Fatalf("peerOwner size = %d, want %d", got, maxUDPListenerPeerOwners)
	}
	if owner := g.ownerFor(first); owner != "" {
		t.Fatalf("oldest peer owner = %q, want eviction", owner)
	}
	latest := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte((maxUDPListenerPeerOwners + 7) % 250)}), uint16(10000+maxUDPListenerPeerOwners+7))
	if owner := g.ownerFor(latest); owner != "token" {
		t.Fatalf("latest peer owner = %q, want token", owner)
	}
}

// TestUDPDispatchDeliversUnsolicitedFirstContact pins the fdproxy
// behaviour change that was load-bearing for udp-echo-bind: when a
// datagram arrives via serveUpstream (fromLoopback=false) for a
// remote that no member has previously sent to, deliver to a member
// instead of dropping. The engine's socket_api.udp_inbound is the
// authoritative gate for unsolicited traffic; the fdproxy used to
// drop here as a second-layer firewall, but that silently broke
// wrapped UDP servers receiving first contact even when the engine
// allowed it.
func TestUDPDispatchDeliversUnsolicitedFirstContact(t *testing.T) {
	g := &udpListenerGroup{
		peerOwner: make(map[string]udpPeerOwnerEntry),
		members:   make(map[string]net.Conn),
	}
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	g.members["only-member"] = clientSide
	g.order = []string{"only-member"}

	gotCh := make(chan socketproto.UDPDatagram, 1)
	go func() {
		_ = serverSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		// writeLocalPacket writes a 4-byte BE length prefix followed by
		// a raw EncodeUDPDatagram-encoded payload.
		var lenBuf [4]byte
		if _, err := io.ReadFull(serverSide, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		payload := make([]byte, n)
		if _, err := io.ReadFull(serverSide, payload); err != nil {
			return
		}
		d, err := socketproto.DecodeUDPDatagram(payload)
		if err != nil {
			return
		}
		gotCh <- d
	}()

	remote := netip.MustParseAddrPort("198.51.100.7:42424")
	g.dispatchDatagram(remote, []byte("unsolicited"), false)

	select {
	case d := <-gotCh:
		if string(d.Payload) != "unsolicited" {
			t.Fatalf("payload = %q, want %q", d.Payload, "unsolicited")
		}
		gotRemote := netip.AddrPortFrom(d.RemoteIP, d.RemotePort)
		if gotRemote != remote {
			t.Fatalf("remote = %v, want %v", gotRemote, remote)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("fdproxy dropped first-contact datagram with fromLoopback=false; udp-echo-bind would never receive")
	}
}
