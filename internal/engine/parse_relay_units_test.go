// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// These tests pin parseRelayPacket and the conntrack-key derivation
// at the lowest level — no Engine, no goroutines, no mesh state.
// They mostly exist to make sure we don't accidentally widen what
// counts as a "trackable" packet (which would let malformed traffic
// open conntrack flows for free) or break the forward/reverse key
// symmetry that the relay sweep depends on.

func TestParseRelayPacketRejectsBadInput(t *testing.T) {
	cases := []struct {
		name   string
		packet []byte
	}{
		{"empty", []byte{}},
		{"version 0", []byte{0x00, 0, 0, 0}},
		{"version 7", []byte{0x70, 0, 0, 0}},
		{"v4 too short", []byte{0x45, 0, 0, 0, 0}},
		{"v4 ihl too small", func() []byte {
			b := make([]byte, 20)
			b[0] = 0x42 // ihl=2 → 8 bytes, below minimum
			return b
		}()},
		{"v4 total length larger than buffer", func() []byte {
			b := make([]byte, 20)
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:4], 9999)
			return b
		}()},
		{"v4 total length smaller than ihl", func() []byte {
			b := make([]byte, 20)
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:4], 10) // < 20
			return b
		}()},
		{"v6 too short", make([]byte, 39)},
		{"v6 payload exceeds buffer", func() []byte {
			b := make([]byte, 40)
			b[0] = 0x60
			binary.BigEndian.PutUint16(b[4:6], 1000)
			return b
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseRelayPacket(tc.packet); ok {
				t.Fatalf("expected parse failure for %s", tc.name)
			}
		})
	}
}

func TestParseRelayPacketIPv4UDPHappyPath(t *testing.T) {
	pkt := testIPv4UDPPacket("100.64.1.2", "100.64.2.3", 12345, 53)
	meta, ok := parseRelayPacket(pkt)
	if !ok {
		t.Fatal("expected parse success")
	}
	if meta.proto != 17 || meta.network != "udp" {
		t.Fatalf("unexpected proto/network %d/%s", meta.proto, meta.network)
	}
	if meta.src.Port() != 12345 || meta.dst.Port() != 53 {
		t.Fatalf("unexpected ports src=%d dst=%d", meta.src.Port(), meta.dst.Port())
	}
	if meta.src.Addr() != netip.MustParseAddr("100.64.1.2") {
		t.Fatalf("unexpected src addr %s", meta.src.Addr())
	}
}

func TestParseRelayPacketIPv4TCPCarriesFlags(t *testing.T) {
	pkt := testIPv4TCPPacketFlags("100.64.1.2", "100.64.2.3", 40000, 443, tcpFlagSYN|tcpFlagACK)
	meta, ok := parseRelayPacket(pkt)
	if !ok {
		t.Fatal("expected parse success")
	}
	if meta.tcpFlags != tcpFlagSYN|tcpFlagACK {
		t.Fatalf("unexpected tcp flags 0x%02x", meta.tcpFlags)
	}
	if meta.network != "tcp" {
		t.Fatalf("unexpected network %s", meta.network)
	}
}

func TestParseRelayPacketIPv4FragmentDropsTransport(t *testing.T) {
	pkt := testIPv4UDPPacket("100.64.1.2", "100.64.2.3", 12345, 53)
	// Set fragment offset so the parser can't trust the transport bytes.
	binary.BigEndian.PutUint16(pkt[6:8], 0x00ff)
	meta, ok := parseRelayPacket(pkt)
	if !ok {
		t.Fatal("expected parse success")
	}
	// Transport ports must be zeroed — packetPorts returns 0/0 when
	// the slice is too short.
	if meta.src.Port() != 0 || meta.dst.Port() != 0 {
		t.Fatalf("expected fragment to zero transport ports, got src=%d dst=%d", meta.src.Port(), meta.dst.Port())
	}
}

func TestParseRelayPacketIPv6TCPHappyPath(t *testing.T) {
	pkt := testIPv6TCPPacketFlags("fd00::1", "fd00::2", 40000, 443, tcpFlagSYN)
	meta, ok := parseRelayPacket(pkt)
	if !ok {
		t.Fatal("expected parse success")
	}
	if meta.proto != 6 || meta.network != "tcp" {
		t.Fatalf("unexpected proto/network %d/%s", meta.proto, meta.network)
	}
	if meta.tcpFlags != tcpFlagSYN {
		t.Fatalf("expected SYN flag, got 0x%02x", meta.tcpFlags)
	}
	if meta.src.Addr() != netip.MustParseAddr("fd00::1") {
		t.Fatalf("unexpected src addr %s", meta.src.Addr())
	}
}

func TestParseRelayPacketIPv4ICMPEchoRecordsID(t *testing.T) {
	pkt := testIPv4ICMPEcho("100.64.1.2", "100.64.2.3", 8, 0xabcd)
	meta, ok := parseRelayPacket(pkt)
	if !ok {
		t.Fatal("expected parse success")
	}
	if meta.network != "icmp" {
		t.Fatalf("unexpected network %s", meta.network)
	}
	if meta.icmpType != 8 {
		t.Fatalf("expected icmpType=8, got %d", meta.icmpType)
	}
	if meta.icmpID != 0xabcd {
		t.Fatalf("expected icmpID=0xabcd, got 0x%x", meta.icmpID)
	}
	if meta.icmpErr {
		t.Fatal("echo should not be flagged as icmpErr")
	}
}

func TestParseRelayPacketIPv4ICMPErrorParsesInnerPacket(t *testing.T) {
	// inner = original UDP datagram that triggered Dest-Unreachable.
	inner := testIPv4UDPPacket("100.64.2.3", "8.8.8.8", 53000, 53)
	outer := testIPv4ICMPError("100.64.1.2", "100.64.2.3", inner)
	meta, ok := parseRelayPacket(outer)
	if !ok {
		t.Fatal("expected outer parse success")
	}
	if !meta.icmpErr {
		t.Fatal("expected icmpErr=true on type 3 ICMP")
	}
	if meta.inner == nil {
		t.Fatal("expected inner packet to be parsed")
	}
	if meta.inner.network != "udp" {
		t.Fatalf("unexpected inner network %s", meta.inner.network)
	}
	if meta.inner.src.Port() != 53000 || meta.inner.dst.Port() != 53 {
		t.Fatalf("inner port mismatch src=%d dst=%d", meta.inner.src.Port(), meta.inner.dst.Port())
	}
}

func TestRelayForwardReverseKeySymmetry(t *testing.T) {
	pkt := testIPv4UDPPacket("100.64.1.2", "100.64.2.3", 12345, 53)
	meta, ok := parseRelayPacket(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	fwd := relayForwardKey(meta)
	rev := relayReverseKey(meta)
	if fwd == rev {
		t.Fatal("forward/reverse keys should differ for asymmetric flows")
	}
	if fwd.InitIP != rev.RespIP || fwd.RespIP != rev.InitIP {
		t.Fatalf("forward/reverse IPs not swapped: fwd=%+v rev=%+v", fwd, rev)
	}
	if fwd.InitPort != rev.RespPort || fwd.RespPort != rev.InitPort {
		t.Fatalf("forward/reverse ports not swapped: fwd=%+v rev=%+v", fwd, rev)
	}
	if fwd.Proto != rev.Proto {
		t.Fatalf("proto must match: fwd=%d rev=%d", fwd.Proto, rev.Proto)
	}
}

func TestRelayForwardKeyICMPCollapsesPorts(t *testing.T) {
	pkt := testIPv4ICMPEcho("100.64.1.2", "100.64.2.3", 8, 0x4242)
	meta, ok := parseRelayPacket(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	key := relayForwardKey(meta)
	if key.InitPort != 0x4242 {
		t.Fatalf("expected ICMP id in InitPort, got %d", key.InitPort)
	}
	if key.RespPort != 0 {
		t.Fatalf("expected RespPort=0 for ICMP, got %d", key.RespPort)
	}
}

func TestRelayCanOpenFlow(t *testing.T) {
	cases := []struct {
		name string
		meta relayPacketMeta
		want bool
	}{
		{"udp", relayPacketMeta{proto: 17}, true},
		{"tcp syn", relayPacketMeta{proto: 6, tcpFlags: tcpFlagSYN}, true},
		{"tcp synack", relayPacketMeta{proto: 6, tcpFlags: tcpFlagSYN | tcpFlagACK}, false},
		{"tcp ack only", relayPacketMeta{proto: 6, tcpFlags: tcpFlagACK}, false},
		{"tcp rst", relayPacketMeta{proto: 6, tcpFlags: tcpFlagRST}, false},
		{"icmp echo request", relayPacketMeta{proto: relayProtoICMP, icmpType: 8}, true},
		{"icmp echo reply", relayPacketMeta{proto: relayProtoICMP, icmpType: 0}, false},
		{"icmp other", relayPacketMeta{proto: relayProtoICMP, icmpType: 3}, false},
		{"unknown proto", relayPacketMeta{proto: 99}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayCanOpenFlow(tc.meta); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestRelayTrackable(t *testing.T) {
	cases := []struct {
		name string
		meta relayPacketMeta
		want bool
	}{
		{"tcp", relayPacketMeta{proto: 6}, true},
		{"udp", relayPacketMeta{proto: 17}, true},
		{"icmp echo", relayPacketMeta{proto: relayProtoICMP, icmpType: 8}, true},
		{"icmp echo reply", relayPacketMeta{proto: relayProtoICMP, icmpType: 0}, true},
		{"icmp dest unreachable", relayPacketMeta{proto: relayProtoICMP, icmpType: 3}, false},
		{"icmp time exceeded", relayPacketMeta{proto: relayProtoICMP, icmpType: 11}, false},
		{"unknown proto", relayPacketMeta{proto: 50}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayTrackable(tc.meta); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestRelayICMPErrorTypeMatrix(t *testing.T) {
	// IPv4 = proto 1, IPv6 = proto 58. Each protocol family has its
	// own type numbers for the same logical errors. A regression that
	// confused the two would silently change which errors get inner-
	// packet parsing, so pin the matrix.
	cases := []struct {
		name  string
		proto byte
		typ   byte
		want  bool
	}{
		// ICMPv4
		{"v4 dest unreachable", 1, 3, true},
		{"v4 time exceeded", 1, 11, true},
		{"v4 param problem", 1, 12, true},
		{"v4 echo request not error", 1, 8, false},
		{"v4 echo reply not error", 1, 0, false},
		// ICMPv6
		{"v6 dest unreachable", 58, 1, true},
		{"v6 packet too big", 58, 2, true},
		{"v6 time exceeded", 58, 3, true},
		{"v6 param problem", 58, 4, true},
		{"v6 echo request not error", 58, 128, false},
		{"v6 echo reply not error", 58, 129, false},
		// relayICMPError treats anything that isn't proto 58 as
		// "use the IPv4 error set"; callers are responsible for only
		// passing 1 or 58. Pin that contract by asserting v4 typ 3
		// also returns true via proto=1 (the documented input).
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayICMPError(tc.proto, tc.typ); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestPacketPortsHandlesShortTransport(t *testing.T) {
	// TCP needs ≥4 bytes; UDP needs ≥4 bytes; anything else returns 0/0.
	if sp, dp := packetPorts(6, []byte{1, 2, 3}); sp != 0 || dp != 0 {
		t.Fatalf("short tcp transport must yield 0/0, got %d/%d", sp, dp)
	}
	if sp, dp := packetPorts(17, []byte{1, 2, 3}); sp != 0 || dp != 0 {
		t.Fatalf("short udp transport must yield 0/0, got %d/%d", sp, dp)
	}
	// Happy path: BE-encoded src+dst.
	sp, dp := packetPorts(6, []byte{0x12, 0x34, 0x00, 0x50, 9, 9, 9, 9})
	if sp != 0x1234 || dp != 0x0050 {
		t.Fatalf("got src=%d dst=%d", sp, dp)
	}
	// Unknown proto: zero regardless of buffer.
	if sp, dp := packetPorts(99, []byte{1, 2, 3, 4}); sp != 0 || dp != 0 {
		t.Fatalf("unknown proto should yield 0/0, got %d/%d", sp, dp)
	}
}
