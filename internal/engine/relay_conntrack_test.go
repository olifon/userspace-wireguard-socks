package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
)

func TestRelayConntrackPerPeerCounterExpires(t *testing.T) {
	e := testRelayEngine(t, acl.List{Default: acl.Allow}, []netip.Prefix{netip.MustParsePrefix("100.64.2.0/24")})
	e.cfg.Relay.ConntrackMaxFlows = 10
	e.cfg.Relay.ConntrackMaxPerPeer = 1

	now := time.Unix(1000, 0)
	first, ok := parseRelayPacket(testIPv4UDPPacket("100.64.2.2", "100.64.3.3", 40000, 53))
	if !ok {
		t.Fatal("failed to parse first UDP packet")
	}
	second, ok := parseRelayPacket(testIPv4UDPPacket("100.64.2.2", "100.64.3.4", 40001, 53))
	if !ok {
		t.Fatal("failed to parse second UDP packet")
	}
	if !e.allowRelayTracked(first, now) {
		t.Fatal("first UDP flow was denied")
	}
	if e.allowRelayTracked(second, now.Add(time.Second)) {
		t.Fatal("second UDP flow exceeded the per-peer conntrack limit")
	}
	if !e.allowRelayTracked(second, now.Add(31*time.Second)) {
		t.Fatal("expired per-peer flow was not released before admitting a new flow")
	}
}

func TestRelayConntrackPerPeerCounterReleasesOnRST(t *testing.T) {
	e := testRelayEngine(t, acl.List{Default: acl.Allow}, []netip.Prefix{netip.MustParsePrefix("100.64.2.0/24")})
	e.cfg.Relay.ConntrackMaxFlows = 10
	e.cfg.Relay.ConntrackMaxPerPeer = 1

	now := time.Unix(2000, 0)
	syn, ok := parseRelayPacket(testIPv4TCPPacketFlags("100.64.2.2", "100.64.3.3", 40000, 443, tcpFlagSYN))
	if !ok {
		t.Fatal("failed to parse TCP SYN packet")
	}
	synAck, ok := parseRelayPacket(testIPv4TCPPacketFlags("100.64.3.3", "100.64.2.2", 443, 40000, tcpFlagSYN|tcpFlagACK))
	if !ok {
		t.Fatal("failed to parse TCP SYN+ACK packet")
	}
	ack, ok := parseRelayPacket(testIPv4TCPPacketFlags("100.64.2.2", "100.64.3.3", 40000, 443, tcpFlagACK))
	if !ok {
		t.Fatal("failed to parse TCP ACK packet")
	}
	second, ok := parseRelayPacket(testIPv4TCPPacketFlags("100.64.2.2", "100.64.3.4", 40001, 443, tcpFlagSYN))
	if !ok {
		t.Fatal("failed to parse second TCP packet")
	}
	rst, ok := parseRelayPacket(testIPv4TCPPacketFlags("100.64.3.3", "100.64.2.2", 443, 40000, tcpFlagRST|tcpFlagACK))
	if !ok {
		t.Fatal("failed to parse TCP RST packet")
	}
	if !e.allowRelayTracked(syn, now) {
		t.Fatal("TCP SYN was denied")
	}
	if !e.allowRelayTracked(synAck, now.Add(time.Second)) {
		t.Fatal("TCP SYN+ACK was denied")
	}
	if !e.allowRelayTracked(ack, now.Add(2*time.Second)) {
		t.Fatal("TCP ACK was denied")
	}
	if e.allowRelayTracked(second, now.Add(3*time.Second)) {
		t.Fatal("second TCP flow exceeded the per-peer conntrack limit")
	}
	if !e.allowRelayTracked(rst, now.Add(4*time.Second)) {
		t.Fatal("tracked TCP RST was denied")
	}
	if !e.allowRelayTracked(second, now.Add(5*time.Second)) {
		t.Fatal("per-peer counter was not released after TCP RST")
	}
}

func TestRelayICMPErrorIPv6Types(t *testing.T) {
	for _, typ := range []byte{1, 2, 3, 4} {
		if !relayICMPError(58, typ) {
			t.Fatalf("IPv6 ICMP type %d should be treated as an error", typ)
		}
	}
	for _, typ := range []byte{0, 5, 127, 128, 129} {
		if relayICMPError(58, typ) {
			t.Fatalf("IPv6 ICMP type %d should not be treated as an error", typ)
		}
	}
}
