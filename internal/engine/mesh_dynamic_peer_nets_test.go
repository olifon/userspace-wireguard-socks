// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestDynamicPeerDestinationFilter verifies that allowTunnelPacket enforces
// the destination-IP filter for dynamically discovered (P2P) peers.
//
// The security invariant: a dynamic peer may only send packets whose
// destination is within the IP ranges the mesh control server allocated to
// this node (fetched via /v1/nets). This prevents a malicious-but-
// legitimately-provisioned peer from injecting packets to arbitrary
// destinations via the direct P2P path.
//
// Guarantees exercised:
//  1. Packets from a dynamic peer to an allocated destination → ALLOW
//  2. Packets from a dynamic peer to a non-allocated destination → DENY
//  3. Packets from a dynamic peer before the parent is ready → DENY (deny-until-ready)
//  4. Packets from a static peer → not subject to the filter (ALLOW regardless)
//  5. Dynamic peer with broader allocation subnet: destination inside → ALLOW, outside → DENY
//
// This is a unit test: it constructs an Engine via New() without starting
// WireGuard, then manually injects dynamic peer state and the self-prefix
// allocation to test the filter logic directly. Safe for -short mode.
func TestDynamicPeerDestinationFilter(t *testing.T) {
	const (
		selfAddr  = "10.100.1.1"
		selfCIDR  = "10.100.1.1/32"
		dynIP     = "10.100.2.1"
		dynCIDR   = "10.100.2.1/32"
		staticIP  = "10.100.3.1"
		staticCIDR = "10.100.3.1/32"
		outsideIP = "192.168.99.1"
		parentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		dynKey    = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
		staticKey = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	)

	privKey := mustMeshKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = privKey.String()
	cfg.WireGuard.Addresses = []string{selfCIDR}
	cfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:  staticKey,
			AllowedIPs: []string{staticCIDR},
		},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	eng, err := New(cfg, DiscardLogger())
	if err != nil {
		t.Fatal(err)
	}

	// localAddrs is normally populated by Start(); set it directly for the unit test.
	eng.localAddrs = []netip.Addr{netip.MustParseAddr(selfAddr)}

	// Inject the dynamic peer into the engine state.
	eng.dynamicMu.Lock()
	eng.dynamicPeers[dynKey] = &dynamicPeer{
		Peer: config.Peer{
			PublicKey:  dynKey,
			AllowedIPs: []string{dynCIDR},
		},
		ParentPublicKey: parentKey,
	}
	eng.dynamicMu.Unlock()

	// Add the dynamic peer's prefix to the routing table (normally done by
	// applyMeshDiscoveredPeers → wgApplyPeer which builds peerRoutes).
	eng.allowedMu.Lock()
	eng.peerRoutes = append(eng.peerRoutes, peerRoute{
		prefix:    netip.MustParsePrefix(dynCIDR),
		publicKey: dynKey,
	})
	eng.allowedMu.Unlock()

	makePacket := func(src, dst string) []byte {
		return buildMinimalIPv4TCPPacket(
			netip.MustParseAddr(src),
			netip.MustParseAddr(dst),
		)
	}

	// ── Case 1: parent not ready yet ─────────────────────────────────────
	// Dynamic peer sends to our self address. Should be denied because the
	// mesh control server has not yet completed a full poll cycle for this parent.
	if eng.allowTunnelPacket(makePacket(dynIP, selfAddr)) {
		t.Error("case 1 FAIL: expected DENY from dynamic peer before parent is ready")
	}

	// ── Case 2: mark parent ready with self-prefixes ──────────────────────
	eng.meshACLMu.Lock()
	eng.meshSelfPrefixesByParent[parentKey] = []netip.Prefix{netip.MustParsePrefix(selfCIDR)}
	eng.meshParentReady[parentKey] = true
	eng.meshACLMu.Unlock()

	// Dynamic peer sending to our allocated address → ALLOW.
	if !eng.allowTunnelPacket(makePacket(dynIP, selfAddr)) {
		t.Error("case 2 FAIL: expected ALLOW from dynamic peer to allocated destination")
	}

	// ── Case 3: dynamic peer to non-allocated destination ─────────────────
	if eng.allowTunnelPacket(makePacket(dynIP, outsideIP)) {
		t.Error("case 3 FAIL: expected DENY from dynamic peer to destination outside allocation")
	}

	// ── Case 4: static peer not subject to filter ─────────────────────────
	// Static peer sends to outside IP — no self-prefix filter applies.
	if !eng.allowTunnelPacket(makePacket(staticIP, outsideIP)) {
		t.Error("case 4 FAIL: expected ALLOW for static peer (not subject to destination filter)")
	}

	// ── Case 5: broader allocation subnet ────────────────────────────────
	// Simulate a /24 allocation: any dst in 10.100.1.0/24 is allowed.
	eng.meshACLMu.Lock()
	eng.meshSelfPrefixesByParent[parentKey] = []netip.Prefix{netip.MustParsePrefix("10.100.1.0/24")}
	eng.meshACLMu.Unlock()

	if !eng.allowTunnelPacket(makePacket(dynIP, "10.100.1.50")) {
		t.Error("case 5a FAIL: expected ALLOW to address inside /24 allocation")
	}
	if eng.allowTunnelPacket(makePacket(dynIP, "10.100.2.50")) {
		t.Error("case 5b FAIL: expected DENY to address outside /24 allocation")
	}
}

// TestMeshNetsServerResponse verifies that the server-side meshNetsForRequester
// returns the AllowedIPs the server has configured for the requester, and that
// applyMeshSelfPrefixes stores them correctly for the destination filter.
func TestMeshNetsServerResponse(t *testing.T) {
	serverKey := mustMeshKey(t)
	clientKey := mustMeshKey(t)
	serverPort := freeUDPPortTest(t)

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.97.1:8797"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.97.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:      clientKey.PublicKey().String(),
		PresharedKey:   mustMeshKey(t).String(),
		AllowedIPs:     []string{"100.64.97.2/32", "100.64.97.128/25"},
		MeshEnabled:    true,
		MeshAcceptACLs: true,
	}}
	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	// meshNetsForRequester: returns the allocated prefixes for the requesting peer.
	resp, err := server.meshNetsForRequester(clientKey.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Prefixes) != 2 {
		t.Fatalf("meshNetsForRequester: got %d prefixes, want 2: %v", len(resp.Prefixes), resp.Prefixes)
	}

	// applyMeshSelfPrefixes: parses and stores the prefixes.
	if err := server.applyMeshSelfPrefixes("testparent", resp.Prefixes); err != nil {
		t.Fatal(err)
	}
	server.meshACLMu.Lock()
	stored := server.meshSelfPrefixesByParent["testparent"]
	server.meshACLMu.Unlock()
	if len(stored) != 2 {
		t.Fatalf("applyMeshSelfPrefixes: got %d stored prefixes, want 2: %v", len(stored), stored)
	}
	// Order-independent checks: each expected address must appear in some prefix.
	mustContainAddr := func(addr string) {
		t.Helper()
		ip := netip.MustParseAddr(addr)
		for _, p := range stored {
			if p.Contains(ip) {
				return
			}
		}
		t.Errorf("stored prefixes %v do not contain %s", stored, addr)
	}
	mustContainAddr("100.64.97.2")    // from /32
	mustContainAddr("100.64.97.200")  // from /25
	// Non-allocated addresses must not match any prefix.
	for _, addr := range []string{"100.64.97.3", "10.0.0.1"} {
		ip := netip.MustParseAddr(addr)
		for _, p := range stored {
			if p.Contains(ip) {
				t.Errorf("prefix %s should not contain unrelated address %s", p, addr)
			}
		}
	}

	// meshNetsForRequester: unknown peer returns error.
	if _, err := server.meshNetsForRequester("UNKNOWNUNKNOWNUNKNOWNUNKNOWNUNKNOWNUNKNOWNUNKNOWN=="); err == nil {
		t.Error("expected error for unknown peer, got nil")
	}
}

// buildMinimalIPv4TCPPacket constructs a minimal 40-byte IPv4/TCP packet
// (20-byte IP header + 20-byte TCP header, no payload) for use in filter tests.
func buildMinimalIPv4TCPPacket(src, dst netip.Addr) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], 40) // total length
	pkt[8] = 64 // TTL
	pkt[9] = 6  // protocol: TCP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	// TCP: src=1234, dst=80, data offset=5
	binary.BigEndian.PutUint16(pkt[20:22], 1234)
	binary.BigEndian.PutUint16(pkt[22:24], 80)
	pkt[32] = 0x50 // data offset = 5 (20 bytes), no flags
	return pkt
}
