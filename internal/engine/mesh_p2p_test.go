// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"encoding/base64"
	"math"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshKeepaliveIPAllocation verifies allocKeepaliveIPLocked:
//   - deterministic candidate derived from key bytes
//   - collision falls back to a different address
//   - both results are within the configured subnet
func TestMeshKeepaliveIPAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("keepalive IP allocation unit test skipped in -short mode")
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustMeshKey(t).String()
	cfg.WireGuard.Addresses = []string{"10.99.0.1/32"}
	cfg.MeshControl.KeepaliveSubnet = "250.0.0.0/8"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	key1 := mustMeshKey(t)
	key2 := mustMeshKey(t)

	eng.dynamicMu.Lock()

	ip1 := eng.allocKeepaliveIPLocked(key1.PublicKey().String())
	if !ip1.IsValid() {
		t.Fatal("expected valid IP for first peer, got zero")
	}
	if !eng.keepaliveSubnet.Contains(ip1) {
		t.Fatalf("allocated IP %s is outside keepalive subnet %s", ip1, eng.keepaliveSubnet)
	}

	// Occupy ip1 so key2 gets something else.
	eng.dynamicPeers[key1.PublicKey().String()] = &dynamicPeer{KeepaliveIP: ip1}
	ip2 := eng.allocKeepaliveIPLocked(key2.PublicKey().String())
	if !ip2.IsValid() {
		t.Fatal("expected valid IP for second peer, got zero")
	}
	if ip2 == ip1 {
		t.Fatalf("second peer got same IP as first: %s", ip2)
	}
	if !eng.keepaliveSubnet.Contains(ip2) {
		t.Fatalf("allocated IP %s is outside keepalive subnet %s", ip2, eng.keepaliveSubnet)
	}

	eng.dynamicMu.Unlock()
}

// TestMeshKeepaliveIPExhaustion verifies that allocation with an exhausted
// subnet returns a zero Addr rather than panicking or returning an
// out-of-subnet address.
func TestMeshKeepaliveIPExhaustion(t *testing.T) {
	if testing.Short() {
		t.Skip("keepalive IP exhaustion test skipped in -short mode")
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustMeshKey(t).String()
	cfg.WireGuard.Addresses = []string{"10.99.1.1/32"}
	// /30: network=.0, src=.1, only .2 is usable, .3=broadcast
	cfg.MeshControl.KeepaliveSubnet = "250.0.0.0/30"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// /30 has 4 addresses: .0 (net), .1 (src), .2 and .3 usable.
	// Occupy both .2 and .3 to exhaust all allocatable addresses.
	eng.dynamicMu.Lock()
	k1 := mustMeshKey(t)
	k2 := mustMeshKey(t)
	eng.dynamicPeers[k1.PublicKey().String()] = &dynamicPeer{
		KeepaliveIP: netip.MustParseAddr("250.0.0.2"),
	}
	eng.dynamicPeers[k2.PublicKey().String()] = &dynamicPeer{
		KeepaliveIP: netip.MustParseAddr("250.0.0.3"),
	}
	key := mustMeshKey(t)
	result := eng.allocKeepaliveIPLocked(key.PublicKey().String())
	eng.dynamicMu.Unlock()

	if result.IsValid() {
		t.Fatalf("expected zero addr on exhaustion, got %s", result)
	}
}

// TestMeshKeepaliveIPDeterministic verifies that the same key bytes always
// produce the same keepalive IP candidate and that it's within the subnet.
func TestMeshKeepaliveIPDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("keepalive IP determinism test skipped in -short mode")
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustMeshKey(t).String()
	cfg.WireGuard.Addresses = []string{"10.99.3.1/32"}
	cfg.MeshControl.KeepaliveSubnet = "250.0.0.0/8"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	key := mustMeshKey(t)
	keyBytes, err := base64.StdEncoding.DecodeString(key.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}

	ip1 := eng.keepaliveIPFromKeyBytes(keyBytes)
	ip2 := eng.keepaliveIPFromKeyBytes(keyBytes)
	if ip1 != ip2 {
		t.Fatalf("keepaliveIPFromKeyBytes not deterministic: %s != %s", ip1, ip2)
	}
	if ip1.IsValid() && !eng.keepaliveSubnet.Contains(ip1) {
		t.Fatalf("derived IP %s outside subnet %s", ip1, eng.keepaliveSubnet)
	}
}

// TestMeshP2PDeclareAndReflect verifies the POST /v1/p2p → /v1/peers flow:
// client A declares "active"; hub stores it; client B sees A with type="p2p".
func TestMeshP2PDeclareAndReflect(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh P2P declare+reflect integration test skipped in -short mode")
	}
	serverKey := mustMeshKey(t)
	aKey := mustMeshKey(t)
	bKey := mustMeshKey(t)
	serverPort := freeUDPPortTest(t)
	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.12.1:8787"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.12.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{PublicKey: aKey.PublicKey().String(), PresharedKey: pskA, AllowedIPs: []string{"100.64.12.2/32"}, MeshEnabled: true, MeshAcceptACLs: true},
		{PublicKey: bKey.PublicKey().String(), PresharedKey: pskB, AllowedIPs: []string{"100.64.12.3/32"}, MeshEnabled: true, MeshAcceptACLs: true},
	}
	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	makeCfg := func(key, addr, psk, p2pMode string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key
		cfg.WireGuard.Addresses = []string{addr}
		cfg.MeshControl.P2PMode = p2pMode
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
			AllowedIPs:          []string{"100.64.12.1/32", "100.64.12.0/24"},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.12.1:8787",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	clientA := mustStartMeshEngine(t, makeCfg(aKey.String(), "100.64.12.2/32", pskA, "active"))
	defer clientA.Close()
	clientB := mustStartMeshEngine(t, makeCfg(bKey.String(), "100.64.12.3/32", pskB, ""))
	defer clientB.Close()

	waitPeerHandshakeTest(t, server, aKey.PublicKey().String())
	waitPeerHandshakeTest(t, server, bKey.PublicKey().String())
	waitPeerHandshakeTest(t, clientA, serverKey.PublicKey().String())
	waitPeerHandshakeTest(t, clientB, serverKey.PublicKey().String())

	// A posts its P2P mode; B fetches peers and should see A as type="p2p".
	clientA.runMeshPolling()

	deadline := time.Now().Add(5 * time.Second * testDeadlineScale)
	var gotDecl string
	for time.Now().Before(deadline) {
		server.meshP2PMu.RLock()
		gotDecl = server.meshP2PDecls[aKey.PublicKey().String()]
		server.meshP2PMu.RUnlock()
		if gotDecl == "active" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if gotDecl != "active" {
		t.Fatalf("hub did not store A's p2p declaration; got %q", gotDecl)
	}

	// B polls and should get A with type="p2p".
	clientB.runMeshPolling()

	deadline = time.Now().Add(5 * time.Second * testDeadlineScale)
	var gotType string
	for time.Now().Before(deadline) {
		clientB.dynamicMu.RLock()
		dp := clientB.dynamicPeers[aKey.PublicKey().String()]
		if dp != nil {
			gotType = dp.PeerType
		}
		clientB.dynamicMu.RUnlock()
		if gotType == "p2p" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if gotType != "p2p" {
		t.Fatalf("B's dynamic peer type for A = %q, want %q", gotType, "p2p")
	}
}

// TestMeshP2PDisableFilter verifies that a peer declaring "disable" receives
// only "remote" peers in its /v1/peers response — not "p2p" or "client" peers.
func TestMeshP2PDisableFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh P2P disable filter integration test skipped in -short mode")
	}
	serverKey := mustMeshKey(t)
	aKey := mustMeshKey(t) // active → type p2p
	bKey := mustMeshKey(t) // remote
	cKey := mustMeshKey(t) // disable — should only see B
	serverPort := freeUDPPortTest(t)
	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()
	pskC := mustMeshKey(t).String()

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.13.1:8787"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.13.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{PublicKey: aKey.PublicKey().String(), PresharedKey: pskA, AllowedIPs: []string{"100.64.13.2/32"}, MeshEnabled: true, MeshAcceptACLs: true},
		{PublicKey: bKey.PublicKey().String(), PresharedKey: pskB, AllowedIPs: []string{"100.64.13.3/32"}, MeshEnabled: true, MeshAcceptACLs: true},
		{PublicKey: cKey.PublicKey().String(), PresharedKey: pskC, AllowedIPs: []string{"100.64.13.4/32"}, MeshEnabled: true, MeshAcceptACLs: true},
	}
	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	makeCfg := func(key, addr, psk, p2pMode string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key
		cfg.WireGuard.Addresses = []string{addr}
		cfg.MeshControl.P2PMode = p2pMode
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
			AllowedIPs:          []string{"100.64.13.1/32", "100.64.13.0/24"},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.13.1:8787",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	clientA := mustStartMeshEngine(t, makeCfg(aKey.String(), "100.64.13.2/32", pskA, "active"))
	defer clientA.Close()
	clientB := mustStartMeshEngine(t, makeCfg(bKey.String(), "100.64.13.3/32", pskB, "remote"))
	defer clientB.Close()
	clientC := mustStartMeshEngine(t, makeCfg(cKey.String(), "100.64.13.4/32", pskC, "disable"))
	defer clientC.Close()

	waitPeerHandshakeTest(t, server, aKey.PublicKey().String())
	waitPeerHandshakeTest(t, server, bKey.PublicKey().String())
	waitPeerHandshakeTest(t, server, cKey.PublicKey().String())
	waitPeerHandshakeTest(t, clientA, serverKey.PublicKey().String())
	waitPeerHandshakeTest(t, clientB, serverKey.PublicKey().String())
	waitPeerHandshakeTest(t, clientC, serverKey.PublicKey().String())

	// Have A, B declare their modes to the hub.
	clientA.runMeshPolling()
	clientB.runMeshPolling()

	// Wait for hub to register A and B declarations.
	deadline := time.Now().Add(5 * time.Second * testDeadlineScale)
	for time.Now().Before(deadline) {
		server.meshP2PMu.RLock()
		aDecl := server.meshP2PDecls[aKey.PublicKey().String()]
		bDecl := server.meshP2PDecls[bKey.PublicKey().String()]
		server.meshP2PMu.RUnlock()
		if aDecl == "active" && bDecl == "remote" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	server.meshP2PMu.RLock()
	aDecl := server.meshP2PDecls[aKey.PublicKey().String()]
	bDecl := server.meshP2PDecls[bKey.PublicKey().String()]
	server.meshP2PMu.RUnlock()
	if aDecl != "active" || bDecl != "remote" {
		t.Fatalf("hub declarations: A=%q B=%q (want active/remote)", aDecl, bDecl)
	}

	// C polls — as a "disable" peer it should only see B (remote), not A.
	clientC.runMeshPolling()

	deadline = time.Now().Add(5 * time.Second * testDeadlineScale)
	for time.Now().Before(deadline) {
		clientC.dynamicMu.RLock()
		n := len(clientC.dynamicPeers)
		clientC.dynamicMu.RUnlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	clientC.dynamicMu.RLock()
	_, hasA := clientC.dynamicPeers[aKey.PublicKey().String()]
	dpB := clientC.dynamicPeers[bKey.PublicKey().String()]
	clientC.dynamicMu.RUnlock()

	if hasA {
		t.Fatal("C (disable) received peer A (active) — should be filtered out")
	}
	if dpB == nil {
		t.Fatal("C (disable) should receive peer B (remote) but did not")
	}
	if dpB.PeerType != "remote" {
		t.Fatalf("B's type as seen by C = %q, want remote", dpB.PeerType)
	}
}

// TestMeshStateGracePeriodReject verifies that an active dynamic peer whose
// grace window expires without confirmed RX growth goes inactive. We use
// GraceRxSnap=MaxUint64 (impossible for real ReceiveBytes to exceed) to
// guarantee the grace check always fails.
//
// Since the injected peer has no real WireGuard session (no handshake),
// refreshDynamicPeerActivity sees !HasHandshake and takes the same inactive
// path as the grace check. The observable invariant is identical: an Active=true
// peer without WireGuard liveness goes inactive on the next refresh.
func TestMeshStateGracePeriodReject(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh grace period reject test skipped in -short mode")
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustMeshKey(t).String()
	cfg.WireGuard.Addresses = []string{"10.99.2.1/32"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	peerKey := mustMeshKey(t)
	keyB64 := peerKey.PublicKey().String()

	// Inject an active dynamic peer with an impossible grace condition.
	// ActiveSince is backdated past dynPeerGraceWindow (5s).
	eng.dynamicMu.Lock()
	eng.dynamicPeers[keyB64] = &dynamicPeer{
		Peer: config.Peer{
			PublicKey:  keyB64,
			AllowedIPs: []string{"10.99.2.2/32"},
		},
		Active:      true,
		ActiveSince: time.Now().Add(-10 * time.Second),
		GraceRxSnap: math.MaxUint64, // ReceiveBytes can never exceed this
		LastControl: time.Now(),
	}
	eng.dynamicMu.Unlock()

	eng.refreshDynamicPeerActivity()

	eng.dynamicMu.RLock()
	dp := eng.dynamicPeers[keyB64]
	eng.dynamicMu.RUnlock()

	if dp == nil {
		t.Fatal("dynamic peer was deleted; should be marked inactive instead")
	}
	if dp.Active {
		t.Fatal("peer should be inactive after liveness check failed")
	}
}
