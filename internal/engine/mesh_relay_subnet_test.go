// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"strconv"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshRelayFailover_SubnetHubAllowedIPs pins the fix in
// reconcileDynamicPeerPriority: when the client's hub peer carries a subnet
// prefix (/24) rather than an explicit /32 per dynamic peer, an inactive
// dynamic peer's /32 must be reclaimed by the hub in wireguard-go's
// AllowedIPs trie so packets route to the relay hub rather than the dead
// direct endpoint.
//
// Before the fix, the dynamic peer's /32 stayed in the trie after going
// inactive, winning the longest-prefix-match over the hub's /24 and sending
// traffic to the unreachable direct endpoint instead of the relay.
//
// Topology:
//
//	      ┌──────────────┐
//	      │     hub      │ relay enabled, RelayDefault=Allow
//	      └──────┬───────┘
//	    ┌────────┴────────┐
//	  ┌─┴─┐              ┌─┴─┐
//	  │ A │              │ B │
//	  └───┘              └───┘
//
// Both A and B use hub with AllowedIPs=100.64.100.0/24 (no per-peer /32).
// The test forces B inactive on A and verifies A→B still transfers via hub.
func TestMeshRelayFailover_SubnetHubAllowedIPs(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh relay subnet test skipped in -short mode")
	}

	hubKey := mustMeshKey(t)
	keyA := mustMeshKey(t)
	keyB := mustMeshKey(t)
	hubPort := freeUDPPortTest(t)
	portA := freeUDPPortTest(t)
	portB := freeUDPPortTest(t)
	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()

	hubCfg := config.Default()
	hubCfg.WireGuard.PrivateKey = hubKey.String()
	hubCfg.WireGuard.ListenPort = &hubPort
	hubCfg.WireGuard.Addresses = []string{"100.64.100.1/32"}
	hubCfg.MeshControl.Listen = "100.64.100.1:8803"
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = acl.Allow
	hubCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      keyA.PublicKey().String(),
			PresharedKey:   pskA,
			AllowedIPs:     []string{"100.64.100.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      keyB.PublicKey().String(),
			PresharedKey:   pskB,
			AllowedIPs:     []string{"100.64.100.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	hub := mustStartMeshEngine(t, hubCfg)
	defer hub.Close()

	hubAddr := "127.0.0.1:" + strconv.Itoa(hubPort)
	clientCfg := func(priv, addr string, listenPort int, psk string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.ListenPort = &listenPort
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            hubAddr,
			AllowedIPs:          []string{"100.64.100.0/24"}, // subnet — no explicit /32s per peer
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.100.1:8803",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	engA := mustStartMeshEngine(t, clientCfg(keyA.String(), "100.64.100.2/32", portA, pskA))
	defer engA.Close()
	engB := mustStartMeshEngine(t, clientCfg(keyB.String(), "100.64.100.3/32", portB, pskB))
	defer engB.Close()

	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())

	engA.runMeshPolling()
	engB.runMeshPolling()
	waitDynamicPeerStatus(t, engA, keyB.PublicKey().String())
	waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

	const blobBytes = 256 * 1024
	stopFn := startBlobServerOn(t, engB, "100.64.100.3:18082", 10, 0, blobBytes)
	defer stopFn()

	// Force B inactive on A (and A inactive on B). reconcileDynamicPeerPriority
	// must reclaim B's /32 under hub's push so the trie routes to hub.
	forceMeshDynamicInactive(t, engA, keyB.PublicKey().String())
	forceMeshDynamicInactive(t, engB, keyA.PublicKey().String())

	if err := fetchBlobAndVerify(engA, "100.64.100.3:18082", 10, 0, blobBytes); err != nil {
		t.Fatalf("relay transfer A→B failed with /24 hub AllowedIPs after B inactive: %v", err)
	}

	// Re-activate and verify the trie correctly hands /32 back to B.
	forceMeshDynamicActive(t, engA, keyB.PublicKey().String())
	forceMeshDynamicActive(t, engB, keyA.PublicKey().String())

	if err := fetchBlobAndVerify(engA, "100.64.100.3:18082", 10, 0, blobBytes); err != nil {
		t.Fatalf("transfer A→B failed after re-activating B: %v", err)
	}
}
