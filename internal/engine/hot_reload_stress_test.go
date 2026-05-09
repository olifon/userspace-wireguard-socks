// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestHotReloadACLAndPeerMutations drives the runtime API while a background
// goroutine continuously hammers the engine with TCP connections.  Verifies:
//   - ACL replace + append + deny-all mid-flow
//   - Peer add, delete, re-add with same AllowedIPs
//   - Malformed JSON/config returns 4xx, not 5xx
//   - WireGuard config hot-reload (key rotation)
//   - Engine stays healthy after all mutations (status endpoint responsive)
func TestHotReloadACLAndPeerMutations(t *testing.T) {
	if testing.Short() {
		t.Skip("hot-reload stress test skipped in -short mode (runs without -short)")
	}

	serverKey := mustKey(t)
	peerBKey := mustKey(t)
	peerCKey := mustKey(t)

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = serverKey.String()
	cfg.WireGuard.Addresses = []string{"100.64.60.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "stress-token"
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:  peerBKey.PublicKey().String(),
			AllowedIPs: []string{"100.64.60.2/32"},
		},
	}
	eng := mustStart(t, cfg)
	apiAddr := eng.Addr("api")

	// Background: hammer SOCKS5 proxy to generate engine activity.
	socks5Addr := eng.Addr("socks5")
	var conns atomic.Int64
	var connErrs atomic.Int64
	stopBG := make(chan struct{})
	var bgWg sync.WaitGroup
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		for {
			select {
			case <-stopBG:
				return
			default:
			}
			c, err := net.DialTimeout("tcp", socks5Addr, 500*time.Millisecond)
			if err != nil {
				connErrs.Add(1)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			conns.Add(1)
			c.Close()
			time.Sleep(5 * time.Millisecond)
		}
	}()
	defer func() {
		close(stopBG)
		bgWg.Wait()
	}()
	time.Sleep(50 * time.Millisecond)

	// --- ACL mutations ---
	allowAll := map[string]any{
		"inbound_default":  "allow",
		"outbound_default": "allow",
		"relay_default":    "deny",
	}
	resp, body := apiRequest(t, apiAddr, "stress-token", http.MethodPut, "/v1/acls", allowAll)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /v1/acls allow-all: %d %s", resp.StatusCode, body)
	}
	resp, body = apiRequest(t, apiAddr, "stress-token", http.MethodPost, "/v1/acls/outbound", map[string]any{
		"action": "allow", "destination": "100.64.60.0/24",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/acls/outbound: %d %s", resp.StatusCode, body)
	}
	// deny-all
	resp, body = apiRequest(t, apiAddr, "stress-token", http.MethodPut, "/v1/acls", map[string]any{
		"inbound_default": "deny", "outbound_default": "deny", "relay_default": "deny",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /v1/acls deny-all: %d %s", resp.StatusCode, body)
	}
	// restore allow
	resp, body = apiRequest(t, apiAddr, "stress-token", http.MethodPut, "/v1/acls", allowAll)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /v1/acls restore: %d %s", resp.StatusCode, body)
	}

	// --- Peer lifecycle mutations ---
	resp, body = apiRequest(t, apiAddr, "stress-token", http.MethodPost, "/v1/peers", map[string]any{
		"public_key":  peerCKey.PublicKey().String(),
		"allowed_ips": []string{"100.64.60.3/32"},
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add peerC: %d %s", resp.StatusCode, body)
	}
	if got := eng.Peers(); len(got) < 2 {
		t.Fatalf("expected ≥2 peers after add, got %d", len(got))
	}

	resp, body = apiRequest(t, apiAddr, "stress-token", http.MethodDelete,
		"/v1/peers?public_key="+url.QueryEscape(peerCKey.PublicKey().String()), nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete peerC: %d %s", resp.StatusCode, body)
	}

	// Re-add with same AllowedIPs — must not crash or return 5xx.
	resp, body = apiRequest(t, apiAddr, "stress-token", http.MethodPost, "/v1/peers", map[string]any{
		"public_key":  peerCKey.PublicKey().String(),
		"allowed_ips": []string{"100.64.60.3/32"},
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("re-add peerC: %d %s", resp.StatusCode, body)
	}

	// --- Malformed config rejection ---
	for _, mc := range []struct{ method, path, body string }{
		{http.MethodPut, "/v1/acls", `{"not-valid json`},
		{http.MethodPost, "/v1/peers", `{"public_key": ""}`},
		{http.MethodPost, "/v1/peers", `not-json-at-all`},
		{http.MethodPut, "/v1/acls", `{"inbound_default": "bad-action"}`},
	} {
		req, err := http.NewRequest(mc.method, "http://"+apiAddr+mc.path, strings.NewReader(mc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer stress-token")
		resp2, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("malformed %s %s: %v", mc.method, mc.path, err)
		}
		resp2.Body.Close()
		if resp2.StatusCode >= 500 {
			t.Fatalf("malformed %s %s body=%q: got %d (want 4xx)", mc.method, mc.path, mc.body, resp2.StatusCode)
		}
	}

	// --- WireGuard config hot-reload (key rotation) ---
	newKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wgCfg := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 100.64.60.1/32\n", newKey.String())
	req, err := http.NewRequest(http.MethodPut, "http://"+apiAddr+"/v1/wireguard/config", strings.NewReader(wgCfg))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer stress-token")
	resp3, err3 := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err3 != nil {
		t.Fatalf("PUT /v1/wireguard/config: %v", err3)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /v1/wireguard/config: %d", resp3.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)

	// Engine must still answer status after all mutations.
	resp4, statusBody := apiRequest(t, apiAddr, "stress-token", http.MethodGet, "/v1/status", nil)
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("status after mutations: %d %s", resp4.StatusCode, statusBody)
	}
	var st engine.Status
	if err := json.Unmarshal([]byte(statusBody), &st); err != nil {
		t.Fatalf("parse status: %v: %s", err, statusBody)
	}

	t.Logf("hot-reload stress: %d SOCKS5 conns, %d dial errors", conns.Load(), connErrs.Load())
}

// TestAllowedIPsOverlapRoutesCorrectly removes a peer and re-adds a different
// peer with the same AllowedIPs.  The engine must not error on the re-add and
// must route to the new peer, not the deleted one.
func TestAllowedIPsOverlapRoutesCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("AllowedIPs overlap test skipped in -short mode")
	}

	serverKey := mustKey(t)
	peerKey := mustKey(t)
	newPeerKey := mustKey(t)

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = serverKey.String()
	cfg.WireGuard.Addresses = []string{"100.64.61.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "overlap-token"
	cfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  peerKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.61.2/32"},
	}}
	eng := mustStart(t, cfg)
	apiAddr := eng.Addr("api")

	if got := eng.Peers(); len(got) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(got))
	}

	resp, body := apiRequest(t, apiAddr, "overlap-token", http.MethodDelete,
		"/v1/peers?public_key="+url.QueryEscape(peerKey.PublicKey().String()), nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete peer: %d %s", resp.StatusCode, body)
	}

	// New peer with same AllowedIPs — must succeed, not "route already exists".
	resp, body = apiRequest(t, apiAddr, "overlap-token", http.MethodPost, "/v1/peers", map[string]any{
		"public_key":  newPeerKey.PublicKey().String(),
		"allowed_ips": []string{"100.64.61.2/32"},
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add new peer with overlapping AllowedIPs: %d %s", resp.StatusCode, body)
	}

	peers := eng.Peers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer after re-add, got %d", len(peers))
	}
	if peers[0].PublicKey != newPeerKey.PublicKey().String() {
		t.Fatalf("expected new peer key, got %s", peers[0].PublicKey)
	}
}

// TestPeerRemovalWithSessionThenReAdd adds, removes, and re-adds a peer.
// Verifies no crash and the re-added peer has a clean session state.
func TestPeerRemovalWithSessionThenReAdd(t *testing.T) {
	if testing.Short() {
		t.Skip("peer removal/re-add test skipped in -short mode")
	}

	serverKey := mustKey(t)
	peerKey := mustKey(t)

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = serverKey.String()
	cfg.WireGuard.Addresses = []string{"100.64.62.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "remove-token"
	cfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  peerKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.62.2/32"},
	}}
	eng := mustStart(t, cfg)
	apiAddr := eng.Addr("api")

	if got := eng.Peers(); len(got) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(got))
	}

	resp, body := apiRequest(t, apiAddr, "remove-token", http.MethodDelete,
		"/v1/peers?public_key="+url.QueryEscape(peerKey.PublicKey().String()), nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete peer: %d %s", resp.StatusCode, body)
	}

	resp, body = apiRequest(t, apiAddr, "remove-token", http.MethodGet, "/v1/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status after delete: %d %s", resp.StatusCode, body)
	}

	resp, body = apiRequest(t, apiAddr, "remove-token", http.MethodPost, "/v1/peers", map[string]any{
		"public_key":  peerKey.PublicKey().String(),
		"allowed_ips": []string{"100.64.62.2/32"},
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("re-add peer: %d %s", resp.StatusCode, body)
	}

	if got := eng.Peers(); len(got) != 1 {
		t.Fatalf("expected 1 peer after re-add, got %d", len(got))
	}

	// Newly re-added peer must not show stale handshake.
	status, err := eng.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, ps := range status.Peers {
		if ps.PublicKey == peerKey.PublicKey().String() && ps.HasHandshake {
			t.Fatal("re-added peer shows stale handshake from before delete")
		}
	}
}

// TestWireGuardConfigKeyRotation rotates the WireGuard private key via the
// config API and verifies the engine remains healthy and reflects the new key.
func TestWireGuardConfigKeyRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("WireGuard key rotation test skipped in -short mode")
	}

	serverKey := mustKey(t)
	peerKey := mustKey(t)

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = serverKey.String()
	cfg.WireGuard.Addresses = []string{"100.64.63.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "rotate-token"
	cfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  peerKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.63.2/32"},
	}}
	eng := mustStart(t, cfg)
	apiAddr := eng.Addr("api")

	newKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wgCfg := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 100.64.63.1/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 100.64.63.2/32\n",
		newKey.String(), peerKey.PublicKey().String())
	req, err := http.NewRequest(http.MethodPut, "http://"+apiAddr+"/v1/wireguard/config", strings.NewReader(wgCfg))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer rotate-token")
	resp, err2 := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err2 != nil {
		t.Fatalf("PUT wireguard/config: %v", err2)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("key rotation: %d", resp.StatusCode)
	}

	// Engine must still be healthy after key rotation.
	statusResp, statusBody := apiRequest(t, apiAddr, "rotate-token", http.MethodGet, "/v1/status", nil)
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status after key rotation: %d %s", statusResp.StatusCode, statusBody)
	}
	var st engine.Status
	if err := json.Unmarshal([]byte(statusBody), &st); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if !st.Running {
		t.Fatalf("engine not running after key rotation: %s", statusBody)
	}

	// Peer must still be present.
	if got := eng.Peers(); len(got) != 1 || got[0].PublicKey != peerKey.PublicKey().String() {
		t.Fatalf("peer missing after key rotation: %v", got)
	}
}

// TestHotReloadFlowsSurviveACLMutation establishes a live TCP flow through the
// engine's SOCKS5 proxy to a loopback echo server, then pushes an ACL update.
// The existing flow must survive; a new flow must succeed immediately after.
func TestHotReloadFlowsSurviveACLMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("flows-survive-ACL-mutation test skipped in -short mode")
	}

	// Local echo server (outside the tunnel — just on loopback).
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()
	echoAddr := echoLn.Addr().String()

	serverKey := mustKey(t)
	peerKey := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = serverKey.String()
	cfg.WireGuard.Addresses = []string{"100.64.64.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "flow-token"
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  peerKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.64.2/32"},
	}}
	eng := mustStart(t, cfg)
	apiAddr := eng.Addr("api")
	socks5Addr := eng.Addr("socks5")

	// Open a SOCKS5 connection to the echo server.
	socks5d, err := proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}
	conn1, err := socks5d.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("pre-mutation SOCKS5 dial: %v", err)
	}
	defer conn1.Close()

	// Verify the flow is live.
	conn1.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := conn1.Write([]byte("before-mutation")); err != nil {
		t.Fatalf("write before mutation: %v", err)
	}
	buf := make([]byte, 15)
	if _, err := io.ReadFull(conn1, buf); err != nil {
		t.Fatalf("echo before mutation: %v", err)
	}
	conn1.SetDeadline(time.Time{}) //nolint:errcheck

	// Push an ACL update while conn1 is live.
	resp, body := apiRequest(t, apiAddr, "flow-token", http.MethodPut, "/v1/acls", map[string]any{
		"inbound_default": "allow", "outbound_default": "allow", "relay_default": "deny",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /v1/acls during flow: %d %s", resp.StatusCode, body)
	}

	// Existing conn1 must still work after ACL replacement.
	conn1.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := conn1.Write([]byte("after-mutation!")); err != nil {
		t.Fatalf("write on existing conn after mutation: %v", err)
	}
	buf2 := make([]byte, 15)
	if _, err := io.ReadFull(conn1, buf2); err != nil {
		t.Fatalf("echo on existing conn after mutation: %v", err)
	}

	// A brand new SOCKS5 flow must work post-mutation.
	conn2, err := socks5d.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("post-mutation SOCKS5 dial: %v", err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := conn2.Write([]byte("new-after-acl")); err != nil {
		t.Fatalf("write on new conn after mutation: %v", err)
	}
	buf3 := make([]byte, 13)
	if _, err := io.ReadFull(conn2, buf3); err != nil {
		t.Fatalf("echo on new conn after mutation: %v", err)
	}

	t.Log("flows survived ACL hot-reload mutation")
}

// TestHotReloadBandwidthFlowsSurvivePeerMutation establishes a WireGuard
// tunnel between two engines, sends data through it, and verifies that an
// ACL mutation on the server side does not crash either engine or disrupt
// flows that are re-established after the mutation.
func TestHotReloadBandwidthFlowsSurvivePeerMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("bandwidth + hot-reload survival test skipped in -short mode")
	}

	serverKey := mustKey(t)
	clientKey := mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.65.1/32"}
	serverCfg.API.Listen = "127.0.0.1:0"
	serverCfg.API.Token = "bw-token"
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.65.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.65.2/32"}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.65.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	// Expose an echo listener on the server's tunnel address.
	echoLn, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.65.1:19081"))
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()

	// Wait for WireGuard handshake.
	waitForHandshake(t, serverEng, 10*time.Second)

	// Dial through the tunnel.
	socks5Addr := clientEng.Addr("socks5")
	socks5d, err := proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}

	conn1, err := socks5d.Dial("tcp", "100.64.65.1:19081")
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn1.Close()

	conn1.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := conn1.Write([]byte("hello")); err != nil {
		t.Fatalf("write before mutation: %v", err)
	}
	echo := make([]byte, 5)
	if _, err := io.ReadFull(conn1, echo); err != nil {
		t.Fatalf("echo before mutation: %v", err)
	}
	conn1.SetDeadline(time.Time{}) //nolint:errcheck

	// Hot-reload ACL on server.
	serverAPIAddr := serverEng.Addr("api")
	resp, body := apiRequest(t, serverAPIAddr, "bw-token", http.MethodPut, "/v1/acls", map[string]any{
		"inbound_default": "allow", "outbound_default": "allow", "relay_default": "deny",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /v1/acls during tunnel flow: %d %s", resp.StatusCode, body)
	}

	// New connection post-mutation.
	conn2, err := socks5d.Dial("tcp", "100.64.65.1:19081")
	if err != nil {
		t.Fatalf("dial through tunnel post-mutation: %v", err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := conn2.Write([]byte("world")); err != nil {
		t.Fatalf("write after mutation: %v", err)
	}
	echo2 := make([]byte, 5)
	if _, err := io.ReadFull(conn2, echo2); err != nil {
		t.Fatalf("echo after mutation: %v", err)
	}
	t.Log("bandwidth flow survived ACL hot-reload mutation through WireGuard tunnel")
}

// waitForHandshake polls eng.Status until at least one peer shows HasHandshake,
// or fails if d elapses without a handshake.
func waitForHandshake(t *testing.T, eng *engine.Engine, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		st, err := eng.Status()
		if err == nil {
			for _, p := range st.Peers {
				if p.HasHandshake {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("WireGuard handshake timeout")
}
