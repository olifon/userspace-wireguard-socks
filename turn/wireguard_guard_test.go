package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
)

func makeHandshakeInitiation(t *testing.T, guard *WireguardGuard, sender uint32) []byte {
	t.Helper()
	packet := make([]byte, HandshakeInitiationSize)
	packet[0] = PacketHandshakeInitiation
	binary.LittleEndian.PutUint32(packet[4:8], sender)

	h128, err := blake2s.New128(guard.Mac1Key[:])
	if err != nil {
		t.Fatalf("blake2s mac1: %v", err)
	}
	h128.Write(packet[:116])
	copy(packet[116:132], h128.Sum(nil))
	return packet
}

func addValidMac2(t *testing.T, guard *WireguardGuard, packet []byte, ip net.IP) {
	t.Helper()
	cookie := guard.getCookie(ip)
	h128, err := blake2s.New128(cookie[:])
	if err != nil {
		t.Fatalf("blake2s mac2: %v", err)
	}
	h128.Write(packet[:132])
	copy(packet[132:148], h128.Sum(nil))
}

func setHandshakeRateEntry(guard *WireguardGuard, ip string, last time.Time, verified bool) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	for i := range guard.HandshakeRate {
		if guard.HandshakeRate[i].IP == "" || guard.HandshakeRate[i].IP == ip {
			guard.HandshakeRate[i] = handshakeRateEntry{
				IP:             ip,
				LastPostCookie: last,
				Verified:       verified,
			}
			return
		}
	}
}

func TestWireguardGuard_Fuzz(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	// 1. Random UDP packets (not Wireguard) -> rejected
	allowed, _ := guard.ProcessInbound([]byte{0, 0, 0, 0, 5}, remoteAddr, relayPort)
	if allowed {
		t.Error("Random UDP packet should be rejected")
	}

	// 2. Invalid mac1 in Handshake Initiation -> rejected
	initiation := make([]byte, HandshakeInitiationSize)
	initiation[0] = PacketHandshakeInitiation
	allowed, _ = guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if allowed {
		t.Error("Handshake Initiation with invalid mac1 should be rejected")
	}

	// 3. Handshake response / Cookie reply / Data with unknown receiver ID -> rejected
	data := make([]byte, MinDataPacketSize)
	data[0] = PacketData
	binary.LittleEndian.PutUint32(data[4:8], 9999) // Unknown receiver ID
	allowed, _ = guard.ProcessInbound(data, remoteAddr, relayPort)
	if allowed {
		t.Error("Packet with unknown receiver ID should be rejected")
	}
}

func TestWireguardGuard_HandshakeAndCookies(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	initiation := makeHandshakeInitiation(t, guard, 123)

	// Inbound Handshake Initiation -> allowed
	allowed, modified := guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if !allowed {
		t.Fatal("Valid Handshake Initiation should be allowed")
	}
	if modified == nil {
		t.Fatal("Handshake Initiation should be modified (cleared mac2)")
	}

	// Simulate Wireguard Server (Outbound Handshake Response)
	response := make([]byte, HandshakeResponseSize)
	response[0] = PacketHandshakeResponse
	binary.LittleEndian.PutUint32(response[4:8], 456)  // sender index (server)
	binary.LittleEndian.PutUint32(response[8:12], 123) // receiver index (client)

	if !guard.ProcessOutbound(response, remoteAddr, relayPort) {
		t.Fatal("Outbound Handshake Response should be allowed")
	}

	// Verify session is verified
	guard.mu.RLock()
	if len(guard.Sessions) != 1 || !guard.Sessions[0].Verified {
		t.Fatal("Session should be verified after server response")
	}
	guard.mu.RUnlock()

	// Data packet from client -> allowed
	data := make([]byte, MinDataPacketSize)
	data[0] = PacketData
	binary.LittleEndian.PutUint32(data[4:8], 456) // receiver ID = server's sender ID
	binary.LittleEndian.PutUint64(data[8:16], 1)  // counter

	allowed, _ = guard.ProcessInbound(data, remoteAddr, relayPort)
	if !allowed {
		t.Error("Data packet should be allowed")
	}
}

func TestWireguardGuard_DoSAndCookies(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	guard.DoSLevel = DoSLevelFull
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	// Initiation without mac2 in DoS mode -> should return Cookie Reply
	initiation := makeHandshakeInitiation(t, guard, 123)

	allowed, modified := guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if allowed {
		t.Error("Initiation without mac2 in DoS mode should be rejected")
	}
	if modified == nil || modified[0] != PacketCookieReply {
		t.Fatal("Should return Cookie Reply")
	}

	// Now send initiation with valid mac2 (from our cookie)
	addValidMac2(t, guard, initiation, net.ParseIP("1.2.3.4"))

	allowed, _ = guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if !allowed {
		t.Error("Initiation with valid mac2 should be allowed in DoS mode")
	}
}

func TestWireguardGuard_InvalidMac2MatchesMissingMac2(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	guard.DoSLevel = DoSLevelFull
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	missing := makeHandshakeInitiation(t, guard, 111)
	allowed, modified := guard.ProcessInbound(missing, remoteAddr, 3478)
	if allowed || modified == nil || modified[0] != PacketCookieReply {
		t.Fatal("missing mac2 should trigger a cookie reply in full DoS mode")
	}

	invalid := makeHandshakeInitiation(t, guard, 222)
	for i := 132; i < 148; i++ {
		invalid[i] = 0x42
	}
	allowed, modified = guard.ProcessInbound(invalid, remoteAddr, 3478)
	if allowed || modified == nil || modified[0] != PacketCookieReply {
		t.Fatal("invalid mac2 should be treated the same as missing mac2")
	}
}

func TestWireguardGuard_PostCookieHandshakeRateLimits(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	guard.DoSLevel = DoSLevelFull
	remoteIP := net.ParseIP("1.2.3.4")
	remoteAddr := &net.UDPAddr{IP: remoteIP, Port: 12345}
	relayPort := 3478

	first := makeHandshakeInitiation(t, guard, 100)
	addValidMac2(t, guard, first, remoteIP)
	if allowed, _ := guard.ProcessInbound(first, remoteAddr, relayPort); !allowed {
		t.Fatal("first post-cookie initiation should be forwarded")
	}

	second := makeHandshakeInitiation(t, guard, 101)
	addValidMac2(t, guard, second, remoteIP)
	if allowed, _ := guard.ProcessInbound(second, remoteAddr, relayPort); allowed {
		t.Fatal("second post-cookie initiation inside 500ms should be dropped")
	}

	setHandshakeRateEntry(guard, remoteIP.String(), time.Now().Add(-time.Second), false)
	guard.mu.Lock()
	guard.StricterHandshakeLimitAll = true
	guard.mu.Unlock()
	third := makeHandshakeInitiation(t, guard, 102)
	addValidMac2(t, guard, third, remoteIP)
	if allowed, _ := guard.ProcessInbound(third, remoteAddr, relayPort); allowed {
		t.Fatal("strict all-IPs limit should enforce a 5 second post-cookie window")
	}

	setHandshakeRateEntry(guard, remoteIP.String(), time.Now().Add(-6*time.Second), false)
	fourth := makeHandshakeInitiation(t, guard, 103)
	addValidMac2(t, guard, fourth, remoteIP)
	if allowed, _ := guard.ProcessInbound(fourth, remoteAddr, relayPort); !allowed {
		t.Fatal("expired post-cookie limiter entry should allow a fresh initiation")
	}
}

func TestWireguardGuard_StrictUnknownIPsExemptsKnownVerifiedIPs(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	guard.DoSLevel = DoSLevelFull
	guard.StricterHandshakeLimitUnknowns = true
	relayPort := 3478

	knownAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111}
	unknownAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2222}

	guard.mu.Lock()
	guard.Sessions = append(guard.Sessions, &WireguardSession{
		RelayPort:     relayPort,
		RemoteAddr:    knownAddr.String(),
		Verified:      true,
		LastServerPkt: time.Now(),
	})
	guard.mu.Unlock()
	setHandshakeRateEntry(guard, knownAddr.IP.String(), time.Now().Add(-time.Second), true)
	setHandshakeRateEntry(guard, unknownAddr.IP.String(), time.Now().Add(-time.Second), false)

	known := makeHandshakeInitiation(t, guard, 201)
	addValidMac2(t, guard, known, knownAddr.IP)
	if allowed, _ := guard.ProcessInbound(known, knownAddr, relayPort); !allowed {
		t.Fatal("known verified IP should bypass the stricter unknown-IP handshake window")
	}

	unknown := makeHandshakeInitiation(t, guard, 202)
	addValidMac2(t, guard, unknown, unknownAddr.IP)
	if allowed, _ := guard.ProcessInbound(unknown, unknownAddr, relayPort); allowed {
		t.Fatal("unknown IP should be held to the stricter 5 second handshake window")
	}
}

func TestWireguardGuard_DataLimit(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	// Establish verified session
	init := make([]byte, HandshakeInitiationSize)
	init[0] = PacketHandshakeInitiation
	// skip mac1 for simplicity, just hack the guard
	guard.mu.Lock()
	sess := &WireguardSession{
		RelayPort:     relayPort,
		RemoteAddr:    remoteAddr.String(),
		ClientPeerID:  123,
		ServerPeerID:  456,
		Verified:      true,
		LastServerPkt: time.Now(),
	}
	guard.Sessions = append(guard.Sessions, sess)
	guard.mu.Unlock()

	// Send data until limit
	data := make([]byte, 1024)
	data[0] = PacketData
	binary.LittleEndian.PutUint32(data[4:8], 456)

	for i := 0; i < 256; i++ {
		allowed, _ := guard.ProcessInbound(data, remoteAddr, relayPort)
		if !allowed {
			t.Fatalf("Failed at packet %d", i)
		}
	}

	// Next packet should be rejected
	allowed, _ := guard.ProcessInbound(data, remoteAddr, relayPort)
	if allowed {
		t.Error("Data limit (256KB) should be enforced")
	}
}

func TestWireguardGuard_SessionOverflow(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	relayPort := 3478

	// Fill session table with unverified sessions
	for i := 0; i < guard.MaxSessions; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000 + i}
		guard.mu.Lock()
		guard.Sessions = append(guard.Sessions, &WireguardSession{
			RelayPort:  relayPort,
			RemoteAddr: addr.String(),
			Verified:   false,
		})
		guard.mu.Unlock()
	}

	// New verified outbound should replace an unverified one
	serverAddr := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2222}
	resp := make([]byte, HandshakeResponseSize)
	resp[0] = PacketHandshakeResponse
	binary.LittleEndian.PutUint32(resp[8:12], 123)

	if !guard.ProcessOutbound(resp, serverAddr, relayPort) {
		t.Fatal("Outbound should be allowed even if table is full")
	}

	found := false
	guard.mu.RLock()
	for _, s := range guard.Sessions {
		if s.RemoteAddr == serverAddr.String() && s.Verified {
			found = true
			break
		}
	}
	guard.mu.RUnlock()
	if !found {
		t.Error("New verified session should have replaced an unverified one")
	}
}

func TestWireguardGuard_RoamBurstEscalatesDoS(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	relayPort := 3478

	sess := &WireguardSession{
		RelayPort:     relayPort,
		RemoteAddr:    (&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}).String(),
		ClientPeerID:  123,
		ServerPeerID:  456,
		Verified:      true,
		LastServerPkt: time.Now(),
	}
	guard.mu.Lock()
	guard.Sessions = append(guard.Sessions, sess)
	guard.mu.Unlock()

	packet := make([]byte, MinDataPacketSize)
	packet[0] = PacketData
	binary.LittleEndian.PutUint32(packet[4:8], 456)
	binary.LittleEndian.PutUint64(packet[8:16], 1)

	if allowed, _ := guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2222}, relayPort); !allowed {
		t.Fatal("first roam packet should still be allowed before escalation")
	}
	if allowed, _ := guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("3.3.3.3"), Port: 3333}, relayPort); !allowed {
		t.Fatal("second burst roam packet should still be allowed before escalation")
	}
	guard.mu.Lock()
	guard.LastStatsReset = time.Now().Add(-11 * time.Second)
	guard.mu.Unlock()
	guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("4.4.4.4"), Port: 4444}, relayPort)
	if guard.DoSLevel == DoSLevelNone {
		t.Fatal("burst roam activity did not raise DoS level")
	}
}

func TestWireguardGuard_RoamSustainedEscalatesDoS(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	relayPort := 3478

	sess := &WireguardSession{
		RelayPort:     relayPort,
		RemoteAddr:    (&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}).String(),
		ClientPeerID:  123,
		ServerPeerID:  456,
		Verified:      true,
		LastServerPkt: time.Now(),
	}
	guard.mu.Lock()
	guard.Sessions = append(guard.Sessions, sess)
	guard.mu.Unlock()

	packet := make([]byte, MinDataPacketSize)
	packet[0] = PacketData
	binary.LittleEndian.PutUint32(packet[4:8], 456)
	binary.LittleEndian.PutUint64(packet[8:16], 1)

	remotes := []*net.UDPAddr{
		{IP: net.ParseIP("2.2.2.2"), Port: 2222},
		{IP: net.ParseIP("3.3.3.3"), Port: 3333},
		{IP: net.ParseIP("4.4.4.4"), Port: 4444},
	}
	for i, remote := range remotes {
		if allowed, _ := guard.ProcessInbound(packet, remote, relayPort); !allowed {
			t.Fatalf("roam packet %d should still be allowed before escalation", i)
		}
		guard.mu.Lock()
		sess.LastRoam = time.Now().Add(-time.Second)
		guard.mu.Unlock()
	}
	guard.mu.Lock()
	guard.LastStatsReset = time.Now().Add(-11 * time.Second)
	guard.mu.Unlock()
	guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("5.5.5.5"), Port: 5555}, relayPort)
	if guard.DoSLevel == DoSLevelNone {
		t.Fatal("sustained roam activity did not raise DoS level")
	}
}

func TestWireguardGuard_HandshakeFloodEscalatesDoSAndStrictFlags(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)

	guard.mu.Lock()
	guard.ForwardedHandshakeCount = handshakeRateLimit + 1
	guard.LastHandshakeRateReset = time.Now().Add(-2 * handshakeRateWindow)
	guard.maintenanceHandshakePressure(time.Now())
	if guard.DoSLevel != DoSLevelUnknownIPs {
		t.Fatalf("first over-limit window should raise DoS to unknown-IPs, got %v", guard.DoSLevel)
	}

	guard.ForwardedHandshakeCount = handshakeRateLimit + 1
	guard.LastHandshakeRateReset = time.Now().Add(-2 * handshakeRateWindow)
	guard.maintenanceHandshakePressure(time.Now())
	if guard.DoSLevel != DoSLevelFull {
		t.Fatalf("second over-limit window should raise DoS to full, got %v", guard.DoSLevel)
	}

	guard.ForwardedHandshakeCount = handshakeRateLimit + 1
	guard.LastHandshakeRateReset = time.Now().Add(-2 * handshakeRateWindow)
	guard.maintenanceHandshakePressure(time.Now())
	if !guard.StricterHandshakeLimitUnknowns {
		t.Fatal("third over-limit window at full DoS should enable stricter unknown-IP limits")
	}

	guard.ForwardedHandshakeCount = handshakeRateLimit + 1
	guard.LastHandshakeRateReset = time.Now().Add(-2 * handshakeRateWindow)
	guard.maintenanceHandshakePressure(time.Now())
	if !guard.StricterHandshakeLimitAll {
		t.Fatal("fourth over-limit window at full DoS should enable stricter all-IP limits")
	}
	guard.mu.Unlock()
}

func TestWireguardGuard_DoSDecreaseClearsStrictHandshakeFlags(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)

	guard.mu.Lock()
	guard.DoSLevel = DoSLevelFull
	guard.StricterHandshakeLimitUnknowns = true
	guard.StricterHandshakeLimitAll = true
	guard.DOSLowerTrigger = 11
	guard.LastStatsReset = time.Now().Add(-11 * time.Second)
	guard.maintenance()
	if guard.DoSLevel != DoSLevelUnknownIPs {
		t.Fatalf("expected DoS level to decrease by one step, got %v", guard.DoSLevel)
	}
	if guard.StricterHandshakeLimitUnknowns || guard.StricterHandshakeLimitAll {
		t.Fatal("decreasing DoS level should clear stricter handshake flags")
	}
	guard.mu.Unlock()
}
