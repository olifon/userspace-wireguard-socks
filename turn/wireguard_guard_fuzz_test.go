// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// FuzzWireguardGuardProcessInbound throws random byte sequences at
// the WireguardGuard's ProcessInbound packet parser. The parser is
// the primary attack surface on a TURN deployment using the
// optional WireGuard-aware filter — every TURN client can send
// arbitrary bytes, the relay forwards them, the guard inspects.
//
// The fuzz invariant: ProcessInbound must never panic, must never
// allocate unbounded memory, must always return cleanly.
//
// Seed corpus covers:
//   - Empty / single-byte / under-minimum-size packets.
//   - Each msgType (1, 2, 3, 4) with under/over-sized payloads.
//   - Random bytes at the legitimate handshake-initiation size
//     (148 bytes) so the verifyMac1 path runs.
func FuzzWireguardGuardProcessInbound(f *testing.F) {
	// Seed corpus.
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 0, 0, 0})
	f.Add(make([]byte, 4))
	f.Add(make([]byte, HandshakeInitiationSize))
	f.Add(make([]byte, HandshakeResponseSize))
	f.Add(make([]byte, CookieReplySize))
	f.Add(make([]byte, MinDataPacketSize))
	f.Add(make([]byte, MinDataPacketSize+1))
	// Random-byte handshake initiation at the right size.
	rh := make([]byte, HandshakeInitiationSize)
	rand.Read(rh)
	rh[0] = byte(PacketHandshakeInitiation)
	rh[1], rh[2], rh[3] = 0, 0, 0
	f.Add(rh)
	// Same but with non-zero padding to exercise the early-return.
	rh2 := append([]byte(nil), rh...)
	rh2[1] = 1
	f.Add(rh2)

	var publicKey [32]byte
	rand.Read(publicKey[:])
	guard := NewWireguardGuard(publicKey)
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345}

	f.Fuzz(func(t *testing.T, packet []byte) {
		// Cap input size at 64 KiB — beyond that, fuzz inputs grow
		// unboundedly and the guard's processing time would
		// dominate the fuzz target instead of the actual code we
		// want to exercise.
		if len(packet) > 65536 {
			return
		}
		// Goal: ProcessInbound must not panic, must return.
		_, _ = guard.ProcessInbound(packet, addr, 9999)
	})
}

// FuzzWireguardGuardProcessOutbound — same shape as Inbound, on
// the egress path. Less attack-exposed (outbound packets come from
// the WG endpoint we're protecting, which is already authenticated)
// but a panic here still takes the relay down.
func FuzzWireguardGuardProcessOutbound(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, HandshakeInitiationSize))
	f.Add(make([]byte, HandshakeResponseSize))
	f.Add(make([]byte, CookieReplySize))

	var publicKey [32]byte
	rand.Read(publicKey[:])
	guard := NewWireguardGuard(publicKey)
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345}

	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65536 {
			return
		}
		_ = guard.ProcessOutbound(packet, addr, 9999)
	})
}

// TestWireguardGuardAdversarialFlood verifies the guard tolerates
// a high rate of malformed packets from many distinct source IPs
// without runaway memory growth or unbounded session creation.
//
// The session table is capped at DefaultMaxSessions; this test
// exercises the cap by sending well above that count from random
// IPs over a short window.
func TestWireguardGuardAdversarialFlood(t *testing.T) {
	if testing.Short() {
		t.Skip("adversarial flood test skipped in -short mode")
	}

	var publicKey [32]byte
	rand.Read(publicKey[:])
	guard := NewWireguardGuard(publicKey)

	const (
		attackers = 4096
		perAttacker = 5
	)

	// Random bytes at handshake-init size (will mostly fail mac1
	// verification, but the parser still runs).
	makePacket := func() []byte {
		p := make([]byte, HandshakeInitiationSize)
		rand.Read(p)
		p[0] = byte(PacketHandshakeInitiation)
		p[1], p[2], p[3] = 0, 0, 0
		return p
	}

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ipBytes := []byte{
				203,
				0,
				byte(i / 256),
				byte(i % 256),
			}
			addr := &net.UDPAddr{IP: net.IP(ipBytes), Port: 1234}
			for j := 0; j < perAttacker; j++ {
				_, _ = guard.ProcessInbound(makePacket(), addr, 9999)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Sanity: the session table must not have grown beyond its cap.
	guard.mu.Lock()
	sessionCount := len(guard.Sessions)
	guard.mu.Unlock()

	if sessionCount > DefaultMaxSessions {
		t.Fatalf("session table grew to %d, above cap %d", sessionCount, DefaultMaxSessions)
	}

	t.Logf("adversarial flood: %d attackers × %d packets in %v; final session count %d (cap %d)",
		attackers, perAttacker, elapsed, sessionCount, DefaultMaxSessions)
}
