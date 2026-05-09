// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine_test

import (
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// openFDCount returns the number of open file descriptors in the current
// process by counting entries in /proc/self/fd.  Returns -1 on non-Linux.
func openFDCount() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// TestResourceLeakDetection verifies that goroutine count and open file
// descriptor count return to near-baseline after a traffic burst through
// the engine's SOCKS5 proxy.
//
// This catches the class of leaks (goroutine leaks, FD leaks) that only
// manifest after extended uptime and are invisible to short integration
// tests.  The test deliberately does NOT exercise the WireGuard tunnel —
// it drives the SOCKS5 accept/dispatch/close path at volume.
func TestResourceLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("resource leak detection test skipped in -short mode")
	}

	const (
		burstSize  = 200          // number of SOCKS5 dial attempts
		drainWait  = 2 * time.Second
		goroutineTolerance = 30   // allow up to N extra goroutines above baseline
		fdTolerance        = 30   // allow up to N extra FDs above baseline
	)

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "leak-token"
	eng := mustStart(t, cfg)
	socks5Addr := eng.Addr("socks5")

	// Stabilise: let background goroutines settle.
	runtime.GC()
	time.Sleep(300 * time.Millisecond)
	runtime.GC()

	baselineGoroutines := runtime.NumGoroutine()
	baselineFDs := openFDCount()
	t.Logf("baseline: goroutines=%d fds=%d", baselineGoroutines, baselineFDs)

	// Burst: open burstSize SOCKS5 connections, each attempting to connect
	// to 127.0.0.1:1 (port 1 — nothing listening; SOCKS5 returns an error
	// quickly so the connection closes cleanly without blocking).
	var wg sync.WaitGroup
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", socks5Addr, 2*time.Second)
			if err != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
			// SOCKS5 greeting: ver=5, nmethods=1, method=0 (no auth)
			c.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
			buf := make([]byte, 2)
			c.Read(buf) //nolint:errcheck
			// SOCKS5 CONNECT to 127.0.0.1:1 (IPv4, port 1)
			c.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1}) //nolint:errcheck
			reply := make([]byte, 10)
			c.Read(reply) //nolint:errcheck
		}()
	}
	wg.Wait()

	// Drain: allow the engine to close its side of all connections.
	time.Sleep(drainWait)
	runtime.GC()
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	finalFDs := openFDCount()

	goroutineDelta := finalGoroutines - baselineGoroutines
	t.Logf("after burst: goroutines=%d (delta=%+d) fds=%d (delta=%+d)",
		finalGoroutines, goroutineDelta, finalFDs, finalFDs-baselineFDs)

	if goroutineDelta > goroutineTolerance {
		t.Errorf("goroutine leak: baseline=%d final=%d delta=%d (tolerance=%d)",
			baselineGoroutines, finalGoroutines, goroutineDelta, goroutineTolerance)
	}

	if baselineFDs >= 0 && finalFDs >= 0 {
		fdDelta := finalFDs - baselineFDs
		if fdDelta > fdTolerance {
			t.Errorf("fd leak: baseline=%d final=%d delta=%d (tolerance=%d)",
				baselineFDs, finalFDs, fdDelta, fdTolerance)
		}
	}
}
