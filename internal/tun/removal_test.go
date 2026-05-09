// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package tun

import (
	"net/netip"
	"os/exec"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestAddRouteDuplicateIsIdempotent verifies that AddRoute with an already
// existing prefix (EEXIST) returns nil, not an error.  The Linux kernel returns
// EEXIST when a route for the same destination already exists; the manager must
// absorb that and report success so callers can call AddRoute unconditionally
// at startup without fragile "check-then-add" races.
func TestAddRouteDuplicateIsIdempotent(t *testing.T) {
	if !testconfig.Get().RealTUN {
		t.Skip("set UWG_TEST_REAL_TUN=1 or -uwgs-real-tun to run real host TUN tests")
	}
	if err := RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}

	addr := netip.MustParsePrefix("198.19.1.2/32")
	route := netip.MustParsePrefix("198.19.1.0/24")

	mgr, err := Create(Options{Name: "uwgtest%d", MTU: 1380})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer mgr.Close()

	if err := Configure(mgr, Options{
		Name:      mgr.Name(),
		MTU:       1380,
		Configure: true,
		Addresses: []netip.Prefix{addr},
		Routes:    []netip.Prefix{route},
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	defer mgr.RemoveRoute(route)
	defer mgr.RemoveAddress(addr)

	// Second AddRoute for the same prefix must not return an error.
	if err := mgr.AddRoute(route); err != nil {
		t.Fatalf("second AddRoute returned unexpected error: %v", err)
	}
}

// TestTUNDeviceExternalRemovalGraceful creates a TUN device, removes it from
// the OS with `ip link del`, and verifies that the manager's Close() does not
// hang or panic.  The intent is to guard the engine against a host-level
// interface deletion (e.g. host reboot, container network reconfiguration)
// that races with the shutdown path.
func TestTUNDeviceExternalRemovalGraceful(t *testing.T) {
	if !testconfig.Get().RealTUN {
		t.Skip("set UWG_TEST_REAL_TUN=1 or -uwgs-real-tun to run real host TUN tests")
	}
	if err := RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command not found (required for this test)")
	}

	addr := netip.MustParsePrefix("198.19.2.2/32")
	route := netip.MustParsePrefix("198.19.2.0/24")

	mgr, err := Create(Options{Name: "uwgtest%d", MTU: 1380})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	name := mgr.Name()

	if err := Configure(mgr, Options{
		Name:      name,
		MTU:       1380,
		Configure: true,
		Addresses: []netip.Prefix{addr},
		Routes:    []netip.Prefix{route},
	}); err != nil {
		// If configure fails, try to clean up and skip.
		mgr.Close()
		t.Skipf("Configure: %v", err)
	}

	// Remove the interface externally — simulates host-side deletion.
	if out, err := exec.Command("ip", "link", "del", name).CombinedOutput(); err != nil {
		// Interface might already be gone; that is fine for our purposes.
		t.Logf("ip link del %s: %v output=%s", name, err, out)
	}

	// Close must not panic or deadlock even though the interface is gone.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = mgr.Close()
	}()

	select {
	case <-done:
		// Passed.
	default:
		// Timeout check handled by test runner (-timeout flag).
		<-done
	}
}

// TestManagerCloseIsIdempotent verifies that calling Close() twice on a manager
// does not panic.  This protects deferred-close patterns that may call Close
// after an earlier error path already closed the manager.
func TestManagerCloseIsIdempotent(t *testing.T) {
	if !testconfig.Get().RealTUN {
		t.Skip("set UWG_TEST_REAL_TUN=1 or -uwgs-real-tun to run real host TUN tests")
	}
	if err := RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}

	mgr, err := Create(Options{Name: "uwgtest%d", MTU: 1380})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = mgr.Close()
	// Second close must not panic.
	_ = mgr.Close()
}

// TestBypassDialerWithRemovedAddress verifies that the bypass dialer returned
// by BypassDialer still constructs without panicking even after the TUN's
// local address has been removed from the host.  The dialer may fail on first
// use (the source address is stale), but constructing it must not crash.
func TestBypassDialerWithRemovedAddress(t *testing.T) {
	if !testconfig.Get().RealTUN {
		t.Skip("set UWG_TEST_REAL_TUN=1 or -uwgs-real-tun to run real host TUN tests")
	}
	if err := RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}

	addr := netip.MustParsePrefix("198.19.3.2/32")

	mgr, err := Create(Options{Name: "uwgtest%d", MTU: 1380})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer mgr.Close()

	if err := Configure(mgr, Options{
		Name:      mgr.Name(),
		MTU:       1380,
		Configure: true,
		Addresses: []netip.Prefix{addr},
	}); err != nil {
		t.Skipf("Configure: %v", err)
	}

	// Construct the bypass dialer before removing the address.
	dialer := mgr.BypassDialer(false, addr)
	if dialer == nil {
		t.Fatal("BypassDialer returned nil")
	}

	// Remove the address so the source IP is stale.
	_ = mgr.RemoveAddress(addr)

	// Constructing a second bypass dialer after removal must not panic.
	dialer2 := mgr.BypassDialer(false, addr)
	if dialer2 == nil {
		t.Fatal("BypassDialer after address removal returned nil")
	}

	t.Log("bypass dialer construction with stale address: no panic")
}
