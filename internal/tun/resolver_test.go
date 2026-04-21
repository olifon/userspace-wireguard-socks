// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package tun

import (
	"context"
	"net/netip"
	"testing"
)

func TestBypassResolverLookupLiteral(t *testing.T) {
	r := &BypassResolver{}
	ips, err := r.LookupNetIP(context.Background(), "ip", "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.8") {
		t.Fatalf("literal lookup = %v", ips)
	}
}

func TestParseFallbackSystemDNS(t *testing.T) {
	ips, err := ParseFallbackSystemDNS([]string{"1.1.1.1", "2606:4700:4700::1111"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("parsed %d fallback DNS servers, want 2", len(ips))
	}
}
