// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package wgbind

import (
	"context"
	"net/netip"
	"testing"
)

func TestResolveAddrPortWithResolver(t *testing.T) {
	ap, err := resolveAddrPortWithResolver("mesh.example:51820", func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != "mesh.example" {
			t.Fatalf("resolver host = %q, want mesh.example", host)
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.44")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddrPort("198.51.100.44:51820")
	if ap != want {
		t.Fatalf("resolved addrport = %s, want %s", ap, want)
	}
}
