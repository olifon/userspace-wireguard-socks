// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildUDPAssociateRequest(t *testing.T) {
	cases := []struct {
		name     string
		hint     string
		wantAtyp byte
		wantIP   [4]byte // only checked for IPv4
		wantPort uint16
	}{
		{
			name:     "empty hint → fallback 0.0.0.0:0",
			hint:     "",
			wantAtyp: 1,
			wantIP:   [4]byte{0, 0, 0, 0},
			wantPort: 0,
		},
		{
			name:     "IPv4 hint",
			hint:     "192.0.2.1:3478",
			wantAtyp: 1,
			wantIP:   [4]byte{192, 0, 2, 1},
			wantPort: 3478,
		},
		{
			name:     "invalid hint → fallback",
			hint:     "not-a-valid-hint",
			wantAtyp: 1,
			wantIP:   [4]byte{0, 0, 0, 0},
			wantPort: 0,
		},
		{
			name:     "hint with port zero → fallback",
			hint:     "192.0.2.1:0",
			wantAtyp: 1,
			wantIP:   [4]byte{0, 0, 0, 0},
			wantPort: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := buildUDPAssociateRequest(tc.hint)
			if len(req) < 10 {
				t.Fatalf("request too short: %d bytes", len(req))
			}
			if req[0] != 5 || req[1] != 3 || req[2] != 0 {
				t.Errorf("header VER/CMD/RSV = %v, want [5 3 0]", req[:3])
			}
			if req[3] != tc.wantAtyp {
				t.Errorf("ATYP = %d, want %d", req[3], tc.wantAtyp)
			}
			if tc.wantAtyp == 1 {
				got := [4]byte(req[4:8])
				if got != tc.wantIP {
					t.Errorf("DST.ADDR = %v, want %v", got, tc.wantIP)
				}
				gotPort := binary.BigEndian.Uint16(req[8:10])
				if gotPort != tc.wantPort {
					t.Errorf("DST.PORT = %d, want %d", gotPort, tc.wantPort)
				}
			}
		})
	}
}

// TestBuildUDPAssociateRequestIPv6Hint verifies that an IPv6 hint produces
// a UDP ASSOCIATE request with ATYP=4 and the correct 16-byte address.
func TestBuildUDPAssociateRequestIPv6Hint(t *testing.T) {
	req := buildUDPAssociateRequest("[2001:db8::1]:3478")
	// 3 (VER/CMD/RSV) + 1 (ATYP) + 16 (IPv6 addr) + 2 (port) = 22 bytes minimum.
	if len(req) < 22 {
		t.Fatalf("IPv6 UDP ASSOCIATE request too short: %d bytes", len(req))
	}
	if req[0] != 5 || req[1] != 3 || req[2] != 0 {
		t.Errorf("header VER/CMD/RSV = %v, want [5 3 0]", req[:3])
	}
	if req[3] != 0x04 {
		t.Errorf("ATYP = %d, want 4 (IPv6)", req[3])
	}
	want := netip.MustParseAddr("2001:db8::1").As16()
	var got [16]byte
	copy(got[:], req[4:20])
	if got != want {
		t.Errorf("IPv6 address bytes = %x, want %x", got, want)
	}
	if port := binary.BigEndian.Uint16(req[20:22]); port != 3478 {
		t.Errorf("port = %d, want 3478", port)
	}
}

func TestSOCKS5UDPHeaderLenRejectsTruncatedIPv6Header(t *testing.T) {
	if _, err := socks5UDPHeaderLen([]byte{
		0x00, 0x00, 0x00, 0x04,
		0, 1, 2, 3, 4, 5,
	}); err == nil {
		t.Fatal("socks5UDPHeaderLen accepted truncated IPv6 header")
	}
}

func TestSOCKS5UDPHeaderLenRejectsTruncatedDomainHeader(t *testing.T) {
	if _, err := socks5UDPHeaderLen([]byte{
		0x00, 0x00, 0x00, 0x03,
		0x05, 'h', 'o',
	}); err == nil {
		t.Fatal("socks5UDPHeaderLen accepted truncated domain header")
	}
}
