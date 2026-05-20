// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"encoding/binary"
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
