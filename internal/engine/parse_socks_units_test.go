// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"net/netip"
	"testing"
)

// readSOCKSAddr / parseSOCKSUDPDatagram / packSOCKSUDPDatagram are
// touched by every inbound SOCKS5 connection — they parse data
// straight off an untrusted client wire. These tests pin the input
// validation so a regression that allows zero-length domains, bad
// ATYP, or short reads can't sneak in.

func TestReadSOCKSAddrIPv4(t *testing.T) {
	// 4 bytes addr + 2 bytes port (BE).
	body := []byte{1, 2, 3, 4, 0x01, 0xbb}
	addr, err := readSOCKSAddr(bytes.NewReader(body), socksAtypIPv4)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if addr.atyp != socksAtypIPv4 || addr.port != 443 {
		t.Fatalf("unexpected addr: %+v", addr)
	}
	if addr.addr != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("unexpected addr.addr: %s", addr.addr)
	}
}

func TestReadSOCKSAddrIPv6(t *testing.T) {
	body := make([]byte, 0, 18)
	body = append(body, []byte{
		0xfd, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x42,
	}...)
	body = append(body, 0x00, 0x50)
	addr, err := readSOCKSAddr(bytes.NewReader(body), socksAtypIPv6)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if addr.atyp != socksAtypIPv6 || addr.port != 80 {
		t.Fatalf("unexpected addr: %+v", addr)
	}
	if !addr.addr.Is6() {
		t.Fatalf("expected IPv6 addr, got %s", addr.addr)
	}
}

func TestReadSOCKSAddrDomain(t *testing.T) {
	host := "example.com"
	body := []byte{byte(len(host))}
	body = append(body, []byte(host)...)
	body = append(body, 0x00, 0x50)
	addr, err := readSOCKSAddr(bytes.NewReader(body), socksAtypDomain)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if addr.host != host || addr.port != 80 {
		t.Fatalf("unexpected addr: %+v", addr)
	}
	if addr.addr.IsValid() {
		t.Fatalf("expected unresolved domain, got %s", addr.addr)
	}
}

func TestReadSOCKSAddrZeroLengthDomainRejected(t *testing.T) {
	body := []byte{0x00, 0x00, 0x50}
	_, err := readSOCKSAddr(bytes.NewReader(body), socksAtypDomain)
	if err == nil {
		t.Fatal("expected error on zero-length domain")
	}
}

func TestReadSOCKSAddrUnknownATYPRejected(t *testing.T) {
	_, err := readSOCKSAddr(bytes.NewReader([]byte{1, 2, 3, 4}), 0xff)
	if err == nil {
		t.Fatal("expected error on unknown ATYP")
	}
}

func TestReadSOCKSAddrShortReads(t *testing.T) {
	cases := []struct {
		name string
		atyp byte
		body []byte
	}{
		{"ipv4 missing port", socksAtypIPv4, []byte{1, 2, 3, 4}},
		{"ipv4 missing addr", socksAtypIPv4, []byte{1, 2}},
		{"ipv6 missing addr", socksAtypIPv6, make([]byte, 8)},
		{"ipv6 missing port", socksAtypIPv6, make([]byte, 16)},
		{"domain missing length", socksAtypDomain, []byte{}},
		{"domain payload truncated", socksAtypDomain, []byte{4, 'a', 'b'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readSOCKSAddr(bytes.NewReader(tc.body), tc.atyp); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseSOCKSUDPDatagramRoundTrip(t *testing.T) {
	src := netip.MustParseAddrPort("100.64.1.2:9999")
	payload := []byte("hello-udp")
	packed, err := packSOCKSUDPDatagram(src, payload)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	gotAddr, gotPayload, ok := parseSOCKSUDPDatagram(packed)
	if !ok {
		t.Fatal("parse failed on round-trip")
	}
	if gotAddr.atyp != socksAtypIPv4 {
		t.Fatalf("expected ipv4 atyp, got %d", gotAddr.atyp)
	}
	if gotAddr.port != 9999 {
		t.Fatalf("expected port 9999, got %d", gotAddr.port)
	}
	if gotAddr.addr != src.Addr() {
		t.Fatalf("addr mismatch: %s vs %s", gotAddr.addr, src.Addr())
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch: %x vs %x", gotPayload, payload)
	}
}

func TestParseSOCKSUDPDatagramRejectsBadHeader(t *testing.T) {
	cases := [][]byte{
		nil,
		{0},
		{0, 0, 0},
		{0, 0, 1, socksAtypIPv4, 1, 2, 3, 4, 0, 0}, // FRAG != 0
		{1, 0, 0, socksAtypIPv4, 1, 2, 3, 4, 0, 0}, // RSV[0] != 0
		{0, 1, 0, socksAtypIPv4, 1, 2, 3, 4, 0, 0}, // RSV[1] != 0
		{0, 0, 0, 0xff, 1, 2, 3, 4, 0, 0},          // bad ATYP
	}
	for i, packet := range cases {
		if _, _, ok := parseSOCKSUDPDatagram(packet); ok {
			t.Fatalf("case %d: parse should have failed", i)
		}
	}
}

func TestPackSOCKSUDPDatagramRejectsZeroSrc(t *testing.T) {
	if _, err := packSOCKSUDPDatagram(netip.AddrPort{}, []byte("x")); err == nil {
		t.Fatal("expected error on invalid src")
	}
}

func TestSOCKSBindExpectedOK(t *testing.T) {
	v4 := netip.MustParseAddr("198.51.100.5")
	cases := []struct {
		name      string
		requested socksAddr
		remote    netip.AddrPort
		want      bool
	}{
		{
			"unspecified addr unspecified port matches anything",
			socksAddr{atyp: socksAtypIPv4, addr: netip.IPv4Unspecified()},
			netip.AddrPortFrom(v4, 12345),
			true,
		},
		{
			"specific addr matches remote",
			socksAddr{atyp: socksAtypIPv4, addr: v4, port: 12345},
			netip.AddrPortFrom(v4, 12345),
			true,
		},
		{
			"port mismatch",
			socksAddr{atyp: socksAtypIPv4, addr: v4, port: 12345},
			netip.AddrPortFrom(v4, 9999),
			false,
		},
		{
			"addr mismatch",
			socksAddr{atyp: socksAtypIPv4, addr: netip.MustParseAddr("198.51.100.6"), port: 12345},
			netip.AddrPortFrom(v4, 12345),
			false,
		},
		{
			"hostname requests are never expected to bind to a specific addrport",
			socksAddr{atyp: socksAtypDomain, host: "example.com", port: 80},
			netip.AddrPortFrom(v4, 80),
			false,
		},
		{
			"invalid remote",
			socksAddr{atyp: socksAtypIPv4, addr: v4, port: 12345},
			netip.AddrPort{},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := socksBindExpectedOK(tc.requested, tc.remote); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestSOCKSAddrString(t *testing.T) {
	cases := []struct {
		name string
		in   socksAddr
		want string
	}{
		{
			"ipv4",
			socksAddr{atyp: socksAtypIPv4, addr: netip.MustParseAddr("1.2.3.4"), port: 80},
			"1.2.3.4:80",
		},
		{
			"ipv6",
			socksAddr{atyp: socksAtypIPv6, addr: netip.MustParseAddr("fd00::1"), port: 443},
			"[fd00::1]:443",
		},
		{
			"domain",
			socksAddr{atyp: socksAtypDomain, host: "example.com", port: 8080},
			"example.com:8080",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.string(); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
