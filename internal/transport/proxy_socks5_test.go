// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import "testing"

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
