// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !darwin

package engine

import (
	"net"
	"net/netip"

	xicmp "golang.org/x/net/icmp"
)

func (e *Engine) dialHostPing(bindIP, dst netip.Addr) (net.Conn, error) {
	network := "udp4"
	if dst.Is6() {
		network = "udp6"
	}
	laddr := ""
	if bind := e.hostDirectBindIP(bindIP, dst); bind.IsValid() {
		laddr = bind.String()
	}
	pc, err := xicmp.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return &connectedPacketConn{
		PacketConn: pc,
		remote:     &net.IPAddr{IP: net.IP(dst.AsSlice())},
	}, nil
}
