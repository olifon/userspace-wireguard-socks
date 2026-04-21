// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !darwin

package engine_test

import (
	"bytes"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func hostPingSupported(dst netip.Addr) bool {
	pc, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false
	}
	defer pc.Close()
	payload := []byte("uwgsocks-host-ping-check")
	packet, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0x4321, Seq: 1, Data: payload},
	}).Marshal(nil)
	if err != nil {
		return false
	}
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc.WriteTo(packet, &net.IPAddr{IP: net.IP(dst.AsSlice())}); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return false
		}
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if ok && msg.Type == ipv4.ICMPTypeEchoReply && bytes.Equal(echo.Data, payload) {
			return true
		}
	}
}
