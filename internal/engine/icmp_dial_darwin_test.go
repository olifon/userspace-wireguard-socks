// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build darwin

package engine

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestStripDarwinICMPPacketIPv4(t *testing.T) {
	packet := append([]byte{
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00,
		127, 0, 0, 1,
		127, 0, 0, 1,
	}, []byte{0x00, 0x00, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x07, 'u', 'w', 'g'}...)
	got, ok := stripDarwinICMPPacket(syscall.AF_INET, packet)
	if !ok {
		t.Fatal("stripDarwinICMPPacket rejected valid IPv4 packet")
	}
	if len(got) != len(packet)-20 {
		t.Fatalf("payload len=%d want=%d", len(got), len(packet)-20)
	}
	if got[0] != 0x00 || got[1] != 0x00 || got[7] != 0x07 {
		t.Fatalf("unexpected payload %x", got)
	}
}

func TestStripDarwinICMPPacketKeepsBareICMP(t *testing.T) {
	packet := []byte{0x00, 0x00, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x07}
	got, ok := stripDarwinICMPPacket(syscall.AF_INET, packet)
	if !ok {
		t.Fatal("stripDarwinICMPPacket rejected bare ICMP")
	}
	if len(got) != len(packet) {
		t.Fatalf("payload len=%d want=%d", len(got), len(packet))
	}
}

func TestStripDarwinICMPPacketRejectsTruncatedIPv4Header(t *testing.T) {
	packet := []byte{0x45, 0x00, 0x00, 0x20}
	if _, ok := stripDarwinICMPPacket(syscall.AF_INET, packet); ok {
		t.Fatal("stripDarwinICMPPacket accepted truncated IPv4 header")
	}
}

func TestStripDarwinICMPPacketRejectsBadIPv4HeaderLength(t *testing.T) {
	packet := append([]byte{0x4f, 0x00, 0x00, 0x20}, make([]byte, 20)...)
	if _, ok := stripDarwinICMPPacket(syscall.AF_INET, packet); ok {
		t.Fatal("stripDarwinICMPPacket accepted invalid IPv4 IHL")
	}
}

func TestStripDarwinICMPPacketRejectsTruncatedIPv6Header(t *testing.T) {
	packet := append([]byte{0x60, 0x00, 0x00, 0x00}, make([]byte, 20)...)
	if _, ok := stripDarwinICMPPacket(syscall.AF_INET6, packet); ok {
		t.Fatal("stripDarwinICMPPacket accepted truncated IPv6 header")
	}
}

func TestDarwinICMPConnReadTruncatesToCallerBuffer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	conn := &darwinICMPConn{Conn: client, family: syscall.AF_INET}
	packet := append([]byte{
		0x45, 0x00, 0x00, 0x24,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00,
		127, 0, 0, 1,
		127, 0, 0, 1,
	}, []byte{0x00, 0x00, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x07, 'u', 'w', 'g', 'x'}...)
	go func() {
		_, _ = server.Write(packet)
	}()
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read returned err=%v", err)
	}
	if n != len(buf) {
		t.Fatalf("Read returned n=%d want=%d", n, len(buf))
	}
}

func TestDarwinICMPConnReadRejectsMalformedPacket(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	conn := &darwinICMPConn{Conn: client, family: syscall.AF_INET}
	go func() {
		_, _ = server.Write([]byte{0x45, 0x00, 0x00, 0x20})
	}()
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("Read unexpectedly accepted malformed packet")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("Read returned EOF instead of malformed packet error")
	}
}
