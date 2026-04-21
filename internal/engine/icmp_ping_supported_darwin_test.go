// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build darwin

package engine_test

import (
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// hostPingSupported probes the same connect+write path that dialHostPing uses
// on macOS: SOCK_DGRAM ICMP connected socket via net.FileConn.
func hostPingSupported(dst netip.Addr) bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return false
	}
	sa := &syscall.SockaddrInet4{}
	v4 := dst.As4()
	copy(sa.Addr[:], v4[:])
	if err := syscall.Connect(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return false
	}
	f := os.NewFile(uintptr(fd), "icmp")
	conn, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(buildICMPEcho()); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	return err == nil && n > 0
}

func buildICMPEcho() []byte {
	pkt := []byte{8, 0, 0, 0, 0x43, 0x21, 0, 1, 'u', 'w', 'g', 's'}
	var sum uint32
	for i := 0; i+1 < len(pkt); i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	pkt[2] = byte(cs >> 8)
	pkt[3] = byte(cs)
	return pkt
}
