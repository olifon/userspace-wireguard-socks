// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build darwin

package engine

// macOS does not support sendto on SOCK_DGRAM ICMP sockets; it requires a
// connected socket (connect + write). We create the socket via syscall,
// connect it to the destination, then hand it to net.FileConn so the rest
// of the engine sees a plain net.Conn.

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
)

func (e *Engine) dialHostPing(_ netip.Addr, dst netip.Addr) (net.Conn, error) {
	family := syscall.AF_INET
	proto := syscall.IPPROTO_ICMP
	if dst.Is6() {
		family = syscall.AF_INET6
		proto = syscall.IPPROTO_ICMPV6
	}
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, err
	}
	var sa syscall.Sockaddr
	if dst.Is4() {
		a := &syscall.SockaddrInet4{}
		v4 := dst.As4()
		copy(a.Addr[:], v4[:])
		sa = a
	} else {
		a := &syscall.SockaddrInet6{}
		v16 := dst.As16()
		copy(a.Addr[:], v16[:])
		sa = a
	}
	if err := syscall.Connect(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "icmp")
	conn, err := net.FileConn(f)
	_ = f.Close() // net.FileConn dups the fd; close our reference
	if err != nil {
		return nil, err
	}
	return &darwinICMPConn{Conn: conn, family: family}, nil
}

type darwinICMPConn struct {
	net.Conn
	family int
}

func (c *darwinICMPConn) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)+64)
	n, err := c.Conn.Read(buf)
	if n <= 0 {
		return n, err
	}
	payload, ok := stripDarwinICMPPacket(c.family, buf[:n])
	if !ok {
		return 0, fmt.Errorf("darwin icmp read: malformed packet")
	}
	if len(payload) > len(p) {
		copy(p, payload[:len(p)])
		return len(p), err
	}
	copy(p, payload)
	return len(payload), err
}

func stripDarwinICMPPacket(family int, packet []byte) ([]byte, bool) {
	switch family {
	case syscall.AF_INET:
		if len(packet) == 0 {
			return nil, false
		}
		if packet[0]>>4 != 4 {
			return packet, true
		}
		if len(packet) < 20 {
			return nil, false
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || ihl > len(packet) {
			return nil, false
		}
		return packet[ihl:], true
	case syscall.AF_INET6:
		if len(packet) == 0 {
			return nil, false
		}
		if packet[0]>>4 != 6 {
			return packet, true
		}
		if len(packet) < 40 {
			return nil, false
		}
		return packet[40:], true
	default:
		return packet, true
	}
}
