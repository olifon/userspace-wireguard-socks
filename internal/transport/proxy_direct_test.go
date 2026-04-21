// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDirectDialerWithLocalAddrsBindsTCPSource(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	d := NewDirectDialerWithLocalAddrs(false, netip.Prefix{}, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case srv := <-accepted:
		defer srv.Close()
		remote := srv.RemoteAddr().(*net.TCPAddr)
		if !remote.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("accepted remote IP = %v, want 127.0.0.1", remote.IP)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for accept")
	}
}

func TestDirectDialerWithLocalAddrsBindsUDPSocket(t *testing.T) {
	d := NewDirectDialerWithLocalAddrs(false, netip.Prefix{}, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pc, effective, err := d.DialPacket(ctx, "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if effective != "127.0.0.1:53" {
		t.Fatalf("effective remote = %q, want 127.0.0.1:53", effective)
	}
	local := pc.LocalAddr().(*net.UDPAddr)
	if !local.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("local UDP IP = %v, want 127.0.0.1", local.IP)
	}
}
