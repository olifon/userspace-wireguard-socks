package netstackex

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestSameNICLoopbackUDP exercises whether gVisor netstack delivers a UDP
// datagram from one listener to another when both listeners are bound to
// the same NIC IP address but different ports. The wrapper's same-host
// udp-echo-bind case depends on this: client side opens an auto-bound
// listener at 10.200.0.1:<eph>, server side bound to 10.200.0.1:<port>,
// and the client writes to the server's tunnel addr.
func TestSameNICLoopbackUDP(t *testing.T) {
	addr := netip.MustParseAddr("10.200.0.1")
	_, tnet, err := CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}

	pcA, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(addr, 0))
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer pcA.Close()
	pcB, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(addr, 49999))
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer pcB.Close()
	t.Logf("pcA local=%v pcB local=%v", pcA.LocalAddr(), pcB.LocalAddr())

	gotCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 2000)
		_ = pcB.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, raddr, err := pcB.ReadFrom(buf)
		if err != nil {
			gotCh <- "ERR: " + err.Error()
			return
		}
		gotCh <- "OK: " + raddr.String() + " " + string(buf[:n])
	}()
	time.Sleep(100 * time.Millisecond)

	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 49999))
	n, err := pcA.WriteTo([]byte("hello"), dst)
	t.Logf("A wrote n=%d err=%v", n, err)

	t.Log("recv result:", <-gotCh)
}
