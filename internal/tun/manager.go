// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package tun

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type Options struct {
	Name       string
	MTU        int
	Configure  bool
	Addresses  []netip.Prefix
	Routes     []netip.Prefix
	DNSServers []netip.Addr
}

type Manager interface {
	Device() wgtun.Device
	Name() string
	LocalAddrs() (netip.Addr, netip.Addr)
	AddAddress(prefix netip.Prefix) error
	RemoveAddress(prefix netip.Prefix) error
	AddRoute(prefix netip.Prefix) error
	RemoveRoute(prefix netip.Prefix) error
	SetDNSServers(addrs []netip.Addr) error
	ClearDNSServers() error
	Start() error
	Stop() error
	BypassDialer(ipv6Translate bool, prefix netip.Prefix) transport.ProxyDialer
	Close() error
}

type baseManager struct {
	device    wgtun.Device
	name      string
	mtu       int
	localIPv4 netip.Addr
	localIPv6 netip.Addr
}

func (m *baseManager) Device() wgtun.Device { return m.device }
func (m *baseManager) Name() string         { return m.name }
func (m *baseManager) LocalAddrs() (netip.Addr, netip.Addr) {
	return m.localIPv4, m.localIPv6
}

func (m *baseManager) BypassDialer(ipv6Translate bool, prefix netip.Prefix) transport.ProxyDialer {
	return transport.NewDirectDialerWithLocalAddrs(ipv6Translate, prefix, m.localIPv4, m.localIPv6)
}

func captureBypassLocalAddrs() (netip.Addr, netip.Addr) {
	return captureBypassLocalAddr("udp4", "1.1.1.1:53"), captureBypassLocalAddr("udp6", "[2001:4860:4860::8888]:53")
}

func captureBypassLocalAddr(network, remote string) netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, remote)
	if err != nil {
		return netip.Addr{}
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}
	}
	addr, ok := netip.AddrFromSlice(ua.IP)
	if !ok || !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
		return netip.Addr{}
	}
	return addr.Unmap()
}
