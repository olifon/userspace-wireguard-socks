// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package tun

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type Options struct {
	Name          string
	MTU           int
	Configure     bool
	Addresses     []netip.Prefix
	Routes        []netip.Prefix
	DNSServers    []netip.Addr
	DNSResolvConf string
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
	device             wgtun.Device
	name               string
	mtu                int
	localIPv4          netip.Addr
	localIPv6          netip.Addr
	dnsResolvConf      string
	originalResolvConf []byte
	resolvTouched      bool
}

func (m *baseManager) Device() wgtun.Device { return m.device }
func (m *baseManager) Name() string         { return m.name }
func (m *baseManager) LocalAddrs() (netip.Addr, netip.Addr) {
	return m.localIPv4, m.localIPv6
}

func (m *baseManager) BypassDialer(ipv6Translate bool, prefix netip.Prefix) transport.ProxyDialer {
	return transport.NewDirectDialerWithLocalAddrs(ipv6Translate, prefix, m.localIPv4, m.localIPv6)
}

func (m *baseManager) writeResolvConf(addrs []netip.Addr) (bool, error) {
	if m.dnsResolvConf == "" {
		return false, nil
	}
	if !m.resolvTouched {
		data, err := os.ReadFile(m.dnsResolvConf)
		if err == nil {
			m.originalResolvConf = append([]byte(nil), data...)
		} else if !os.IsNotExist(err) {
			return true, err
		}
		m.resolvTouched = true
	}
	var buf bytes.Buffer
	for _, addr := range addrs {
		if addr.IsValid() {
			buf.WriteString("nameserver ")
			buf.WriteString(addr.String())
			buf.WriteByte('\n')
		}
	}
	return true, os.WriteFile(m.dnsResolvConf, buf.Bytes(), 0o644)
}

func (m *baseManager) restoreResolvConf() (bool, error) {
	if m.dnsResolvConf == "" || !m.resolvTouched {
		return false, nil
	}
	if m.originalResolvConf == nil {
		if err := os.Remove(m.dnsResolvConf); err != nil && !os.IsNotExist(err) {
			return true, err
		}
		return true, nil
	}
	return true, os.WriteFile(m.dnsResolvConf, m.originalResolvConf, 0o644)
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
