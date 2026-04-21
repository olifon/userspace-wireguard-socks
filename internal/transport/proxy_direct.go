// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// DirectDialer is a ProxyDialer that dials directly through the host network
// with no proxy.  Optional IPv6 translation maps IPv4 target addresses to a
// NAT64 /96 prefix before dialling.
type DirectDialer struct {
	// IPv6Translate enables NAT64/DNS64 address translation.
	IPv6Translate bool
	// IPv6Prefix is the NAT64 prefix.  Must be a /96.
	// Defaults to the well-known prefix 64:ff9b::/96.
	IPv6Prefix netip.Prefix
	// LocalIPv4 and LocalIPv6 pin direct sockets to a specific pre-TUN source
	// address so host-TUN full routes do not recurse back into the tunnel.
	LocalIPv4 netip.Addr
	LocalIPv6 netip.Addr
	// LookupNetIP overrides hostname resolution for outer transport dials.
	LookupNetIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// NewDirectDialer creates a DirectDialer.  If ipv6Translate is true and
// prefix is the zero value the well-known prefix 64:ff9b::/96 is used.
func NewDirectDialer(ipv6Translate bool, prefix netip.Prefix) *DirectDialer {
	if ipv6Translate && !prefix.IsValid() {
		// Well-known NAT64 prefix (RFC 6146)
		prefix = netip.MustParsePrefix("64:ff9b::/96")
	}
	return &DirectDialer{IPv6Translate: ipv6Translate, IPv6Prefix: prefix}
}

func NewDirectDialerWithLocalAddrs(ipv6Translate bool, prefix netip.Prefix, localIPv4, localIPv6 netip.Addr) *DirectDialer {
	d := NewDirectDialer(ipv6Translate, prefix)
	d.LocalIPv4 = localIPv4
	d.LocalIPv6 = localIPv6
	return d
}

// DialContext dials network+addr directly.  When IPv6Translate is set, any
// IPv4 literal address is rewritten to its NAT64 representation before
// dialling.
func (d *DirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.IPv6Translate {
		addr = d.translateAddr(addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		var nd net.Dialer
		nd.LocalAddr = d.localAddrFor(network, ip)
		return nd.DialContext(ctx, network, addr)
	}
	lookup := d.LookupNetIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.String(), port)
		var nd net.Dialer
		nd.LocalAddr = d.localAddrFor(network, ip.Unmap())
		conn, err := nd.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no DNS results")
	}
	return nil, firstErr
}

// DialPacket opens a UDP PacketConn for not-connection-oriented UDP traffic.
// remoteHint is translated when IPv6Translate is set.
func (d *DirectDialer) DialPacket(ctx context.Context, remoteHint string) (net.PacketConn, string, error) {
	if d.IPv6Translate {
		remoteHint = d.translateAddr(remoteHint)
	}
	if host, port, err := net.SplitHostPort(remoteHint); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			local := d.packetListenAddr(ip.Unmap())
			pc, err := (&net.ListenConfig{}).ListenPacket(ctx, udpNetwork(ip.Unmap()), local)
			return pc, remoteHint, err
		}
		lookup := d.LookupNetIP
		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}
		ips, err := lookup(ctx, "ip", host)
		if err == nil {
			for _, ip := range ips {
				local := d.packetListenAddr(ip.Unmap())
				pc, listenErr := (&net.ListenConfig{}).ListenPacket(ctx, udpNetwork(ip.Unmap()), local)
				if listenErr == nil {
					return pc, net.JoinHostPort(ip.String(), port), nil
				}
				err = listenErr
			}
		}
		if err != nil {
			return nil, "", err
		}
	}
	// For direct UDP we listen on any local port and report the remote hint
	// as the effective address so callers can route the packet.
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, "", err
	}
	return pc, remoteHint, nil
}

// SupportsHostname returns true; direct dialling resolves via the OS
// resolver.
func (d *DirectDialer) SupportsHostname() bool { return true }

func (d *DirectDialer) localAddrFor(network string, ip netip.Addr) net.Addr {
	if !ip.IsValid() {
		return nil
	}
	if stringsHasSuffix(network, "udp") {
		if ip.Is4() && d.LocalIPv4.IsValid() {
			return net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.LocalIPv4, 0))
		}
		if ip.Is6() && d.LocalIPv6.IsValid() {
			return net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.LocalIPv6, 0))
		}
		return nil
	}
	if ip.Is4() && d.LocalIPv4.IsValid() {
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(d.LocalIPv4, 0))
	}
	if ip.Is6() && d.LocalIPv6.IsValid() {
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(d.LocalIPv6, 0))
	}
	return nil
}

func (d *DirectDialer) packetListenAddr(ip netip.Addr) string {
	if ip.Is4() && d.LocalIPv4.IsValid() {
		return net.JoinHostPort(d.LocalIPv4.String(), "0")
	}
	if ip.Is6() && d.LocalIPv6.IsValid() {
		return net.JoinHostPort(d.LocalIPv6.String(), "0")
	}
	return ":0"
}

func udpNetwork(ip netip.Addr) string {
	if ip.Is6() {
		return "udp6"
	}
	return "udp4"
}

func stringsHasSuffix(network, suffix string) bool { return strings.HasSuffix(network, suffix) }

// translateAddr rewrites an IPv4 host portion of addr to its NAT64 form.
// The port suffix is preserved unchanged.
func (d *DirectDialer) translateAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not a host:port string – return unchanged.
		return addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return addr
	}
	translated := TranslateToIPv6(ip, d.IPv6Prefix)
	return net.JoinHostPort(translated.String(), port)
}
