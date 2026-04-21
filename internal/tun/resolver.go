// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

type BypassResolver struct {
	LocalIPv4 netip.Addr
	LocalIPv6 netip.Addr
	Servers   []netip.Addr
}

func (r *BypassResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if len(r.Servers) == 0 {
		return net.DefaultResolver.LookupNetIP(ctx, network, host)
	}
	return r.lookupWithServers(ctx, host)
}

func (r *BypassResolver) lookupWithServers(ctx context.Context, host string) ([]netip.Addr, error) {
	name := dns.Fqdn(host)
	seen := make(map[string]struct{})
	var out []netip.Addr
	var last error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, server := range r.Servers {
			resp, err := r.exchange(ctx, server, name, qtype, false)
			if err != nil || resp.Truncated {
				resp, err = r.exchange(ctx, server, name, qtype, true)
			}
			if err != nil {
				last = err
				continue
			}
			if resp.Rcode == dns.RcodeNameError {
				continue
			}
			if resp.Rcode != dns.RcodeSuccess {
				last = fmt.Errorf("dns server %s rcode %s", server, dns.RcodeToString[resp.Rcode])
				continue
			}
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					ip, ok := netip.AddrFromSlice(v.A)
					if ok {
						s := ip.Unmap().String()
						if _, ok := seen[s]; !ok {
							seen[s] = struct{}{}
							out = append(out, ip.Unmap())
						}
					}
				case *dns.AAAA:
					ip, ok := netip.AddrFromSlice(v.AAAA)
					if ok {
						s := ip.Unmap().String()
						if _, ok := seen[s]; !ok {
							seen[s] = struct{}{}
							out = append(out, ip.Unmap())
						}
					}
				}
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("no addresses for %s", host)
}

func (r *BypassResolver) exchange(ctx context.Context, server netip.Addr, name string, qtype uint16, tcp bool) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.RecursionDesired = true
	netw := "udp"
	if tcp {
		netw = "tcp"
	}
	client := &dns.Client{Net: netw, Timeout: 5 * time.Second}
	client.Dialer = &net.Dialer{LocalAddr: r.localAddrForServer(server)}
	if deadline, ok := ctx.Deadline(); ok {
		client.Timeout = time.Until(deadline)
	}
	addr := net.JoinHostPort(server.String(), "53")
	resp, _, err := client.ExchangeContext(ctx, req, addr)
	return resp, err
}

func (r *BypassResolver) localAddrForServer(server netip.Addr) net.Addr {
	server = server.Unmap()
	if server.Is4() && r.LocalIPv4.IsValid() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(r.LocalIPv4, 0))
	}
	if server.Is6() && r.LocalIPv6.IsValid() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(r.LocalIPv6, 0))
	}
	return nil
}

func DefaultFallbackSystemDNS() []netip.Addr {
	return []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.0.0.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("8.8.4.4"),
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("2606:4700:4700::1001"),
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("2001:4860:4860::8844"),
	}
}

func ParseFallbackSystemDNS(raw []string) ([]netip.Addr, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, ip.Unmap())
	}
	return out, nil
}

func RequireRootForRealTUN() error {
	if geteuid() != 0 {
		return errors.New("real host TUN test requires root")
	}
	return nil
}
