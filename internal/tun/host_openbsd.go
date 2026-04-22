// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build openbsd

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"os/exec"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type openbsdManager struct {
	baseManager
}

func Create(opts Options) (Manager, error) {
	nameHint := opts.Name
	if nameHint == "" {
		nameHint = "tun"
	}
	dev, err := wgtun.CreateTUN(nameHint, opts.MTU)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil || name == "" {
		name = nameHint
	}
	local4, local6 := captureBypassLocalAddrs()
	return &openbsdManager{
		baseManager: baseManager{
			device:        dev,
			name:          name,
			mtu:           opts.MTU,
			localIPv4:     local4,
			localIPv6:     local6,
			dnsResolvConf: opts.DNSResolvConf,
		},
	}, nil
}

func (m *openbsdManager) AddAddress(prefix netip.Prefix) error {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		return runOpenBSD("ifconfig", m.name, "inet", prefix.Addr().String(), prefix.Addr().String(), "netmask", ipv4Netmask(prefix.Bits()), "alias")
	}
	return runOpenBSD("ifconfig", m.name, "inet6", prefix.Addr().String(), "prefixlen", strconv.Itoa(prefix.Bits()), "alias")
}

func (m *openbsdManager) RemoveAddress(prefix netip.Prefix) error {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		return runOpenBSD("ifconfig", m.name, "inet", prefix.Addr().String(), prefix.Addr().String(), "delete")
	}
	return runOpenBSD("ifconfig", m.name, "inet6", prefix.Addr().String(), "delete")
}

func (m *openbsdManager) AddRoute(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return runOpenBSD("route", "-qn", "add", "-inet", prefix.String(), "-iface", m.name)
	}
	return runOpenBSD("route", "-qn", "add", "-inet6", prefix.String(), "-iface", m.name)
}

func (m *openbsdManager) RemoveRoute(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return runOpenBSD("route", "-qn", "delete", "-inet", prefix.String(), "-iface", m.name)
	}
	return runOpenBSD("route", "-qn", "delete", "-inet6", prefix.String(), "-iface", m.name)
}

func (m *openbsdManager) SetDNSServers(addrs []netip.Addr) error {
	if handled, err := m.writeResolvConf(addrs); handled {
		return err
	}
	if len(addrs) == 0 {
		return nil
	}
	return fmt.Errorf("tun dns configuration on openbsd requires dns_resolv_conf")
}

func (m *openbsdManager) ClearDNSServers() error {
	if handled, err := m.restoreResolvConf(); handled {
		return err
	}
	return nil
}

func (m *openbsdManager) Start() error {
	if m.mtu > 0 {
		if err := runOpenBSD("ifconfig", m.name, "mtu", strconv.Itoa(m.mtu)); err != nil {
			return err
		}
	}
	return runOpenBSD("ifconfig", m.name, "up")
}

func (m *openbsdManager) Stop() error {
	return runOpenBSD("ifconfig", m.name, "down")
}

func (m *openbsdManager) Close() error { return m.device.Close() }

func Configure(mgr Manager, opts Options) error {
	if !opts.Configure {
		return nil
	}
	if err := mgr.Start(); err != nil {
		return err
	}
	for _, prefix := range opts.Addresses {
		if err := mgr.AddAddress(prefix); err != nil {
			return err
		}
	}
	for _, prefix := range opts.Routes {
		if err := mgr.AddRoute(prefix); err != nil {
			return err
		}
	}
	if err := mgr.SetDNSServers(opts.DNSServers); err != nil {
		return err
	}
	return nil
}

func runOpenBSD(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

func ipv4Netmask(bits int) string {
	mask := net.CIDRMask(bits, 32)
	return net.IP(mask).String()
}
