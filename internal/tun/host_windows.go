// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build windows

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type windowsManager struct {
	baseManager
}

func Create(opts Options) (Manager, error) {
	dev, err := wgtun.CreateTUN(opts.Name, opts.MTU)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil || name == "" {
		name = opts.Name
	}
	local4, local6 := captureBypassLocalAddrs()
	return &windowsManager{
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

func (m *windowsManager) AddAddress(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return run("netsh", "interface", "ipv4", "add", "address", "name="+m.name, "address="+prefix.Addr().String(), "mask="+ipv4Mask(prefix.Bits()))
	}
	return run("netsh", "interface", "ipv6", "add", "address", "interface="+m.name, "address="+prefix.String())
}

func (m *windowsManager) RemoveAddress(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return run("netsh", "interface", "ipv4", "delete", "address", "name="+m.name, "address="+prefix.Addr().String())
	}
	return run("netsh", "interface", "ipv6", "delete", "address", "interface="+m.name, "address="+prefix.Addr().String())
}

func (m *windowsManager) AddRoute(prefix netip.Prefix) error {
	family := "ipv4"
	if !prefix.Addr().Is4() {
		family = "ipv6"
	}
	return run("netsh", "interface", family, "add", "route", "prefix="+prefix.String(), "interface="+m.name)
}

func (m *windowsManager) RemoveRoute(prefix netip.Prefix) error {
	family := "ipv4"
	if !prefix.Addr().Is4() {
		family = "ipv6"
	}
	return run("netsh", "interface", family, "delete", "route", "prefix="+prefix.String(), "interface="+m.name)
}

func (m *windowsManager) SetDNSServers(addrs []netip.Addr) error {
	if handled, err := m.writeResolvConf(addrs); handled {
		return err
	}
	var v4, v6 []netip.Addr
	for _, addr := range addrs {
		if addr.Is4() {
			v4 = append(v4, addr)
		} else if addr.Is6() {
			v6 = append(v6, addr)
		}
	}
	if len(v4) > 0 {
		if err := run("netsh", "interface", "ipv4", "set", "dnsservers", "name="+m.name, "static", v4[0].String(), "primary"); err != nil {
			return err
		}
		for i, addr := range v4[1:] {
			if err := run("netsh", "interface", "ipv4", "add", "dnsservers", "name="+m.name, addr.String(), "index="+strconv.Itoa(i+2)); err != nil {
				return err
			}
		}
	}
	if len(v6) > 0 {
		if err := run("netsh", "interface", "ipv6", "set", "dnsservers", "interface="+m.name, "static", v6[0].String(), "primary"); err != nil {
			return err
		}
		for i, addr := range v6[1:] {
			if err := run("netsh", "interface", "ipv6", "add", "dnsservers", "interface="+m.name, addr.String(), "index="+strconv.Itoa(i+2)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *windowsManager) ClearDNSServers() error {
	if handled, err := m.restoreResolvConf(); handled {
		return err
	}
	return nil
}

func (m *windowsManager) Start() error { return nil }
func (m *windowsManager) Stop() error  { return nil }
func (m *windowsManager) Close() error { return m.device.Close() }

func Configure(mgr Manager, opts Options) error {
	if !opts.Configure {
		return nil
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

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

func ipv4Mask(bits int) string {
	mask := netip.PrefixFrom(netip.AddrFrom4([4]byte{}), bits).Masked().Bits()
	_ = mask
	n := uint32(0)
	if bits > 0 {
		n = ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
