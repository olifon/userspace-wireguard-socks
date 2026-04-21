// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build darwin

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type darwinManager struct {
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
	return &darwinManager{
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

func (m *darwinManager) AddAddress(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		mask := netmaskString(prefix.Bits(), 32)
		return run("ifconfig", m.name, "inet", prefix.Addr().String(), prefix.Addr().String(), "netmask", mask, "alias")
	}
	return run("ifconfig", m.name, "inet6", prefix.Addr().String(), "prefixlen", strconv.Itoa(prefix.Bits()), "alias")
}

func (m *darwinManager) RemoveAddress(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return run("ifconfig", m.name, "-alias", prefix.Addr().String())
	}
	return run("ifconfig", m.name, "inet6", prefix.Addr().String(), "delete")
}

func (m *darwinManager) AddRoute(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return run("route", "-n", "add", "-inet", prefix.String(), "-interface", m.name)
	}
	return run("route", "-n", "add", "-inet6", prefix.String(), "-interface", m.name)
}

func (m *darwinManager) RemoveRoute(prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		return run("route", "-n", "delete", "-inet", prefix.String(), "-interface", m.name)
	}
	return run("route", "-n", "delete", "-inet6", prefix.String(), "-interface", m.name)
}

func (m *darwinManager) SetDNSServers(addrs []netip.Addr) error {
	if handled, err := m.writeResolvConf(addrs); handled {
		return err
	}
	if len(addrs) == 0 {
		return nil
	}
	return fmt.Errorf("tun dns configuration is not supported on darwin utun interfaces")
}

func (m *darwinManager) ClearDNSServers() error {
	if handled, err := m.restoreResolvConf(); handled {
		return err
	}
	return nil
}

func (m *darwinManager) Start() error {
	if m.mtu > 0 {
		if err := run("ifconfig", m.name, "mtu", strconv.Itoa(m.mtu)); err != nil {
			return err
		}
	}
	return run("ifconfig", m.name, "up")
}

func (m *darwinManager) Stop() error {
	return run("ifconfig", m.name, "down")
}

func (m *darwinManager) Close() error { return m.device.Close() }

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

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

func netmaskString(bits, width int) string {
	mask := netip.PrefixFrom(netip.AddrFrom4([4]byte{}), bits).Masked().Bits()
	_ = mask
	n := uint32(0)
	if bits > 0 {
		n = ^uint32(0) << (width - bits)
	}
	return fmt.Sprintf("0x%08x", n)
}
