// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"syscall"

	"github.com/vishvananda/netlink"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type linuxManager struct {
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
	return &linuxManager{
		baseManager: baseManager{
			device:    dev,
			name:      name,
			mtu:       opts.MTU,
			localIPv4: local4,
			localIPv6: local6,
		},
	}, nil
}

func (m *linuxManager) AddAddress(prefix netip.Prefix) error {
	link, err := netlink.LinkByName(m.name)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: ipNetFromPrefix(prefix)}
	if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

func (m *linuxManager) RemoveAddress(prefix netip.Prefix) error {
	link, err := netlink.LinkByName(m.name)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: ipNetFromPrefix(prefix)}
	if err := netlink.AddrDel(link, addr); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func (m *linuxManager) AddRoute(prefix netip.Prefix) error {
	link, err := netlink.LinkByName(m.name)
	if err != nil {
		return err
	}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNetFromPrefix(prefix)}
	if err := netlink.RouteAdd(&route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

func (m *linuxManager) RemoveRoute(prefix netip.Prefix) error {
	link, err := netlink.LinkByName(m.name)
	if err != nil {
		return err
	}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNetFromPrefix(prefix)}
	if err := netlink.RouteDel(&route); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func (m *linuxManager) SetDNSServers(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	if _, err := exec.LookPath("resolvectl"); err == nil {
		args := []string{"dns", m.name}
		for _, addr := range addrs {
			args = append(args, addr.String())
		}
		if err := runCmd("resolvectl", args...); err != nil {
			return err
		}
		return runCmd("resolvectl", "domain", m.name, "~.")
	}
	if _, err := exec.LookPath("systemd-resolve"); err == nil {
		args := []string{"--interface", m.name}
		for _, addr := range addrs {
			args = append(args, "--set-dns", addr.String())
		}
		return runCmd("systemd-resolve", args...)
	}
	return errors.New("tun dns configuration requires resolvectl or systemd-resolve")
}

func (m *linuxManager) ClearDNSServers() error {
	if _, err := exec.LookPath("resolvectl"); err == nil {
		return runCmd("resolvectl", "revert", m.name)
	}
	if _, err := exec.LookPath("systemd-resolve"); err == nil {
		return runCmd("systemd-resolve", "--revert", m.name)
	}
	return nil
}

func (m *linuxManager) Start() error { return nil }

func (m *linuxManager) Stop() error {
	link, err := netlink.LinkByName(m.name)
	if err != nil {
		return err
	}
	return netlink.LinkSetDown(link)
}

func (m *linuxManager) Close() error { return m.device.Close() }

func Configure(mgr Manager, opts Options) error {
	if !opts.Configure {
		return nil
	}
	link, err := netlink.LinkByName(mgr.Name())
	if err != nil {
		return err
	}
	if opts.MTU > 0 {
		if err := netlink.LinkSetMTU(link, opts.MTU); err != nil {
			return err
		}
	}
	for _, prefix := range opts.Addresses {
		if err := mgr.AddAddress(prefix); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
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

func ipNetFromPrefix(prefix netip.Prefix) *net.IPNet {
	prefix = prefix.Masked()
	bits := 128
	ip := net.IP(prefix.Addr().AsSlice()).To16()
	if prefix.Addr().Is4() {
		bits = 32
		ip = net.IP(prefix.Addr().AsSlice()).To4()
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(prefix.Bits(), bits)}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}
