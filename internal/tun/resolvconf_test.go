// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package tun

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestBaseManagerWriteAndRestoreResolvConf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &baseManager{dnsResolvConf: path}
	handled, err := m.writeResolvConf([]netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
	})
	if !handled || err != nil {
		t.Fatalf("writeResolvConf handled=%v err=%v", handled, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" {
		t.Fatalf("unexpected resolv.conf contents %q", data)
	}
	handled, err = m.restoreResolvConf()
	if !handled || err != nil {
		t.Fatalf("restoreResolvConf handled=%v err=%v", handled, err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "nameserver 9.9.9.9\n" {
		t.Fatalf("unexpected restored resolv.conf contents %q", data)
	}
}
