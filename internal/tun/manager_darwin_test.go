// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build darwin

package tun

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestCreateUTUNDevice(t *testing.T) {
	mgr, err := Create(Options{Name: "utun", MTU: 1380})
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("utun creation requires extra privilege on this host: %v", err)
		}
		t.Fatal(err)
	}
	defer mgr.Close()
	if mgr.Device() == nil {
		t.Fatal("expected non-nil device")
	}
	if name := mgr.Name(); !strings.HasPrefix(name, "utun") {
		t.Fatalf("manager name = %q, want utun*", name)
	}
}
