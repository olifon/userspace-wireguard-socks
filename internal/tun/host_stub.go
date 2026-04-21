// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !linux && !darwin && !windows

package tun

import (
	"errors"
	"net/netip"
)

func Create(opts Options) (Manager, error) {
	_ = opts
	return nil, errors.New("host TUN is not supported on this platform")
}

func Configure(mgr Manager, opts Options) error {
	_ = mgr
	_ = opts
	return errors.New("host TUN kernel configuration is not supported on this platform")
}
