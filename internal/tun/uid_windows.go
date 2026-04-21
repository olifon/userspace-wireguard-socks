// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build windows

package tun

func geteuid() int { return 0 }
