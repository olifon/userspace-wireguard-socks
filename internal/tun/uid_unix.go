// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !windows

package tun

import "os"

func geteuid() int { return os.Geteuid() }
