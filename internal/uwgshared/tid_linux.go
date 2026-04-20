// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux || android

package uwgshared

import "golang.org/x/sys/unix"

func currentTID() int {
	return unix.Gettid()
}
