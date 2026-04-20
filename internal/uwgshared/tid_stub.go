// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !linux && !android

package uwgshared

import "os"

func currentTID() int {
	return os.Getpid()
}
