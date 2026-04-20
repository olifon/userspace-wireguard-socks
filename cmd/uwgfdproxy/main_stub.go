//go:build windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "uwgfdproxy is unsupported on Windows")
	os.Exit(1)
}
