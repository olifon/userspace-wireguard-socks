//go:build !linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr, "uwgwrapper is only supported on Linux; current platform is %s/%s\n", runtime.GOOS, runtime.GOARCH)
	os.Exit(1)
}
