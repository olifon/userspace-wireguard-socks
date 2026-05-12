// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC
//
// Regression repro for the systrap-supervised concurrent-raw-syscall
// SIGILL. Compiled and run by tests/preload/catalog_regressions_test.go
// against `uwgwrapper --transport=auto`. The auto cascade MUST pick a
// transport mode that survives this pattern (concurrent Go goroutines
// each issuing raw socket+setsockopt SYSCALL instructions). If the
// cascade re-promotes systrap-supervised in a way that exposes the
// known concurrency bug, this binary will print SIGILL and the test
// fails.
//
// Pattern is exactly what caddy and Python's net.ipStackCapabilities
// probe do at startup: AF_INET6 SOCK_STREAM + setsockopt IPV6_V6ONLY
// from a handful of OS threads.

package main

import (
	"fmt"
	"sync"
	"syscall"
)

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fd, err := syscall.Socket(syscall.AF_INET6,
				syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
				syscall.IPPROTO_TCP)
			if err != nil {
				fmt.Println("FAIL: socket", err)
				return
			}
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
			if err != nil {
				fmt.Println("FAIL: setsockopt", err)
				syscall.Close(fd)
				return
			}
			syscall.Close(fd)
		}(i)
	}
	wg.Wait()
	fmt.Println("OK: concurrent_raw_syscall")
}
