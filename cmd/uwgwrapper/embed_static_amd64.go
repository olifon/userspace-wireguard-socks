// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC
//
// Per-arch embed of the freestanding static-injection blob.  Active only
// when the wrapper is built for the same arch.  Allows the wrapper to
// inject the systrap static-blob into a tracee even when the on-disk
// uwgpreload-static-${arch}.so asset isn't reachable from the current
// CWD (the historical staticBlobPath fallback).

//go:build amd64

package main

import _ "embed"

//go:embed assets/uwgpreload-static-amd64.so
var embeddedStaticBlob []byte

const embeddedStaticBlobArch = "amd64"
