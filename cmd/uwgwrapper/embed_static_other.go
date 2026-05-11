// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC
//
// Stub for archs that don't have a freestanding static blob built.
// Cross-builds for darwin/windows/bsd land here.

//go:build linux && !amd64 && !arm64

package main

var embeddedStaticBlob []byte

const embeddedStaticBlobArch = ""
