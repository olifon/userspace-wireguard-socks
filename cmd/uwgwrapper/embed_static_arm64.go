// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC
//
// arm64 variant of embed_static — see the amd64 file for rationale.
// If you're cross-building for arm64 from another host, ensure that
// preload/build_static.sh has produced
// cmd/uwgwrapper/assets/uwgpreload-static-arm64.so before `go build`.

//go:build arm64

package main

import _ "embed"

//go:embed assets/uwgpreload-static-arm64.so
var embeddedStaticBlob []byte

const embeddedStaticBlobArch = "arm64"
