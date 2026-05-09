//go:build linux && arm64

package main

import _ "embed"

//go:embed assets/uwgptloader-arm64.so
var embeddedPtloaderBytes []byte
