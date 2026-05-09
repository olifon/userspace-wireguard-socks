//go:build linux && amd64

package main

import _ "embed"

//go:embed assets/uwgptloader-amd64.so
var embeddedPtloaderBytes []byte
