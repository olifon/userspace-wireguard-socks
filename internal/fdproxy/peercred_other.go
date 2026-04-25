//go:build !linux && !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy

import "net"

// peerAllowed: on non-Linux Unix-likes we rely on the 0700 socket mode set in
// listenUnixOwnerOnly. SO_PEERCRED is Linux-specific; the equivalent on
// macOS/FreeBSD (LOCAL_PEERCRED, getpeereid) is not wired here. The mode
// guard is sufficient when the socket lives under a per-user directory.
func (s *Server) peerAllowed(c *net.UnixConn) bool {
	_ = c
	return true
}
