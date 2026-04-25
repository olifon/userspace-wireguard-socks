//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy

import (
	"net"
	"syscall"
)

// peerAllowed enforces per-user isolation on the manager Unix socket. The
// fdproxy socket is intended for one user (or one container) only — all
// preload/ptrace clients of the same user trust each other, but a different
// uid must never be able to attach. We use SO_PEERCRED, which the kernel
// records at connect() time and cannot be spoofed by the client.
func (s *Server) peerAllowed(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		s.logger.Printf("peer cred: SyscallConn failed: %v", err)
		return false
	}
	var ucred *syscall.Ucred
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if ctrlErr != nil || sockErr != nil || ucred == nil {
		s.logger.Printf("peer cred: SO_PEERCRED failed: ctrl=%v sock=%v", ctrlErr, sockErr)
		return false
	}
	if ucred.Uid == 0 || ucred.Uid == s.ownUID {
		return true
	}
	if _, ok := s.allowedUIDs[ucred.Uid]; ok {
		return true
	}
	s.logger.Printf("rejecting fdproxy connection from uid=%d (server uid=%d)", ucred.Uid, s.ownUID)
	return false
}
