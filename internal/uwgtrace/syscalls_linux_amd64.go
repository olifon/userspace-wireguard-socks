// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && amd64

package uwgtrace

import "golang.org/x/sys/unix"

var secretBypassSyscalls = []uint32{
	unix.SYS_SOCKET,
	unix.SYS_CONNECT,
	unix.SYS_BIND,
	unix.SYS_LISTEN,
	unix.SYS_ACCEPT,
	unix.SYS_ACCEPT4,
	unix.SYS_CLOSE,
	unix.SYS_READ,
	unix.SYS_WRITE,
	unix.SYS_READV,
	unix.SYS_WRITEV,
	unix.SYS_SENDMSG,
	unix.SYS_RECVMSG,
	unix.SYS_SENDMMSG,
	unix.SYS_RECVMMSG,
	unix.SYS_DUP,
	unix.SYS_DUP2,
	unix.SYS_DUP3,
	unix.SYS_GETSOCKNAME,
	unix.SYS_GETPEERNAME,
	unix.SYS_SHUTDOWN,
	unix.SYS_FCNTL,
	unix.SYS_GETSOCKOPT,
	unix.SYS_SETSOCKOPT,
	unix.SYS_POLL,
	unix.SYS_PPOLL,
}

var alwaysTraceSyscalls = []uint32{
	unix.SYS_SENDTO,
	unix.SYS_RECVFROM,
	// x86_64 still exposes a real select(2) syscall, so raw libc select() can
	// still reach the tracer even though the preload hot path prefers ppoll.
	unix.SYS_SELECT,
	unix.SYS_PSELECT6,
	// epoll: modern apps (BIND/dig, libuv, libevent) use epoll_pwait instead
	// of poll/select to wait for data on connected sockets. Without
	// intercepting these, proxied fds (which have data on a unix socket, not
	// the original kernel socket) are invisible to the epoll and the app
	// times out waiting for data that never arrives on the real fd.
	unix.SYS_EPOLL_CTL,
	unix.SYS_EPOLL_WAIT,
	unix.SYS_EPOLL_PWAIT,
}

func syscallUsesPassthroughSecret(nr int64) bool {
	return syscallInSet(nr, secretBypassSyscalls)
}
