// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build (!linux || (!amd64 && !arm64)) && (!android || !arm64)

package uwgtrace

import (
	"errors"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgshared"
)

var (
	ErrPtraceUnavailable  = errors.New("ptrace tracing unavailable")
	ErrSeccompUnavailable = errors.New("seccomp trace filter unavailable")
)

type Options struct {
	Args            []string
	Env             []string
	FDProxy         string
	SeccompMode     SeccompMode
	NoNewPrivileges bool
	Verbose         bool
	Shared          *uwgshared.Table
	StatsPath       string
}

type SeccompMode int

const (
	SeccompNone SeccompMode = iota
	SeccompSimple
	SeccompSecret
)

func Run(opts Options) (int, error) {
	_ = opts
	return 0, ErrPtraceUnavailable
}

func RunTraceeHelper(args []string) error {
	_ = args
	return ErrPtraceUnavailable
}

func SetNoNewPrivileges() error {
	return ErrPtraceUnavailable
}
