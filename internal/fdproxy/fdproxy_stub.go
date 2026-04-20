//go:build windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy

import (
	"errors"
	"log"
	"net"
)

var ErrUnsupported = errors.New("fdproxy is unsupported on this platform")

type Options struct {
	Path         string
	API          string
	Token        string
	SocketPath   string
	Logger       *log.Logger
	AllowBind    bool
	AllowLowBind bool
	Verbose      bool
}

type Server struct{}

func Listen(path, api, token string, logger *log.Logger) (*Server, error) {
	_ = path
	_ = api
	_ = token
	_ = logger
	return nil, ErrUnsupported
}

func ListenWithSocketPath(path, api, token, socketPath string, logger *log.Logger) (*Server, error) {
	_ = path
	_ = api
	_ = token
	_ = socketPath
	_ = logger
	return nil, ErrUnsupported
}

func ListenWithOptions(opts Options) (*Server, error) {
	_ = opts
	return nil, ErrUnsupported
}

func (s *Server) Addr() net.Addr {
	_ = s
	return nil
}

func (s *Server) Close() error {
	_ = s
	return nil
}

func (s *Server) Serve() error {
	_ = s
	return ErrUnsupported
}
