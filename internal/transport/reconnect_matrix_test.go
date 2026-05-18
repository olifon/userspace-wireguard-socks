// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

// stallListener is a TCP listener that accepts connections and discards inbound
// data but never writes.  The accepted connections are kept alive so the client
// sees an "unresponsive" server rather than a clean close.
type stallServer struct {
	ln   net.Listener
	addr string
}

func newStallServer(t *testing.T) *stallServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stall server listen: %v", err)
	}
	ss := &stallServer{ln: ln, addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Drain inbound so the TCP connection is not blocked on sends, but
			// never write a byte back.  The remote side's read deadline fires.
			go io.Copy(io.Discard, c) //nolint:errcheck
		}
	}()
	return ss
}

func (s *stallServer) close() { _ = s.ln.Close() }

// TestSessionUnresponsiveDetectionMatrix verifies that each stream-framed
// transport (TCP, TLS, WebSocket ProxyGuard) correctly detects an unresponsive
// server via its session idle timeout and returns a read error within a
// reasonable deadline.
//
// The "unresponsive" shape is: TCP connection is established and kept alive,
// but the server never writes any data.  The session's deadline-based
// ReadPacket fires after idleTimeout — no software close involved.
func TestSessionUnresponsiveDetectionMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("unresponsive session detection test skipped in -short mode")
	}

	const shortIdle = 200 * time.Millisecond
	const deadline = 3 * time.Second

	type pair struct {
		name   string
		server transport.Transport // listener side
		client transport.Transport // dialer side
	}

	certMgr := &transport.CertManager{}
	if err := certMgr.Start(); err != nil {
		t.Fatal(err)
	}

	cases := []pair{
		{
			name:   "tcp",
			server: transport.NewTCPTransport("tcp-srv", loopbackDialer{}, []string{"127.0.0.1"}).WithIdleTimeout(shortIdle),
			client: transport.NewTCPTransport("tcp-cli", loopbackDialer{}, nil).WithIdleTimeout(shortIdle),
		},
		{
			name:   "tls",
			server: transport.NewTLSTransport("tls-srv", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{}).WithIdleTimeout(shortIdle),
			client: transport.NewTLSTransport("tls-cli", loopbackDialer{}, nil, certMgr, transport.TLSConfig{}).WithIdleTimeout(shortIdle),
		},
		{
			name: "websocket-proxyguard",
			server: transport.NewWebSocketTransport(
				"ws-pg-srv", "http", loopbackDialer{}, []string{"127.0.0.1"}, nil, transport.TLSConfig{},
				transport.WithWebSocketPath("/wg"),
				transport.WithWebSocketUpgradeMode(transport.HTTPUpgradeModeProxyGuard),
			).WithIdleTimeout(shortIdle),
			client: transport.NewWebSocketTransport(
				"ws-pg-cli", "http", loopbackDialer{}, nil, nil, transport.TLSConfig{},
				transport.WithWebSocketPath("/wg"),
				transport.WithWebSocketUpgradeMode(transport.HTTPUpgradeModeProxyGuard),
			).WithIdleTimeout(shortIdle),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()

			// Start server: accept connections, never send.
			ln, err := tc.server.Listen(ctx, 0)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			go func() {
				for {
					sess, err := ln.Accept(ctx)
					if err != nil {
						return
					}
					// Keep session alive — drain inbound but never write back.
					go io.Copy(io.Discard, &sessionReader{sess: sess}) //nolint:errcheck
				}
			}()

			// Client dials and calls ReadPacket.  The idle timer fires after
			// shortIdle because no data flows server→client.
			clientSess, err := tc.client.Dial(ctx, ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer clientSess.Close()

			start := time.Now()
			_, readErr := clientSess.ReadPacket()
			elapsed := time.Since(start)

			if readErr == nil {
				t.Fatal("ReadPacket succeeded unexpectedly (server never sent data)")
			}
			if elapsed < shortIdle/2 {
				t.Fatalf("session died too quickly (%v), expected idle timeout ~%v", elapsed, shortIdle)
			}
			t.Logf("%s: unresponsive session detected via idle timeout after %v (err: %v)", tc.name, elapsed, readErr)

			// Verify the same transport can reconnect immediately (server still up).
			reconnCtx, reconnCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer reconnCancel()
			newSess, err := tc.client.Dial(reconnCtx, ln.Addr().String())
			if err != nil {
				t.Fatalf("reconnect dial failed: %v", err)
			}
			defer newSess.Close()
			t.Logf("%s: reconnect succeeded", tc.name)
		})
	}
}

// sessionReader implements io.Reader by calling ReadPacket.
type sessionReader struct {
	sess transport.Session
}

func (r *sessionReader) Read(_ []byte) (int, error) {
	_, err := r.sess.ReadPacket()
	return 0, err
}

// TestReconnectMatrixSessionDeath covers all transports (TCP, TLS, DTLS,
// WebSocket-HTTP): server closes the connection, client detects the death and
// can dial a new session to the same server.  This is the "connection-close"
// variant of the reconnect matrix — complements the idle-timeout variant above.
func TestReconnectMatrixSessionDeath(t *testing.T) {
	if testing.Short() {
		t.Skip("session-death reconnect matrix skipped in -short mode")
	}

	type pair struct {
		name        string
		server      transport.Transport
		client      transport.Transport
		dialTimeout time.Duration
	}

	certMgr := &transport.CertManager{}
	if err := certMgr.Start(); err != nil {
		t.Fatal(err)
	}

	cases := []pair{
		{
			name:   "tcp",
			server: transport.NewTCPTransport("tcp-srv", loopbackDialer{}, []string{"127.0.0.1"}),
			client: transport.NewTCPTransport("tcp-cli", loopbackDialer{}, nil),
		},
		{
			name:   "tls",
			server: transport.NewTLSTransport("tls-srv", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{}),
			client: transport.NewTLSTransport("tls-cli", loopbackDialer{}, nil, certMgr, transport.TLSConfig{}),
		},
		{
			name: "dtls",
			server: func() transport.Transport {
				cm := &transport.CertManager{}
				_ = cm.Start()
				return transport.NewDTLSTransport("dtls-srv", loopbackDialer{}, []string{"127.0.0.1"}, cm, transport.TLSConfig{})
			}(),
			client: func() transport.Transport {
				cm := &transport.CertManager{}
				_ = cm.Start()
				return transport.NewDTLSTransport("dtls-cli", loopbackDialer{}, nil, cm, transport.TLSConfig{})
			}(),
			dialTimeout: 15 * time.Second,
		},
		{
			name: "websocket-http",
			server: transport.NewWebSocketTransport(
				"ws-srv", "http", loopbackDialer{}, []string{"127.0.0.1"}, nil, transport.TLSConfig{},
				transport.WithWebSocketPath("/wg"),
			),
			client: transport.NewWebSocketTransport(
				"ws-cli", "http", loopbackDialer{}, nil, nil, transport.TLSConfig{},
				transport.WithWebSocketPath("/wg"),
			),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dialTO := 5 * time.Second
			if tc.dialTimeout > 0 {
				dialTO = tc.dialTimeout
			}

			ctx, cancel := context.WithTimeout(context.Background(), dialTO+5*time.Second)
			defer cancel()

			// Start server.
			ln, err := tc.server.Listen(ctx, 0)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}

			serverSessCh := make(chan transport.Session, 1)
			go func() {
				sess, err := ln.Accept(ctx)
				if err == nil {
					serverSessCh <- sess
				}
			}()

			// Client dials.
			dialCtx, dialCancel := context.WithTimeout(ctx, dialTO)
			clientSess, err := tc.client.Dial(dialCtx, ln.Addr().String())
			dialCancel()
			if err != nil {
				ln.Close()
				t.Fatalf("dial: %v", err)
			}

			// Exchange a packet to confirm session is live.
			srvSess := <-serverSessCh
			go func() {
				// Echo one packet.
				pkt, err := srvSess.ReadPacket()
				if err == nil {
					_ = srvSess.WritePacket(pkt)
				}
			}()
			if err := clientSess.WritePacket([]byte("ping")); err != nil {
				t.Fatalf("write ping: %v", err)
			}
			if _, err := clientSess.ReadPacket(); err != nil {
				t.Fatalf("read pong: %v", err)
			}

			// Server closes its side — production-equivalent of a server restart.
			srvSess.Close()
			ln.Close()

			// Client ReadPacket should eventually return an error.
			readErrCh := make(chan error, 1)
			go func() {
				_, err := clientSess.ReadPacket()
				readErrCh <- err
			}()
			select {
			case err := <-readErrCh:
				if err == nil {
					t.Fatal("expected error after server close, got nil")
				}
				t.Logf("%s: session death detected: %v", tc.name, err)
			case <-time.After(15 * time.Second):
				t.Fatal("timeout waiting for session death detection")
			}
			clientSess.Close()

			// Re-open the server, verify reconnect.
			ln2, err := tc.server.Listen(ctx, 0)
			if err != nil {
				t.Fatalf("re-listen: %v", err)
			}
			defer ln2.Close()

			go func() {
				if sess, err := ln2.Accept(ctx); err == nil {
					_ = sess
				}
			}()

			reconnCtx, reconnCancel := context.WithTimeout(ctx, dialTO)
			newSess, err := tc.client.Dial(reconnCtx, ln2.Addr().String())
			reconnCancel()
			if err != nil {
				t.Fatalf("reconnect dial failed: %v", err)
			}
			newSess.Close()
			t.Logf("%s: reconnect succeeded", tc.name)
		})
	}
}

// TestTCPMidStreamDropWithQueuedPackets establishes a TCP session, sends a
// burst of packets, then drops the connection at the carrier level while
// packets are still in-flight.  The session read must return an error (not
// hang); the caller is expected to re-dial.
func TestTCPMidStreamDropWithQueuedPackets(t *testing.T) {
	if testing.Short() {
		t.Skip("mid-stream drop test skipped in -short mode")
	}

	const numPackets = 50

	// Start a slow echo server that adds a delay before forwarding data back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverConnCh := make(chan net.Conn, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case serverConnCh <- c:
			default:
				c.Close()
			}
		}
	}()

	tr := transport.NewTCPTransport("tcp-mid-drop", loopbackDialer{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientSess, err := tr.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientSess.Close()

	srvConn := <-serverConnCh

	// Flood the session with packets before the server processes them all.
	sendErrs := make(chan error, numPackets)
	for i := 0; i < numPackets; i++ {
		pkt := []byte(fmt.Sprintf("packet-%04d", i))
		if err := clientSess.WritePacket(pkt); err != nil {
			sendErrs <- err
			break
		}
	}

	// Drop the carrier TCP connection mid-stream.
	srvConn.Close()

	// ReadPacket (or WritePacket) must return an error rather than hanging.
	errCh := make(chan error, 1)
	go func() {
		_, err := clientSess.ReadPacket()
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReadPacket returned nil after carrier drop")
		}
		t.Logf("mid-stream drop detected: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: ReadPacket did not return after carrier drop")
	}
}

