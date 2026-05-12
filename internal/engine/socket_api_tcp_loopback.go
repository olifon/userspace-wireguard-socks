// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

// tcpLoopbackEntry references a live socket-API TCP listener registered in
// the engine's tcpLoopbackRegistry. The accept callback delivers an
// in-process net.Conn to the listening session as if a fresh client had
// arrived via netstack. gVisor netstack does NOT loop TCP between two
// listeners bound to the same NIC IP (same root cause as the UDP case),
// so engine-level short-circuit is the only path that makes same-host
// wrapped client → wrapped server work for TCP.
//
// Accept is wired by openTCPListener; openTCPConn looks up the registry
// before falling through to the netstack dialer.
type tcpLoopbackEntry struct {
	listenerAP netip.AddrPort
	// accept hands a freshly-created server-side conn to the listening
	// session. The clientAP is the client's source addr:port (used as
	// the conn's RemoteAddr — what the wrapped server sees in its
	// accept() return). Returns an error if the listener is closed or
	// the accept frame can't be sent.
	accept func(serverConn net.Conn, clientAP netip.AddrPort) error
}

func (e *Engine) registerTCPLoopback(bind netip.AddrPort, entry *tcpLoopbackEntry) {
	if !bind.IsValid() || entry == nil {
		return
	}
	e.tcpLoopbackMu.Lock()
	if e.tcpLoopbackRegistry == nil {
		e.tcpLoopbackRegistry = make(map[netip.AddrPort]*tcpLoopbackEntry)
	}
	e.tcpLoopbackRegistry[bind] = entry
	e.tcpLoopbackMu.Unlock()
}

func (e *Engine) unregisterTCPLoopback(bind netip.AddrPort, entry *tcpLoopbackEntry) {
	if !bind.IsValid() {
		return
	}
	e.tcpLoopbackMu.Lock()
	if cur, ok := e.tcpLoopbackRegistry[bind]; ok && cur == entry {
		delete(e.tcpLoopbackRegistry, bind)
	}
	e.tcpLoopbackMu.Unlock()
}

func (e *Engine) lookupTCPLoopback(bind netip.AddrPort) *tcpLoopbackEntry {
	e.tcpLoopbackMu.Lock()
	defer e.tcpLoopbackMu.Unlock()
	return e.tcpLoopbackRegistry[bind]
}

// loopbackAddr is a net.Addr that returns a fixed AddrPort. We can't use
// net.Pipe's pipeAddr because it returns "pipe" with no AddrPort — but
// the rest of the engine + the wrapped server's accept() inspect
// LocalAddr/RemoteAddr to populate the wrapper's connect-frame fields.
type loopbackAddr struct{ ap netip.AddrPort }

func (a loopbackAddr) Network() string { return "tcp" }
func (a loopbackAddr) String() string  { return a.ap.String() }

// loopbackConn wraps a net.Pipe end with AddrPort overrides for
// LocalAddr/RemoteAddr. SetDeadline / Read / Write / Close pass through.
type loopbackConn struct {
	inner      net.Conn
	localAP    netip.AddrPort
	remoteAP   netip.AddrPort
}

func (c *loopbackConn) Read(b []byte) (int, error)         { return c.inner.Read(b) }
func (c *loopbackConn) Write(b []byte) (int, error)        { return c.inner.Write(b) }
func (c *loopbackConn) Close() error                        { return c.inner.Close() }
func (c *loopbackConn) LocalAddr() net.Addr                 { return loopbackAddr{c.localAP} }
func (c *loopbackConn) RemoteAddr() net.Addr                { return loopbackAddr{c.remoteAP} }
func (c *loopbackConn) SetDeadline(t time.Time) error       { return c.inner.SetDeadline(t) }
func (c *loopbackConn) SetReadDeadline(t time.Time) error   { return c.inner.SetReadDeadline(t) }
func (c *loopbackConn) SetWriteDeadline(t time.Time) error  { return c.inner.SetWriteDeadline(t) }

// newTCPLoopbackPair returns a bidirectional in-memory conn pair where
// clientConn's LocalAddr = clientAP, RemoteAddr = serverAP and vice
// versa. The wrapped server's accept() sees the connection as having
// come from clientAP; the wrapped client's dial returns a conn whose
// LocalAddr is its bind addr.
func newTCPLoopbackPair(clientAP, serverAP netip.AddrPort) (clientConn, serverConn net.Conn) {
	a, b := net.Pipe()
	clientConn = &loopbackConn{inner: a, localAP: clientAP, remoteAP: serverAP}
	serverConn = &loopbackConn{inner: b, localAP: serverAP, remoteAP: clientAP}
	return clientConn, serverConn
}

// tryTCPLoopback attempts to short-circuit a TCP dial through the same-
// host loopback registry. Returns (true, nil) on successful loopback
// (caller MUST NOT fall through to the netstack dialer); (false, nil)
// when no registry hit (caller proceeds normally); (true, err) when a
// registry hit was found but the loopback hand-off failed (the dialer
// session has already been closed).
//
// The bind argument may be the zero AddrPort, in which case the client's
// source addr:port is synthesized from the engine's first local addr
// + an ephemeral port — same as what netstack would produce.
func (s *socketServer) tryTCPLoopback(id uint64, bind, dest netip.AddrPort, version uint8) (bool, error) {
	entry := s.e.lookupTCPLoopback(dest)
	if entry == nil {
		return false, nil
	}
	// Synthesize client-side addr:port if the dialer didn't bind. The
	// listener sees this as the "client" in accept() — we want it to
	// look like a tunnel-side connection.
	clientAP := bind
	if !clientAP.IsValid() || clientAP.Port() == 0 {
		ip, ok := s.e.firstLocalAddr(version)
		if !ok {
			return true, errors.New("TCP loopback: no local addr for ephemeral source bind")
		}
		clientAP = netip.AddrPortFrom(ip, s.e.allocateEphemeralPort())
	}

	clientConn, serverConn := newTCPLoopbackPair(clientAP, dest)

	// Hand the server side to the listener. This stores a new session
	// on the listener's socketServer and sends an ActionConnect frame.
	if err := entry.accept(serverConn, clientAP); err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		return true, err
	}

	ss := &socketSession{id: id, proto: socketproto.ProtoTCP, conn: clientConn}
	s.storeSession(ss)
	if err := s.sendAccept(id, version, socketproto.ProtoTCP, clientAP); err != nil {
		s.closeSession(id, false)
		return true, err
	}
	ss.startReader(s, false)
	return true, nil
}

// allocateEphemeralPort returns a port from the engine's ephemeral pool
// for synthesized client-side source addrs in the TCP loopback path.
// It's a strict allocator — no collision check across runs because each
// allocation is per-dial and the conn is in-process (no kernel binding).
func (e *Engine) allocateEphemeralPort() uint16 {
	e.tcpLoopbackEphMu.Lock()
	defer e.tcpLoopbackEphMu.Unlock()
	if e.tcpLoopbackEphNext == 0 {
		e.tcpLoopbackEphNext = 49152 // start of the IANA ephemeral range
	}
	p := e.tcpLoopbackEphNext
	e.tcpLoopbackEphNext++
	if e.tcpLoopbackEphNext < 49152 {
		// Wrapped past 65535; restart.
		e.tcpLoopbackEphNext = 49152
	}
	return p
}

// tcpLoopbackEphMu / tcpLoopbackEphNext are intentionally simple: the
// allocator is in-process, never visible to the kernel, never racing
// against a real bind. A monotonic counter is sufficient.
var _ = sync.Mutex{} // keep imports tidy
