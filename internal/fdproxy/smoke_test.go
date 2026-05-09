//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy_test

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

// mockSocketProtoServer is a minimal server that speaks the socketproto
// HTTP-upgrade protocol used by uwgsocks.  It accepts Connect frames and
// bridges the resulting data stream to a loopback TCP listener.
type mockSocketProtoServer struct {
	ln        net.Listener
	echoLn    net.Listener
	echoAddr  netip.AddrPort
}

func startMockSocketProtoServer(t *testing.T) *mockSocketProtoServer {
	t.Helper()

	// Echo server: clients connected via fdproxy will be bridged here.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()

	// HTTP-upgrade listener that the fdproxy server calls s.dialUp() to reach.
	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		echoLn.Close()
		t.Fatalf("api listen: %v", err)
	}

	srv := &mockSocketProtoServer{
		ln:       apiLn,
		echoLn:   echoLn,
		echoAddr: addrPortFromAddr(echoLn.Addr()),
	}
	go srv.serve()

	t.Cleanup(func() {
		apiLn.Close()
		echoLn.Close()
	})
	return srv
}

func (s *mockSocketProtoServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

// handleConn speaks the "socketproto HTTP-upgrade" session.
// The fdproxy calls s.dialUp() which dials here and writes an HTTP/1.1
// upgrade request; we reply 101 Switching Protocols then speak
// socketproto frame protocol.
func (s *mockSocketProtoServer) handleConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	// Consume the HTTP upgrade request from fdproxy's dialHTTP.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	// Reply with 101 Switching Protocols.
	c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: socketproto\r\nConnection: Upgrade\r\n\r\n")) //nolint:errcheck

	// Now speak socketproto: expect Connect frame, reply Accept, then bridge.
	frame, err := socketproto.ReadFrame(io.MultiReader(br, c), socketproto.DefaultMaxPayload)
	if err != nil {
		return
	}
	if frame.Action != socketproto.ActionConnect {
		return
	}
	connectReq, err := socketproto.DecodeConnect(frame.Payload)
	if err != nil {
		return
	}
	_ = connectReq

	// Dial the echo backend.
	backend, err := net.DialTimeout("tcp", s.echoAddr.String(), 3*time.Second)
	if err != nil {
		return
	}
	defer backend.Close()

	// Reply with Accept, using the local address of the backend connection.
	bindAP := addrPortFromAddr(backend.LocalAddr())
	acceptPayload, err := socketproto.EncodeAccept(socketproto.Accept{
		IPVersion: 4,
		Protocol:  socketproto.ProtoTCP,
		BindIP:    bindAP.Addr(),
		BindPort:  bindAP.Port(),
	})
	if err != nil {
		return
	}
	if err := socketproto.WriteFrame(c, socketproto.Frame{
		ID:      frame.ID,
		Action:  socketproto.ActionAccept,
		Payload: acceptPayload,
	}); err != nil {
		return
	}

	// Bridge the connection: frame-relay between fdproxy client and echo backend.
	done := make(chan struct{}, 2)
	// fdproxy→echo
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			f, err := socketproto.ReadFrame(c, socketproto.DefaultMaxPayload)
			if err != nil {
				return
			}
			switch f.Action {
			case socketproto.ActionData:
				if _, werr := backend.Write(f.Payload); werr != nil {
					return
				}
			case socketproto.ActionClose:
				return
			}
		}
	}()
	// echo→fdproxy
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := backend.Read(buf)
			if n > 0 {
				if werr := socketproto.WriteFrame(c, socketproto.Frame{
					ID:      frame.ID,
					Action:  socketproto.ActionData,
					Payload: append([]byte(nil), buf[:n]...),
				}); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
}

// TestFdproxyServerLifecycle verifies that a Server can be started, serves
// the PING command, and is shut down cleanly.
func TestFdproxyServerLifecycle(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "fdproxy.sock")

	srv, err := fdproxy.ListenWithOptions(fdproxy.Options{
		Path:       sockPath,
		API:        "http://127.0.0.1:1", // won't be dialed in this test
		Token:      "test-token",
		SocketPath: "/v1/socket",
		Logger:     log.New(os.Stderr, "fdproxy-test: ", 0),
		AllowBind:  true,
	})
	if err != nil {
		t.Fatalf("ListenWithOptions: %v", err)
	}

	// Server must accept connections.
	if srv.Addr() == nil {
		t.Fatal("Addr() returned nil")
	}

	go srv.Serve() //nolint:errcheck

	// --- PING ---
	c := dialUnix(t, sockPath)
	defer c.Close()
	sendLine(t, c, "PING\n")
	pong := readLine(t, c)
	if pong != "PONG" {
		t.Fatalf("expected PONG, got %q", pong)
	}

	// Close must not block.
	done := make(chan error, 1)
	go func() { done <- srv.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Server.Close() did not return within 3 seconds")
	}
}

// TestFdproxyPingCommand exercises the PING command over a Unix socket.
// This is a focused smoke test for the command dispatch path.
func TestFdproxyPingCommand(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "fdproxy-ping.sock")

	srv, err := fdproxy.ListenWithOptions(fdproxy.Options{
		Path:       sockPath,
		API:        "http://127.0.0.1:1",
		Token:      "token",
		SocketPath: "/v1/socket",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve() //nolint:errcheck

	// Multiple sequential PINGs must all receive PONG.
	for i := 0; i < 3; i++ {
		c := dialUnix(t, sockPath)
		sendLine(t, c, "PING\n")
		if got := readLine(t, c); got != "PONG" {
			t.Fatalf("PING %d: got %q, want PONG", i, got)
		}
		c.Close()
	}
}

// TestFdproxyCONNECTTCP exercises the CONNECT tcp command by standing up a
// mock socketproto server that speaks the socketproto protocol, then connecting
// a Unix client to the fdproxy and verifying bidirectional data flows through
// the bridged connection.
func TestFdproxyCONNECTTCP(t *testing.T) {
	mock := startMockSocketProtoServer(t)

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "fdproxy-connect.sock")
	apiURL := "http://" + mock.ln.Addr().String()

	srv, err := fdproxy.ListenWithOptions(fdproxy.Options{
		Path:       sockPath,
		API:        apiURL,
		Token:      "test",
		SocketPath: "/v1/socket",
		AllowBind:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve() //nolint:errcheck

	// Connect via fdproxy: send CONNECT command without an fd
	// (fdproxy will use the Unix conn itself as the local side).
	c := dialUnix(t, sockPath)
	defer c.Close()

	destAP := mock.echoAddr
	req := fmt.Sprintf("CONNECT tcp %s %d 0.0.0.0 0\n", destAP.Addr(), destAP.Port())
	sendLine(t, c, req)

	// Read "OK bindIP bindPort\n".
	reply := readLine(t, c)
	if !strings.HasPrefix(reply, "OK ") {
		t.Fatalf("expected OK reply from CONNECT, got %q", reply)
	}

	// Now the Unix socket is the data channel.  Send data; the mock bridges it
	// through to the echo server and back.  bridgeTCP reads/writes raw bytes on
	// the local (Unix socket) side — no length-prefix framing.
	msg := "hello-fdproxy"
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), msg)
	}
}

// dialUnix connects to a Unix socket with a short deadline.
func dialUnix(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	c, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("dialUnix %s: %v", path, err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	return c
}

// sendLine writes a newline-terminated string to the Unix connection.
func sendLine(t *testing.T, c net.Conn, line string) {
	t.Helper()
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatalf("sendLine %q: %v", line, err)
	}
}

// readLine reads a newline-terminated line from the connection.
func readLine(t *testing.T, c net.Conn) string {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	return strings.TrimSpace(string(buf[:n]))
}

func addrPortFromAddr(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	case *net.UDPAddr:
		return v.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
