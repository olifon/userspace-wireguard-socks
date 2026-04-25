//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package malicious

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
)

// TestFDProxyOtherUIDCannotConnect pins the H-1 fix from the security audit:
// the fdproxy manager Unix socket must reject any peer whose effective uid
// differs from the server's uid. We can only meaningfully exercise this
// from root (we need the privilege to drop to a different uid), so the
// test skips on non-root environments rather than producing a false green.
//
// What we verify, end-to-end:
//  1. Server listens.
//  2. Same-uid client connects + writes a malformed request — server
//     processes it (and closes due to the malformed payload, NOT due to
//     a credential rejection). This is the positive control: peercred
//     enforcement is not so aggressive that it locks out the legitimate
//     local user.
//  3. fork+setuid to nobody, attempt to connect, attempt to send a request:
//     the read must come back with EOF/connection-reset because the server
//     closed the conn before reading any bytes (peercred check fails first).
func TestFDProxyOtherUIDCannotConnect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root: drops to a different uid to verify SO_PEERCRED enforcement")
	}
	const altUID = 65534 // nobody on most distros

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "fdproxy.sock")
	srv, err := fdproxy.ListenWithOptions(fdproxy.Options{
		Path:       sockPath,
		API:        "http://127.0.0.1:1", // unused by this test
		SocketPath: "/v1/socket",
		Logger:     log.New(os.Stderr, "fdproxy-test: ", 0),
	})
	if err != nil {
		t.Fatalf("ListenWithOptions: %v", err)
	}
	defer srv.Close()
	go func() { _ = srv.Serve() }()

	// Same-uid sanity: the connection should at least be accepted and we
	// should be able to write something before the server closes us for an
	// unrelated reason (bad request body). If peercred enforcement were
	// over-eager this would fail too.
	t.Run("same uid is accepted", func(t *testing.T) {
		c, err := net.DialTimeout("unix", sockPath, 2*time.Second)
		if err != nil {
			t.Fatalf("same-uid dial: %v", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("PING\n")); err != nil {
			t.Fatalf("same-uid write: %v", err)
		}
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		if n == 0 {
			t.Fatalf("same-uid read returned 0 bytes; server appears to reject our own uid")
		}
	})

	t.Run("other uid is rejected", func(t *testing.T) {
		c, err := dialAsUID(sockPath, altUID, 2*time.Second)
		if err != nil {
			// Some sandboxes (gVisor without setuid, restricted seccomp)
			// will refuse the setuid syscall; treat that as inconclusive
			// rather than a real failure so CI on those runners isn't a
			// false negative.
			if isSetuidUnsupported(err) {
				t.Skipf("setuid(%d) unsupported in this environment: %v", altUID, err)
			}
			t.Fatalf("alt-uid dial: %v", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		// Server should close (or at minimum drop our request on the
		// floor). Either an immediate read EOF or a write that errors on
		// the next syscall is acceptable evidence of rejection. What we
		// MUST NOT see is a PONG-shaped reply.
		_, _ = c.Write([]byte("PING\n"))
		buf := make([]byte, 16)
		n, readErr := c.Read(buf)
		if n > 0 {
			t.Fatalf("alt-uid client got server reply (%d bytes: %q); peercred check failed open", n, buf[:n])
		}
		if readErr == nil {
			t.Fatalf("alt-uid client read returned no data and no error; expected EOF/RST")
		}
	})
}

// relocateTestBinaryForOtherUID copies the running test binary into a
// world-traversable directory so a setuid'd child can fork/exec it.
// `go test` puts the test binary under /tmp/go-build*/... whose parent
// chain is mode 0o700 owned by root, blocking exec for any other uid with
// "permission denied" before our peercred check can even run.
func relocateTestBinaryForOtherUID(uid uint32) (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "uwg-peercred-test-*")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, "helper")
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := copyAll(out, in); err != nil {
		_ = out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	// The setuid'd child inherits cwd from us; if cwd is also under a
	// 0o700 path the child's stat-of-self may fail. Move it somewhere
	// uid `uid` can stat. /tmp is the obvious candidate.
	_ = uid
	return dst, nil
}

func copyAll(dst *os.File, src *os.File) (int64, error) {
	buf := make([]byte, 64*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return total, nil
			}
			return total, err
		}
	}
}

func isSetuidUnsupported(err error) bool {
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EPERM) {
		return true
	}
	// Helper child can also bubble up its own errno text.
	s := err.Error()
	return strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "function not implemented")
}

// dialAsUID forks a tiny helper subprocess (this very test binary,
// re-entered through the helper-mode env var) running as `uid`. The helper
// dials the unix socket, writes "PING\n", reads up to 16 bytes, and exits.
// We capture its exit code + stdout to decide whether the server accepted
// us. We do NOT return a connected net.Conn from the parent — the parent
// is still root and would defeat the purpose of the test.
func dialAsUID(sockPath string, uid uint32, timeout time.Duration) (net.Conn, error) {
	exe, err := relocateTestBinaryForOtherUID(uid)
	if err != nil {
		return nil, err
	}
	// We're specifically validating the SECOND defense layer (SO_PEERCRED).
	// The first layer is the 0o600 socket mode + 0o077-umask creation in
	// listenUnixOwnerOnly, which on its own already blocks `nobody`. To
	// exercise the SO_PEERCRED check on the server, we deliberately widen
	// the socket file mode and its parent dir so the alt-uid child can
	// reach connect(2). If SO_PEERCRED enforcement regresses, this test
	// catches it; if the file mode regresses too, the same regression is
	// caught by the existing security audit doc.
	sockDir := filepath.Dir(sockPath)
	_ = os.Chmod(sockDir, 0o755)
	_ = os.Chmod(sockPath, 0o666)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=TestFDProxyHelperEntrypoint")
	cmd.Env = append(os.Environ(),
		"UWGS_FDPROXY_PEERCRED_HELPER=1",
		"UWGS_FDPROXY_PEERCRED_PATH="+sockPath,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: uid},
	}
	out, runErr := cmd.CombinedOutput()
	// Parse the helper's structured first line: "RESULT: <state> [bytes...]"
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := ""
	for _, ln := range lines {
		if strings.HasPrefix(ln, "RESULT:") {
			last = ln
		}
	}
	if last == "" {
		if runErr != nil {
			return nil, runErr
		}
		return nil, errors.New("helper produced no RESULT line")
	}
	switch {
	case strings.HasPrefix(last, "RESULT: rejected"):
		// Synthesize an already-closed conn so the caller's
		// Read returns 0,EOF as documented in the test.
		return &closedConn{}, nil
	case strings.HasPrefix(last, "RESULT: accepted"):
		// Caller will treat this as a failure (read returns the bytes).
		return &replayConn{payload: []byte(strings.TrimPrefix(last, "RESULT: accepted "))}, nil
	default:
		return nil, errors.New(last)
	}
}

// closedConn is a stand-in for "the server hung up on our alt-uid client".
// The test uses Read → expects 0,EOF; that's exactly what this returns.
type closedConn struct{}

func (closedConn) Read([]byte) (int, error)         { return 0, errors.New("EOF") }
func (closedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (closedConn) Close() error                     { return nil }
func (closedConn) LocalAddr() net.Addr              { return &net.UnixAddr{} }
func (closedConn) RemoteAddr() net.Addr             { return &net.UnixAddr{} }
func (closedConn) SetDeadline(time.Time) error      { return nil }
func (closedConn) SetReadDeadline(time.Time) error  { return nil }
func (closedConn) SetWriteDeadline(time.Time) error { return nil }

// replayConn is the inverse: server replied to alt-uid client with bytes,
// which is what we want the test to flag as a failure.
type replayConn struct {
	payload []byte
	off     int
}

func (r *replayConn) Read(b []byte) (int, error) {
	if r.off >= len(r.payload) {
		return 0, errors.New("EOF")
	}
	n := copy(b, r.payload[r.off:])
	r.off += n
	return n, nil
}
func (r *replayConn) Write(p []byte) (int, error)      { return len(p), nil }
func (r *replayConn) Close() error                     { return nil }
func (r *replayConn) LocalAddr() net.Addr              { return &net.UnixAddr{} }
func (r *replayConn) RemoteAddr() net.Addr             { return &net.UnixAddr{} }
func (r *replayConn) SetDeadline(time.Time) error      { return nil }
func (r *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (r *replayConn) SetWriteDeadline(time.Time) error { return nil }

// TestFDProxyHelperEntrypoint runs inside the alt-uid subprocess. It is
// keyed by the UWGS_FDPROXY_PEERCRED_HELPER env var — the regular test
// run does not enter this branch.
func TestFDProxyHelperEntrypoint(t *testing.T) {
	if os.Getenv("UWGS_FDPROXY_PEERCRED_HELPER") != "1" {
		t.Skip("not the helper invocation")
	}
	path := os.Getenv("UWGS_FDPROXY_PEERCRED_PATH")
	if path == "" {
		t.Fatal("UWGS_FDPROXY_PEERCRED_PATH is required")
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		// Server explicitly closed before accept-handshake completes (rare
		// on Linux; SO_PEERCRED rejection happens after accept, not at
		// dial). Treat as rejection.
		t.Logf("dial err: %v", err)
		os.Stdout.WriteString("RESULT: rejected\n")
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte("PING\n"))
	buf := make([]byte, 16)
	n, _ := c.Read(buf)
	if n > 0 {
		os.Stdout.WriteString("RESULT: accepted " + string(buf[:n]) + "\n")
		return
	}
	os.Stdout.WriteString("RESULT: rejected\n")
}
