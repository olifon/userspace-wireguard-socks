// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package socketproto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------
// Frame — all action constants round-trip
// ---------------------------------------------------------------

func TestFrame_AllActions(t *testing.T) {
	actions := []uint16{
		ActionConnect,
		ActionAccept,
		ActionClose,
		ActionData,
		ActionUDPDatagram,
		ActionDNS,
		ActionToSocketPair,
	}
	for _, action := range actions {
		var buf bytes.Buffer
		in := Frame{ID: uint64(action), Action: action, Flags: 0xAB, Payload: []byte("test")}
		if err := WriteFrame(&buf, in); err != nil {
			t.Fatalf("action %d WriteFrame: %v", action, err)
		}
		out, err := ReadFrame(&buf, 0)
		if err != nil {
			t.Fatalf("action %d ReadFrame: %v", action, err)
		}
		if out.Action != action || out.Flags != 0xAB || string(out.Payload) != "test" {
			t.Errorf("action %d round-trip mismatch: %+v", action, out)
		}
	}
}

// ---------------------------------------------------------------
// ReadFrame — explicit positive maxPayload branches
// ---------------------------------------------------------------

func TestReadFrame_ExplicitMaxPayload_Within(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{ID: 1, Action: ActionData, Payload: []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	// maxPayload larger than payload — must succeed
	if _, err := ReadFrame(&buf, 1024); err != nil {
		t.Fatalf("ReadFrame with ample maxPayload: %v", err)
	}
}

func TestReadFrame_ExplicitMaxPayload_TooSmall(t *testing.T) {
	// Craft a header claiming 100-byte payload; callers maxPayload=50 → reject
	var hdr [HeaderLen]byte
	hdr[15] = 100 // BigEndian uint32 low byte → payload len = 100
	r := bytes.NewReader(hdr[:])
	if _, err := ReadFrame(r, 50); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

// ---------------------------------------------------------------
// EncodeUDPDatagram / DecodeUDPDatagram — bad version
// ---------------------------------------------------------------

func TestEncodeUDPDatagram_BadVersion(t *testing.T) {
	if _, err := EncodeUDPDatagram(UDPDatagram{IPVersion: 5}); !errors.Is(err, ErrBadFrame) {
		t.Errorf("encode bad version: got %v, want ErrBadFrame", err)
	}
}

func TestDecodeUDPDatagram_BadVersion(t *testing.T) {
	// 4 bytes with a bogus IPVersion field
	buf := []byte{5, 0, 0, 53} // version=5, pad, port-hi, port-lo
	if _, err := DecodeUDPDatagram(buf); !errors.Is(err, ErrBadFrame) {
		t.Errorf("decode bad version: got %v, want ErrBadFrame", err)
	}
}

func TestDecodeUDPDatagram_ShortForVersion(t *testing.T) {
	// Header says v6 but only 4 bytes present (need 4+16=20)
	buf := []byte{6, 0, 0, 53} // version=6, not enough IP bytes
	if _, err := DecodeUDPDatagram(buf); !errors.Is(err, ErrBadFrame) {
		t.Errorf("decode v6 too short: got %v, want ErrBadFrame", err)
	}
}

// ---------------------------------------------------------------
// EncodeAccept / DecodeAccept — bad version + length mismatch
// ---------------------------------------------------------------

func TestEncodeAccept_BadVersion(t *testing.T) {
	if _, err := EncodeAccept(Accept{IPVersion: 99}); !errors.Is(err, ErrBadFrame) {
		t.Errorf("encode bad version: got %v, want ErrBadFrame", err)
	}
}

func TestDecodeAccept_LengthMismatch(t *testing.T) {
	// Version=4 means we expect 6+4=10 bytes; give 9.
	buf := make([]byte, 9)
	buf[0] = 4 // IPVersion
	if _, err := DecodeAccept(buf); !errors.Is(err, ErrBadFrame) {
		t.Errorf("length mismatch: got %v, want ErrBadFrame", err)
	}
}

func TestDecodeAccept_LengthMismatch_V6(t *testing.T) {
	// Version=6 means we expect 6+16=22 bytes; give 21.
	buf := make([]byte, 21)
	buf[0] = 6
	if _, err := DecodeAccept(buf); !errors.Is(err, ErrBadFrame) {
		t.Errorf("v6 length mismatch: got %v, want ErrBadFrame", err)
	}
}

// ---------------------------------------------------------------
// DecodeConnect — IPv6 variant
// ---------------------------------------------------------------

func TestConnect_RoundTrip_v6_badInputs(t *testing.T) {
	// Encode v6, then give a payload 1 byte short.
	b, err := EncodeConnect(Connect{
		ListenerID: 1, IPVersion: 6, Protocol: ProtoTCP,
		BindIP: netip.MustParseAddr("fd00::1"), BindPort: 1000,
		DestIP: netip.MustParseAddr("fd00::2"), DestPort: 2000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeConnect(b[:len(b)-1]); !errors.Is(err, ErrBadFrame) {
		t.Errorf("short v6 connect: got %v, want ErrBadFrame", err)
	}
}

// ---------------------------------------------------------------
// writeFull — partial writer exercises the loop
// ---------------------------------------------------------------

type partialWriter struct {
	buf     []byte
	maxEach int
}

func (pw *partialWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > pw.maxEach {
		n = pw.maxEach
	}
	pw.buf = append(pw.buf, p[:n]...)
	return n, nil
}

func TestWriteFull_PartialWriter(t *testing.T) {
	// Write a frame through a writer that only accepts 3 bytes at a time;
	// writeFull must loop until all bytes are delivered.
	pw := &partialWriter{maxEach: 3}
	if err := WriteFrame(pw, Frame{ID: 42, Action: ActionData, Payload: []byte("hello world")}); err != nil {
		t.Fatalf("WriteFrame via partial writer: %v", err)
	}
	got, err := ReadFrame(bytes.NewReader(pw.buf), 0)
	if err != nil {
		t.Fatalf("ReadFrame after partial write: %v", err)
	}
	if string(got.Payload) != "hello world" || got.ID != 42 {
		t.Errorf("round-trip via partial writer: %+v", got)
	}
}

// zero-write causes ErrShortWrite
type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteFull_ZeroWriter(t *testing.T) {
	if err := WriteFrame(zeroWriter{}, Frame{ID: 1, Action: ActionClose}); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("zero writer: got %v, want io.ErrShortWrite", err)
	}
}

// ---------------------------------------------------------------
// DialHTTP — basic-auth credentials in URL
// ---------------------------------------------------------------

type upgradeServerWithAuth struct {
	ln      net.Listener
	gotAuth string
}

func newUpgradeServerWithAuth(t *testing.T) *upgradeServerWithAuth {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &upgradeServerWithAuth{ln: ln}
	go func() {
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				for _, line := range strings.Split(req, "\r\n") {
					if strings.HasPrefix(line, "Proxy-Authorization: ") {
						s.gotAuth = strings.TrimPrefix(line, "Proxy-Authorization: ")
					}
				}
				_, _ = fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: uwg-socket/1\r\nConnection: Upgrade\r\n\r\n")
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func TestDialHTTP_BasicAuthInURL(t *testing.T) {
	s := newUpgradeServerWithAuth(t)
	addr := s.ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialHTTP(ctx, "http://alice:secret@"+addr, "", "/v1/socket")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()

	if !strings.HasPrefix(s.gotAuth, "Basic ") {
		t.Errorf("expected Basic auth header, got: %q", s.gotAuth)
	}
}

// ---------------------------------------------------------------
// AddrVersion — IPv4-mapped sanity
// ---------------------------------------------------------------

func TestAddrVersion_IPv4Mapped(t *testing.T) {
	// ::ffff:10.0.0.1 is stored as 16-byte in netip → Is6() is true.
	addr := netip.MustParseAddr("::ffff:10.0.0.1")
	if got := AddrVersion(addr); got != 6 {
		t.Errorf("AddrVersion(::ffff:10.0.0.1) = %d, want 6", got)
	}
	// Plain v4 → 4.
	if got := AddrVersion(netip.MustParseAddr("10.0.0.1")); got != 4 {
		t.Errorf("AddrVersion(10.0.0.1) = %d, want 4", got)
	}
}

// ---------------------------------------------------------------
// parseAddr — all-zero bytes per version
// ---------------------------------------------------------------

func TestParseAddr_ZeroBytes(t *testing.T) {
	if parseAddr(make([]byte, 4), 4).IsValid() {
		t.Error("all-zero v4 should be invalid addr")
	}
	if parseAddr(make([]byte, 16), 6).IsValid() {
		t.Error("all-zero v6 should be invalid addr")
	}
	v4 := []byte{10, 0, 0, 1}
	if a := parseAddr(v4, 4); a.String() != "10.0.0.1" {
		t.Errorf("v4 parseAddr = %v", a)
	}
}
