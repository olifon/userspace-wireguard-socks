// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package socketproto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------
// Frame round-trip
// ---------------------------------------------------------------

func TestFrame_RoundTrip(t *testing.T) {
	cases := []Frame{
		{ID: 0, Action: ActionConnect, Flags: 0, Payload: nil},
		{ID: 1, Action: ActionConnect, Flags: 0, Payload: []byte{}},
		{ID: 12345, Action: ActionData, Flags: 0xCAFE, Payload: []byte("hello world")},
		// Boundary: payload exactly DefaultMaxPayload (1MiB).
		{ID: ClientIDBase + 7, Action: ActionUDPDatagram, Flags: 0,
			Payload: bytes.Repeat([]byte{0xAB}, DefaultMaxPayload)},
	}
	for i, in := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, in); err != nil {
			t.Fatalf("[%d] WriteFrame: %v", i, err)
		}
		out, err := ReadFrame(&buf, 0) // 0 → DefaultMaxPayload
		if err != nil {
			t.Fatalf("[%d] ReadFrame: %v", i, err)
		}
		if out.ID != in.ID || out.Action != in.Action || out.Flags != in.Flags {
			t.Errorf("[%d] header mismatch: got %+v want %+v", i,
				Frame{ID: out.ID, Action: out.Action, Flags: out.Flags},
				Frame{ID: in.ID, Action: in.Action, Flags: in.Flags})
		}
		if !bytes.Equal(out.Payload, in.Payload) {
			t.Errorf("[%d] payload mismatch: got %d bytes, want %d", i, len(out.Payload), len(in.Payload))
		}
	}
}

func TestFrame_WriteTooLarge(t *testing.T) {
	var buf bytes.Buffer
	huge := bytes.Repeat([]byte{1}, DefaultMaxPayload+1)
	err := WriteFrame(&buf, Frame{Action: ActionData, Payload: huge})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversize Write: want ErrFrameTooLarge, got %v", err)
	}
}

func TestFrame_ReadTooLarge(t *testing.T) {
	// Construct a header claiming a payload larger than the
	// caller's max. Reader must reject before allocating.
	var hdr [HeaderLen]byte
	hdr[15] = 16 // n=16 in the low byte (BigEndian Uint32 at [12:16])
	r := bytes.NewReader(hdr[:])
	if _, err := ReadFrame(r, 8); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("over-max Read: want ErrFrameTooLarge, got %v", err)
	}
}

func TestFrame_ReadTruncated(t *testing.T) {
	// Header truncated mid-stream.
	r := bytes.NewReader([]byte{1, 2, 3})
	if _, err := ReadFrame(r, 0); err == nil {
		t.Errorf("truncated header: want error, got nil")
	}

	// Header fine, payload truncated.
	var buf bytes.Buffer
	_ = WriteFrame(&buf, Frame{Action: ActionData, Payload: []byte("abcdef")})
	full := buf.Bytes()
	short := full[:len(full)-2] // drop the last 2 bytes of payload
	if _, err := ReadFrame(bytes.NewReader(short), 0); err == nil {
		t.Errorf("truncated payload: want error, got nil")
	}
}

func TestFrame_ZeroPayloadDoesntReadFurther(t *testing.T) {
	// A header with payload-length 0 must not attempt to read any
	// extra bytes. Important for keep-alive / close frames.
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{ID: 99, Action: ActionClose, Flags: 0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if buf.Len() != HeaderLen {
		t.Errorf("zero-payload frame should be exactly %d bytes; got %d", HeaderLen, buf.Len())
	}
	out, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.Action != ActionClose || len(out.Payload) != 0 {
		t.Errorf("got %+v", out)
	}
}

// ---------------------------------------------------------------
// Connect encode/decode
// ---------------------------------------------------------------

func TestConnect_RoundTrip_v4(t *testing.T) {
	c := Connect{
		ListenerID: 12345,
		IPVersion:  4,
		Protocol:   ProtoTCP,
		BindIP:     netip.MustParseAddr("10.0.0.1"),
		BindPort:   40000,
		DestIP:     netip.MustParseAddr("100.64.0.1"),
		DestPort:   80,
	}
	b, err := EncodeConnect(c)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeConnect(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != c {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, c)
	}
}

func TestConnect_RoundTrip_v6(t *testing.T) {
	c := Connect{
		ListenerID: 1,
		IPVersion:  6,
		Protocol:   ProtoUDP,
		BindIP:     netip.MustParseAddr("fd00::1"),
		BindPort:   53,
		DestIP:     netip.MustParseAddr("fd00::abc"),
		DestPort:   53,
	}
	b, err := EncodeConnect(c)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeConnect(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != c {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, c)
	}
}

func TestConnect_ZeroAddrsDecodeAsInvalid(t *testing.T) {
	// Encoding all-zero IPs is valid (e.g. "no bind preference");
	// decoder should return an invalid netip.Addr for zero bytes.
	c := Connect{
		ListenerID: 7,
		IPVersion:  4,
		Protocol:   ProtoTCP,
		BindIP:     netip.Addr{}, // unset → all-zero on the wire
		BindPort:   0,
		DestIP:     netip.MustParseAddr("8.8.8.8"),
		DestPort:   53,
	}
	b, err := EncodeConnect(c)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeConnect(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.BindIP.IsValid() {
		t.Errorf("decoded BindIP should be invalid for all-zero bytes; got %v", got.BindIP)
	}
	if got.DestIP != c.DestIP {
		t.Errorf("DestIP mismatch: got %v, want %v", got.DestIP, c.DestIP)
	}
}

func TestConnect_BadInputs(t *testing.T) {
	// IPVersion neither 4 nor 6.
	if _, err := EncodeConnect(Connect{IPVersion: 3}); !errors.Is(err, ErrBadFrame) {
		t.Errorf("EncodeConnect bad version: got %v", err)
	}
	// Decode: short payload.
	if _, err := DecodeConnect([]byte{1, 2, 3}); !errors.Is(err, ErrBadFrame) {
		t.Errorf("short DecodeConnect: got %v", err)
	}
	// Decode: bad version field.
	short := make([]byte, 16)
	short[8] = 7 // bogus IPVersion
	if _, err := DecodeConnect(short); !errors.Is(err, ErrBadFrame) {
		t.Errorf("bad-version DecodeConnect: got %v", err)
	}
	// Decode: header OK, but length doesn't match (16 + 2*4 expected for v4).
	mismatched := make([]byte, 16+1)
	mismatched[8] = 4
	if _, err := DecodeConnect(mismatched); !errors.Is(err, ErrBadFrame) {
		t.Errorf("length-mismatch DecodeConnect: got %v", err)
	}
}

// ---------------------------------------------------------------
// Accept encode/decode
// ---------------------------------------------------------------

func TestAccept_RoundTrip(t *testing.T) {
	cases := []Accept{
		{IPVersion: 4, Protocol: ProtoTCP, BindIP: netip.MustParseAddr("10.0.0.1"), BindPort: 1234},
		{IPVersion: 6, Protocol: ProtoTCP, BindIP: netip.MustParseAddr("fd00::1"), BindPort: 1234},
		{IPVersion: 4, Protocol: ProtoUDP, BindIP: netip.Addr{}, BindPort: 0}, // zeros
	}
	for i, in := range cases {
		b, err := EncodeAccept(in)
		if err != nil {
			t.Fatalf("[%d] encode: %v", i, err)
		}
		out, err := DecodeAccept(b)
		if err != nil {
			t.Fatalf("[%d] decode: %v", i, err)
		}
		if out.IPVersion != in.IPVersion || out.Protocol != in.Protocol || out.BindPort != in.BindPort {
			t.Errorf("[%d] header mismatch: got %+v want %+v", i, out, in)
		}
		if in.BindIP.IsValid() && out.BindIP != in.BindIP {
			t.Errorf("[%d] BindIP mismatch: got %v, want %v", i, out.BindIP, in.BindIP)
		}
		if !in.BindIP.IsValid() && out.BindIP.IsValid() {
			t.Errorf("[%d] BindIP should be invalid for all-zero bytes; got %v", i, out.BindIP)
		}
	}
}

func TestAccept_BadInputs(t *testing.T) {
	if _, err := EncodeAccept(Accept{IPVersion: 99}); !errors.Is(err, ErrBadFrame) {
		t.Errorf("encode bad version: got %v", err)
	}
	if _, err := DecodeAccept([]byte{1}); !errors.Is(err, ErrBadFrame) {
		t.Errorf("short decode: got %v", err)
	}
}

// ---------------------------------------------------------------
// UDPDatagram encode/decode
// ---------------------------------------------------------------

func TestUDPDatagram_RoundTrip(t *testing.T) {
	cases := []UDPDatagram{
		{IPVersion: 4, RemoteIP: netip.MustParseAddr("8.8.8.8"), RemotePort: 53, Payload: []byte("query")},
		{IPVersion: 4, RemoteIP: netip.MustParseAddr("1.1.1.1"), RemotePort: 53, Payload: nil},
		{IPVersion: 6, RemoteIP: netip.MustParseAddr("2606:4700:4700::1111"), RemotePort: 53,
			Payload: bytes.Repeat([]byte("x"), 1500)},
	}
	for i, in := range cases {
		b, err := EncodeUDPDatagram(in)
		if err != nil {
			t.Fatalf("[%d] encode: %v", i, err)
		}
		out, err := DecodeUDPDatagram(b)
		if err != nil {
			t.Fatalf("[%d] decode: %v", i, err)
		}
		if out.IPVersion != in.IPVersion || out.RemotePort != in.RemotePort || out.RemoteIP != in.RemoteIP {
			t.Errorf("[%d] header mismatch", i)
		}
		if !bytes.Equal(out.Payload, in.Payload) {
			t.Errorf("[%d] payload mismatch: got %d bytes, want %d", i, len(out.Payload), len(in.Payload))
		}
	}
}

func TestUDPDatagram_DecodeShort(t *testing.T) {
	if _, err := DecodeUDPDatagram(nil); !errors.Is(err, ErrBadFrame) {
		t.Errorf("decode empty: got %v", err)
	}
	if _, err := DecodeUDPDatagram([]byte{1, 2, 3}); !errors.Is(err, ErrBadFrame) {
		t.Errorf("decode 3-byte: got %v", err)
	}
	// Header OK but missing IP bytes for v4.
	short := []byte{4, 0, 0, 53} // IPVersion=4, _, port hi, port lo
	if _, err := DecodeUDPDatagram(short); !errors.Is(err, ErrBadFrame) {
		t.Errorf("decode pre-IP: got %v", err)
	}
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

func TestAddrVersion(t *testing.T) {
	cases := []struct {
		in   string
		want uint8
	}{
		{"10.0.0.1", 4},
		{"100.64.0.0", 4},
		{"fd00::1", 6},
		{"::1", 6},
		// IPv4-mapped IPv6 addresses are reported by netip as Is6()
		// (because the underlying storage is the 16-byte form).
		{"::ffff:10.0.0.1", 6},
	}
	for _, c := range cases {
		got := AddrVersion(netip.MustParseAddr(c.in))
		if got != c.want {
			t.Errorf("AddrVersion(%q) = %d; want %d", c.in, got, c.want)
		}
	}
}

func TestAddrPort_InvalidGivesZero(t *testing.T) {
	if got := AddrPort(netip.Addr{}, 80); got.IsValid() {
		t.Errorf("AddrPort(invalid, 80) should be invalid; got %v", got)
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 80)
	if got := AddrPort(netip.MustParseAddr("10.0.0.1"), 80); got != want {
		t.Errorf("AddrPort got %v want %v", got, want)
	}
}

// ---------------------------------------------------------------
// DialHTTP — exercises the upgrade handshake against a tiny test
// server that speaks the protocol's switching-protocols dance.
// ---------------------------------------------------------------

func startUpgradeServer(t *testing.T, listener net.Listener, customStatus int) {
	t.Helper()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the HTTP request line + headers.
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				if customStatus != 0 && customStatus != http.StatusSwitchingProtocols {
					_, _ = fmt.Fprintf(c, "HTTP/1.1 %d Bad\r\nContent-Length: 0\r\n\r\n", customStatus)
					return
				}
				// Switching Protocols + immediately echo a frame
				// so the client side can verify upgrade succeeded.
				_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: uwg-socket/1\r\nConnection: Upgrade\r\n\r\n"))
				// Send a small frame back so the BufferedConn
				// path is exercised when the server's response
				// was buffered along with the upgrade headers.
				_ = WriteFrame(c, Frame{ID: 42, Action: ActionData, Payload: []byte("hi")})
			}(c)
		}
	}()
}

func TestDialHTTP_UnixSuccess(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix listen: %v", err)
	}
	defer ln.Close()
	startUpgradeServer(t, ln, http.StatusSwitchingProtocols)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialHTTP(ctx, "unix:"+sockPath, "", "/v1/socket")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// The server's response continues with a frame; verify we
	// can read it (BufferedConn path).
	f, err := ReadFrame(c, 0)
	if err != nil {
		t.Fatalf("read frame from server: %v", err)
	}
	if string(f.Payload) != "hi" {
		t.Errorf("frame payload = %q; want %q", string(f.Payload), "hi")
	}
}

func TestDialHTTP_TCPSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	startUpgradeServer(t, ln, http.StatusSwitchingProtocols)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialHTTP(ctx, "http://"+ln.Addr().String(), "demo-token", "/uwg/socket")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	f, err := ReadFrame(c, 0)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	_ = f
}

func TestDialHTTP_UnsupportedScheme(t *testing.T) {
	_, err := DialHTTP(context.Background(), "https://localhost:1234", "", "")
	if err == nil {
		t.Errorf("https:// scheme should be rejected")
	} else if !strings.Contains(err.Error(), "http or unix") {
		t.Errorf("error message should mention http/unix; got %q", err.Error())
	}
}

func TestDialHTTP_NonUpgradeStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Server returns 200 OK instead of 101 Switching Protocols.
	startUpgradeServer(t, ln, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := DialHTTP(ctx, "http://"+ln.Addr().String(), "", ""); err == nil {
		t.Errorf("non-101 response should error")
	} else if !strings.Contains(err.Error(), "upgrade returned") {
		t.Errorf("error should mention 'upgrade returned'; got %q", err.Error())
	}
}

func TestDialHTTP_ContextDeadline(t *testing.T) {
	// Listener that never accepts; dial should hit the context
	// deadline and return.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// Don't accept — but the OS still does the SYN/ACK; the
	// upgrade-response read will block, hit the deadline.
	if _, err := DialHTTP(ctx, "http://"+ln.Addr().String(), "", ""); err == nil {
		t.Errorf("expected timeout error; got nil")
	}
}

// ---------------------------------------------------------------
// BufferedConn: Read drains the bufio buffer first.
// ---------------------------------------------------------------

type rwcMock struct{ io.Reader }

func (rwcMock) Write(p []byte) (int, error)        { return len(p), nil }
func (rwcMock) Close() error                       { return nil }
func (rwcMock) LocalAddr() net.Addr                { return nil }
func (rwcMock) RemoteAddr() net.Addr               { return nil }
func (rwcMock) SetDeadline(time.Time) error        { return nil }
func (rwcMock) SetReadDeadline(time.Time) error    { return nil }
func (rwcMock) SetWriteDeadline(time.Time) error   { return nil }

func TestBufferedConn_DrainsBuffer(t *testing.T) {
	// We can't easily construct a real BufferedConn without a
	// real net.Conn, but we can test the wrapper's Read delegates
	// to the bufio.Reader. Construct manually.
	src := bytes.NewReader([]byte("buffered-bytes"))
	conn := &BufferedConn{
		Conn:   nil, // not exercised in this test
		Reader: bufio.NewReader(src),
	}
	out := make([]byte, 14)
	n, err := conn.Read(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out[:n]) != "buffered-bytes" {
		t.Errorf("got %q; want %q", string(out[:n]), "buffered-bytes")
	}
}
