// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package config

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------
// ParsePortRange
// ---------------------------------------------------------------

func TestParsePortRange(t *testing.T) {
	type want struct {
		start, end int
		errFrag    string
	}
	cases := []struct {
		in   string
		want want
	}{
		// single-port happy path
		{in: "1", want: want{start: 1, end: 1}},
		{in: "80", want: want{start: 80, end: 80}},
		{in: "65535", want: want{start: 65535, end: 65535}},
		// range happy path
		{in: "1-65535", want: want{start: 1, end: 65535}},
		{in: "40000-41000", want: want{start: 40000, end: 41000}},
		{in: "1024 - 1025", want: want{start: 1024, end: 1025}}, // spaces allowed
		// errors
		{in: "", want: want{errFrag: "empty"}},
		{in: "0", want: want{errFrag: "1 and 65535"}},
		{in: "65536", want: want{errFrag: "1 and 65535"}},
		{in: "abc", want: want{errFrag: "invalid port"}},
		{in: "0-100", want: want{errFrag: "1 and 65535"}},
		{in: "100-66000", want: want{errFrag: "1 and 65535"}},
		{in: "1000-999", want: want{errFrag: "must be <="}},
		{in: "abc-def", want: want{errFrag: "invalid start"}},
		{in: "100-abc", want: want{errFrag: "invalid end"}},
	}
	for _, tc := range cases {
		s, e, err := ParsePortRange(tc.in)
		if tc.want.errFrag != "" {
			if err == nil || !strings.Contains(err.Error(), tc.want.errFrag) {
				t.Errorf("ParsePortRange(%q) err=%v, want fragment %q", tc.in, err, tc.want.errFrag)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortRange(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if s != tc.want.start || e != tc.want.end {
			t.Errorf("ParsePortRange(%q) = (%d,%d), want (%d,%d)", tc.in, s, e, tc.want.start, tc.want.end)
		}
	}
}

// ---------------------------------------------------------------
// splitTaggedScheme
// ---------------------------------------------------------------

func TestSplitTaggedScheme(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{in: "", want: nil},
		{in: "udp", want: []string{"udp"}},
		{in: "TURNS", want: []string{"turns"}}, // special-cased before split
		{in: "turn+tls", want: []string{"turn", "tls"}},
		{in: "turn+wss", want: []string{"turn", "wss"}},
		{in: "http+raw", want: []string{"http", "raw"}},
		{in: "quic+ws", want: []string{"quic", "ws"}},
		// extra spaces are trimmed per-part
		{in: "http + raw", want: []string{"http", "raw"}},
	}
	for _, tc := range cases {
		got := splitTaggedScheme(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitTaggedScheme(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("splitTaggedScheme(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// ---------------------------------------------------------------
// decodeTURNSchemeTags
// ---------------------------------------------------------------

func TestDecodeTURNSchemeTags_Valid(t *testing.T) {
	cases := []struct {
		name        string
		tags        []string
		wantProto   string
		wantUpgrade string
	}{
		{name: "empty→udp", tags: nil, wantProto: "udp"},
		{name: "turn-only→udp", tags: []string{"turn"}, wantProto: "udp"},
		{name: "tls", tags: []string{"turn", "tls"}, wantProto: "tls"},
		{name: "turns→tls", tags: []string{"turns"}, wantProto: "tls"},
		{name: "tcp", tags: []string{"turn", "tcp"}, wantProto: "tcp"},
		{name: "dtls", tags: []string{"turn", "dtls"}, wantProto: "dtls"},
		{name: "http→ws", tags: []string{"turn", "http"}, wantProto: "http", wantUpgrade: "websocket"},
		{name: "https→ws", tags: []string{"turn", "https"}, wantProto: "https", wantUpgrade: "websocket"},
		{name: "quic", tags: []string{"turn", "quic"}, wantProto: "quic"},
		{name: "ws→http+ws", tags: []string{"turn", "ws"}, wantProto: "http", wantUpgrade: "websocket"},
		{name: "wss→https+ws", tags: []string{"turn", "wss"}, wantProto: "https", wantUpgrade: "websocket"},
		{name: "raw→http+raw", tags: []string{"turn", "raw"}, wantProto: "http", wantUpgrade: "proxyguard"},
		{name: "http+raw→proxyguard", tags: []string{"turn", "http", "raw"}, wantProto: "http", wantUpgrade: "proxyguard"},
		{name: "https+raw→proxyguard", tags: []string{"turn", "https", "raw"}, wantProto: "https", wantUpgrade: "proxyguard"},
		{name: "https+ws→websocket", tags: []string{"turn", "https", "ws"}, wantProto: "https", wantUpgrade: "websocket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proto, upgrade, err := decodeTURNSchemeTags(tc.tags)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if proto != tc.wantProto {
				t.Errorf("proto = %q, want %q", proto, tc.wantProto)
			}
			if upgrade != tc.wantUpgrade {
				t.Errorf("upgradeMode = %q, want %q", upgrade, tc.wantUpgrade)
			}
		})
	}
}

func TestDecodeTURNSchemeTags_Errors(t *testing.T) {
	cases := []struct {
		name    string
		tags    []string
		errFrag string
	}{
		{name: "unknown-tag", tags: []string{"turn", "grpc"}, errFrag: "unsupported TURN scheme tag"},
		{name: "conflict-proto", tags: []string{"turn", "tcp", "tls"}, errFrag: "conflicting"},
		{name: "wss-without-https", tags: []string{"turn", "wss", "tcp"}, errFrag: "wss requires https"},
		{name: "ws-on-tls", tags: []string{"turn", "ws", "tls"}, errFrag: "require http or https"},
		{name: "raw-on-tls", tags: []string{"turn", "raw", "tls"}, errFrag: "require http or https"},
		{name: "wss-on-http", tags: []string{"turn", "wss", "http"}, errFrag: "wss requires https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := decodeTURNSchemeTags(tc.tags)
			if err == nil || !strings.Contains(err.Error(), tc.errFrag) {
				t.Errorf("err=%v, want fragment %q", err, tc.errFrag)
			}
		})
	}
}

// ---------------------------------------------------------------
// decodePeerEndpointBase
// ---------------------------------------------------------------

func TestDecodePeerEndpointBase_Valid(t *testing.T) {
	cases := []struct {
		name        string
		tags        []string
		wantBase    string
		wantUpgrade string
		wantScheme  string
	}{
		{name: "empty→udp", tags: nil, wantBase: "udp"},
		{name: "udp", tags: []string{"udp"}, wantBase: "udp"},
		{name: "tcp", tags: []string{"tcp"}, wantBase: "tcp"},
		{name: "tls", tags: []string{"tls"}, wantBase: "tls"},
		{name: "dtls", tags: []string{"dtls"}, wantBase: "dtls"},
		{name: "http→ws", tags: []string{"http"}, wantBase: "http", wantUpgrade: "websocket"},
		{name: "http+raw→proxyguard", tags: []string{"http", "raw"}, wantBase: "http", wantUpgrade: "proxyguard"},
		{name: "https→url", tags: []string{"https"}, wantBase: "url", wantScheme: "https"},
		{name: "https+raw→proxyguard", tags: []string{"https", "raw"}, wantBase: "https", wantUpgrade: "proxyguard"},
		{name: "https+ws→websocket", tags: []string{"https", "ws"}, wantBase: "https", wantUpgrade: "websocket"},
		{name: "https+wss→websocket", tags: []string{"https", "wss"}, wantBase: "https", wantUpgrade: "websocket"},
		{name: "quic", tags: []string{"quic"}, wantBase: "quic"},
		{name: "quic+ws→quic-ws", tags: []string{"quic", "ws"}, wantBase: "quic-ws"},
		{name: "ws→http+ws", tags: []string{"ws"}, wantBase: "http", wantUpgrade: "websocket"},
		{name: "wss→https+ws", tags: []string{"wss"}, wantBase: "https", wantUpgrade: "websocket"},
		{name: "raw→http+proxyguard", tags: []string{"raw"}, wantBase: "http", wantUpgrade: "proxyguard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, upgrade, scheme, err := decodePeerEndpointBase(tc.tags)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if base != tc.wantBase {
				t.Errorf("base = %q, want %q", base, tc.wantBase)
			}
			if upgrade != tc.wantUpgrade {
				t.Errorf("upgradeMode = %q, want %q", upgrade, tc.wantUpgrade)
			}
			if scheme != tc.wantScheme {
				t.Errorf("urlScheme = %q, want %q", scheme, tc.wantScheme)
			}
		})
	}
}

func TestDecodePeerEndpointBase_Errors(t *testing.T) {
	cases := []struct {
		name    string
		tags    []string
		errFrag string
	}{
		{name: "unknown-tag", tags: []string{"grpc"}, errFrag: "unsupported endpoint scheme tag"},
		{name: "conflict-proto", tags: []string{"tcp", "tls"}, errFrag: "conflicting"},
		{name: "wss-without-https", tags: []string{"wss", "tcp"}, errFrag: "wss requires https"},
		{name: "ws-on-tcp", tags: []string{"tcp", "ws"}, errFrag: "require http"},
		{name: "raw-on-tls", tags: []string{"tls", "raw"}, errFrag: "require http"},
		{name: "raw-on-quic", tags: []string{"quic", "raw"}, errFrag: "not supported for quic"},
		{name: "wss-on-http", tags: []string{"http", "wss"}, errFrag: "wss requires https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := decodePeerEndpointBase(tc.tags)
			if err == nil || !strings.Contains(err.Error(), tc.errFrag) {
				t.Errorf("err=%v, want fragment %q", err, tc.errFrag)
			}
		})
	}
}

// ---------------------------------------------------------------
// taggedEndpointHostPort — default port per base
// ---------------------------------------------------------------

func TestTaggedEndpointHostPort_DefaultPorts(t *testing.T) {
	cases := []struct {
		host     string
		base     string
		wantPort string
	}{
		{"example.com", "http", "80"},
		{"example.com", "https", "443"},
		{"example.com", "quic", "443"},
		{"example.com", "quic-ws", "443"},
		{"example.com", "url", "443"},
		{"example.com", "udp", "51820"},
		{"example.com", "tcp", "51820"},
		{"example.com", "tls", "51820"},
		{"example.com", "dtls", "51820"},
		// existing host:port must be returned unchanged
		{"example.com:12345", "http", "12345"},
	}
	for _, tc := range cases {
		u, _, _ := parseTaggedURL("http://" + tc.host + "/path")
		if u == nil {
			t.Fatalf("parseTaggedURL failed for %q", tc.host)
		}
		u.Host = tc.host // override with raw host for the non-URL cases
		got, err := taggedEndpointHostPort(u, tc.base)
		if err != nil {
			t.Errorf("host=%q base=%q: unexpected error %v", tc.host, tc.base, err)
			continue
		}
		_, port, _ := strings.Cut(got, ":")
		if port != tc.wantPort {
			t.Errorf("host=%q base=%q: got port %q, want %q (full=%q)", tc.host, tc.base, port, tc.wantPort, got)
		}
	}
}

func TestTaggedEndpointHostPort_MissingHost(t *testing.T) {
	u, _, _ := parseTaggedURL("http://example.com/")
	if u == nil {
		t.Fatal("parseTaggedURL returned nil")
	}
	u.Host = ""
	if _, err := taggedEndpointHostPort(u, "tcp"); err == nil {
		t.Error("expected error for missing host")
	}
}

// ---------------------------------------------------------------
// normalizeTaggedPath
// ---------------------------------------------------------------

func TestNormalizeTaggedPath(t *testing.T) {
	cases := []struct {
		path, def, want string
	}{
		{"", "/turn", "/turn"},
		{"   ", "/turn", "/turn"},
		{"/foo", "/turn", "/foo"},
		{"foo", "/turn", "/foo"},
		{"/foo/bar", "/turn", "/foo/bar"},
		{"/", "/turn", "/"},
	}
	for _, tc := range cases {
		got := normalizeTaggedPath(tc.path, tc.def)
		if got != tc.want {
			t.Errorf("normalizeTaggedPath(%q, %q) = %q, want %q", tc.path, tc.def, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------
// ParseForwardArg error branches
// ---------------------------------------------------------------

func TestParseForwardArg_Errors(t *testing.T) {
	cases := []struct {
		in      string
		errFrag string
	}{
		{in: "127.0.0.1:8080", errFrag: "must be proto"},    // no "="
		{in: "ftp://127.0.0.1:8080=target:80", errFrag: "proto must be"},
		{in: "tcp://127.0.0.1:8080=target:80,badopt", errFrag: "invalid forward option"},
		{in: "tcp://127.0.0.1:8080=target:80,unknown_key=v", errFrag: "unknown forward option"},
		{in: "udp://127.0.0.1:5353=target:53,allow_unnamed_dgram=notbool", errFrag: "invalid allow_unnamed_dgram"},
		{in: "udp://127.0.0.1:5353=target:53,frame_bytes=xyz", errFrag: "invalid frame_bytes"},
		{in: "tcp://127.0.0.1:8080=target:80,proxy_protocol=v3", errFrag: "proxy_protocol must be v1"},
		{in: "udp://127.0.0.1:5353=target:53,proxy_protocol=v1", errFrag: "UDP forward proxy_protocol requires v2"},
	}
	for _, tc := range cases {
		if _, err := ParseForwardArg(tc.in); err == nil || !strings.Contains(err.Error(), tc.errFrag) {
			t.Errorf("ParseForwardArg(%q) err=%v, want fragment %q", tc.in, err, tc.errFrag)
		}
	}
}

// ---------------------------------------------------------------
// ParsePeerArg — key aliases and error paths
// ---------------------------------------------------------------

func TestParsePeerArg_KeyAliases(t *testing.T) {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	aliases := []string{
		"public=" + key,
		"publickey=" + key,
		"public_key=" + key,
	}
	for _, alias := range aliases {
		p, err := ParsePeerArg(alias)
		if err != nil {
			t.Errorf("ParsePeerArg(%q) error: %v", alias, err)
			continue
		}
		if p.PublicKey != key {
			t.Errorf("ParsePeerArg(%q) PublicKey=%q", alias, p.PublicKey)
		}
	}
}

func TestParsePeerArg_Errors(t *testing.T) {
	cases := []struct {
		in      string
		errFrag string
	}{
		{in: "noequal", errFrag: "key=value"},
		{in: "unknown_field=foo", errFrag: "unknown peer field"},
		{in: "keepalive=-1", errFrag: "invalid keepalive"},
		{in: "keepalive=notanumber", errFrag: "invalid keepalive"},
		{in: "upload_bps=-1", errFrag: "invalid upload_bps"},
		{in: "upload_bps=x", errFrag: "invalid upload_bps"},
		{in: "download_bps=-100", errFrag: "invalid download_bps"},
		{in: "latency_ms=-5", errFrag: "invalid latency_ms"},
	}
	for _, tc := range cases {
		if _, err := ParsePeerArg(tc.in); err == nil || !strings.Contains(err.Error(), tc.errFrag) {
			t.Errorf("ParsePeerArg(%q) err=%v, want fragment %q", tc.in, err, tc.errFrag)
		}
	}
}

// ---------------------------------------------------------------
// ParseOutboundProxyArg — bare address and option errors
// ---------------------------------------------------------------

func TestParseOutboundProxyArg_BareAddress(t *testing.T) {
	p, err := ParseOutboundProxyArg("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Type != "socks5" || p.Address != "127.0.0.1:1080" {
		t.Errorf("got type=%q addr=%q", p.Type, p.Address)
	}
}

func TestParseOutboundProxyArg_Errors(t *testing.T) {
	cases := []struct {
		in      string
		errFrag string
	}{
		{in: "http://127.0.0.1:3128;badopt", errFrag: "invalid outbound proxy option"},
		{in: "http://127.0.0.1:3128;unknown_key=v", errFrag: "unknown outbound proxy option"},
	}
	for _, tc := range cases {
		if _, err := ParseOutboundProxyArg(tc.in); err == nil || !strings.Contains(err.Error(), tc.errFrag) {
			t.Errorf("ParseOutboundProxyArg(%q) err=%v, want fragment %q", tc.in, err, tc.errFrag)
		}
	}
}

// ---------------------------------------------------------------
// MergeWGQuick — strict mode rejects unknown keys
// ---------------------------------------------------------------

// testWGKey is a syntactically valid base64 key string (32 bytes).
// setInterface stores it verbatim without validation; Normalize is not
// called in these tests so the clamping requirement does not apply.
const testWGKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestMergeWGQuickStrict_UnknownKey(t *testing.T) {
	text := "[Interface]\nPrivateKey = " + testWGKey + "\nFakeKey = bad\n"
	var wg WireGuard
	if err := MergeWGQuickStrict(&wg, text); err == nil {
		t.Error("strict mode should reject unknown interface keys")
	}
}

func TestMergeWGQuick_UnknownKeyAlsoRejected(t *testing.T) {
	// Both strict and non-strict reject unknown keys; strict additionally
	// silently drops hook lines (PreUp/PostUp/PreDown/PostDown) rather
	// than forwarding them to setInterface.
	text := "[Interface]\nPrivateKey = " + testWGKey + "\nFakeKey = ignored\n"
	var wg WireGuard
	if err := MergeWGQuick(&wg, text); err == nil {
		t.Error("non-strict mode should also reject unknown interface keys")
	}
}

func TestMergeWGQuickStrict_DropsHookKeys(t *testing.T) {
	// In strict mode the four hook keys are silently dropped rather than
	// passed to setInterface (which would reject them as unknown).
	text := "[Interface]\nPrivateKey = " + testWGKey + "\nPostUp = echo up\n"
	var wgStrict WireGuard
	if err := MergeWGQuickStrict(&wgStrict, text); err != nil {
		t.Fatalf("strict mode should silently drop PostUp, got: %v", err)
	}
	// non-strict accepts and stores it
	var wgNormal WireGuard
	if err := MergeWGQuick(&wgNormal, text); err != nil {
		t.Fatalf("non-strict mode should accept PostUp, got: %v", err)
	}
	if len(wgNormal.PostUp) != 1 || wgNormal.PostUp[0] != "echo up" {
		t.Errorf("non-strict mode PostUp not stored: %v", wgNormal.PostUp)
	}
	if len(wgStrict.PostUp) != 0 {
		t.Errorf("strict mode should not store PostUp, got: %v", wgStrict.PostUp)
	}
}

// ---------------------------------------------------------------
// Normalize — remaining validation branches
// ---------------------------------------------------------------

func TestNormalize_InvalidRoamFallback(t *testing.T) {
	cfg := Default()
	cfg.WireGuard.RoamFallbackSeconds = -1
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "roam_fallback_seconds") {
		t.Errorf("Normalize err=%v, want roam_fallback_seconds rejection", err)
	}
}

func TestNormalize_InvalidUDPAssociatePorts(t *testing.T) {
	cfg := Default()
	cfg.Proxy.UDPAssociatePorts = "bad-range"
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "udp_associate_ports") {
		t.Errorf("Normalize err=%v, want udp_associate_ports rejection", err)
	}
}

func TestNormalize_InvalidHTTPSProxyVerify(t *testing.T) {
	cfg := Default()
	cfg.Proxy.HTTPSProxyVerify = "invalid-mode"
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "https_proxy_verify") {
		t.Errorf("Normalize err=%v, want https_proxy_verify rejection", err)
	}
}

func TestNormalize_BadListenAddress(t *testing.T) {
	cfg := Default()
	cfg.WireGuard.ListenAddresses = []string{"not-an-ip"}
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "listen_addresses") {
		t.Errorf("Normalize err=%v, want listen_addresses rejection", err)
	}
}

func TestNormalize_ForwardBadProto(t *testing.T) {
	cfg := Default()
	cfg.Forwards = []Forward{{Proto: "ftp", Listen: "127.0.0.1:8080", Target: "10.0.0.1:80"}}
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "proto") {
		t.Errorf("Normalize err=%v, want forward proto rejection", err)
	}
}

func TestNormalize_ForwardMissingTarget(t *testing.T) {
	cfg := Default()
	cfg.Forwards = []Forward{{Proto: "tcp", Listen: "127.0.0.1:8080"}}
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("Normalize err=%v, want forward required-field rejection", err)
	}
}

func TestNormalize_ForwardBadProxyProtocol(t *testing.T) {
	cfg := Default()
	cfg.Forwards = []Forward{{Proto: "tcp", Listen: "127.0.0.1:8080", Target: "10.0.0.1:80", ProxyProtocol: "v3"}}
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "proxy_protocol") {
		t.Errorf("Normalize err=%v, want proxy_protocol rejection", err)
	}
}

func TestNormalize_UDPForwardV1ProxyProtocol(t *testing.T) {
	cfg := Default()
	cfg.Forwards = []Forward{{Proto: "udp", Listen: "127.0.0.1:5353", Target: "10.0.0.1:53", ProxyProtocol: "v1"}}
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Errorf("Normalize err=%v, want UDP proxy_protocol rejection", err)
	}
}

// ---------------------------------------------------------------
// AddressAddrs / AddressPrefixes
// ---------------------------------------------------------------

func TestAddressAddrs(t *testing.T) {
	addrs, err := AddressAddrs([]string{"100.64.0.1/32", "fd00::1/128", "10.0.0.1"})
	if err != nil {
		t.Fatalf("AddressAddrs: %v", err)
	}
	if len(addrs) != 3 {
		t.Fatalf("expected 3 addrs, got %d", len(addrs))
	}
	if _, err := AddressAddrs([]string{"not-an-addr"}); err == nil {
		t.Error("AddressAddrs should reject invalid address")
	}
}

func TestAddressPrefixes(t *testing.T) {
	pfxs, err := AddressPrefixes([]string{"100.64.0.0/10", "fd00::/48"})
	if err != nil {
		t.Fatalf("AddressPrefixes: %v", err)
	}
	if len(pfxs) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(pfxs))
	}
	if _, err := AddressPrefixes([]string{"not-a-prefix"}); err == nil {
		t.Error("AddressPrefixes should reject invalid prefix")
	}
}
