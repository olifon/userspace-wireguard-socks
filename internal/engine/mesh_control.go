// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	meshTokenVersionV1     = 1
	meshTokenVersionV2     = 2
	meshAuthContextLabel   = "uwgsocks-mesh-auth"
	meshBodyContextLabel   = "uwgsocks-mesh-body"
	meshChallengeBodyLimit = 4 << 10
	meshDynamicPeerLimit   = 1024
)

type meshChallengeResponse struct {
	ServerPublicKey    string `json:"server_public_key"`
	ChallengePublicKey string `json:"challenge_public_key"`
	TokenVersion       uint8  `json:"token_version,omitempty"`
	ExpiresUnix        int64  `json:"expires_unix"`
}

type meshDiscoveredPeer struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	PSK        string   `json:"psk,omitempty"`
	MeshAccept bool     `json:"mesh_accept_acls,omitempty"`
	MeshTrust  string   `json:"mesh_trust,omitempty"`
	// Type describes the P2P role declared by this peer via POST /v1/p2p.
	// Values: "client", "p2p-maybe", "p2p", "remote". Empty is "p2p-maybe".
	Type string `json:"type,omitempty"`
}

type meshACLResponse struct {
	Default  acl.Action `json:"default"`
	Inbound  []acl.Rule `json:"inbound,omitempty"`
	Outbound []acl.Rule `json:"outbound,omitempty"`
}

// meshNetsResponse carries the IP prefixes the mesh control server has
// allocated to the requesting peer. The client uses these as the destination
// filter for packets received from dynamically discovered (P2P) peers.
type meshNetsResponse struct {
	Prefixes []string `json:"prefixes"`
}

type meshAuthResult struct {
	PeerPublicKey string
	PeerIndex     int
	SharedSecret  []byte
}

type dynamicPeer struct {
	Peer            config.Peer
	ParentPublicKey string
	Active          bool
	LastControl     time.Time
	// PeerType is the P2P role for this peer as reported by the mesh control
	// server. One of "client", "p2p-maybe", "p2p", "remote". Empty = "p2p-maybe".
	PeerType string
	// ActiveOnHandshake is the LastHandshakeTimeSec that triggered Active=true.
	// Prevents re-activation on the same stale handshake after a grace failure.
	ActiveOnHandshake int64
	// ActiveSince and GraceRxSnap track the confirmation window: once Active is
	// set, ReceiveBytes must grow before the next poll or the path is rejected.
	// ActiveSince is zeroed once the grace period is confirmed.
	ActiveSince time.Time
	GraceRxSnap uint64
	// LastRxGrow is the last time ReceiveBytes increased while Active. Used for
	// the 30s no-RX inactive condition.
	LastRxGrow time.Time
	// PrevTxSnap and PrevRxSnap are updated each poll for growth detection.
	PrevTxSnap uint64
	PrevRxSnap uint64
	// KeepaliveIP is the allocated address in keepaliveSubnet used to probe
	// this peer's direct path. Zero means none allocated or peer is "remote".
	KeepaliveIP netip.Addr
	// LastHubEndpoint is the endpoint most recently advertised by the
	// mesh-control server for this peer. When the server's view changes
	// (e.g. after a peer restarts on a new port), hub-endpoint tracking
	// lets applyMeshDiscoveredPeers distinguish "hub changed endpoint
	// (use new value)" from "hub endpoint unchanged (keep any override)".
	LastHubEndpoint string
}

type meshAuthenticator interface {
	Challenge(now time.Time) (meshChallengeResponse, error)
	Verify(r *http.Request) (meshAuthResult, error)
}

type meshChallengeState struct {
	priv    *ecdh.PrivateKey
	pub     []byte
	expires time.Time
}

type meshControlAuthenticator struct {
	e       *Engine
	curve   ecdh.Curve
	pubKey  wgtypes.Key
	privKey *ecdh.PrivateKey

	mu      sync.Mutex
	current meshChallengeState
	prev    meshChallengeState
}

func newMeshControlAuthenticator(e *Engine) (*meshControlAuthenticator, error) {
	pub, err := e.wgPublicKey()
	if err != nil {
		return nil, err
	}
	parsedPriv, err := wgtypes.ParseKey(e.cfg.WireGuard.PrivateKey)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(parsedPriv[:])
	if err != nil {
		return nil, err
	}
	return &meshControlAuthenticator{
		e:       e,
		curve:   ecdh.X25519(),
		pubKey:  wgtypes.Key(pub),
		privKey: priv,
	}, nil
}

func (a *meshControlAuthenticator) Challenge(now time.Time) (meshChallengeResponse, error) {
	state, _, err := a.challengeState(now)
	if err != nil {
		return meshChallengeResponse{}, err
	}
	return meshChallengeResponse{
		ServerPublicKey:    a.pubKey.String(),
		ChallengePublicKey: base64.StdEncoding.EncodeToString(state.pub),
		TokenVersion:       meshTokenVersionV2,
		ExpiresUnix:        state.expires.Unix(),
	}, nil
}

func (a *meshControlAuthenticator) Verify(r *http.Request) (meshAuthResult, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		return meshAuthResult{}, errors.New("missing bearer token")
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")))
	if err != nil {
		return meshAuthResult{}, errors.New("invalid bearer token encoding")
	}
	if len(token) < 1+32+32+24+16+32 {
		return meshAuthResult{}, errors.New("invalid bearer token length")
	}
	tokenVersion := token[0]
	// v1 tokens were superseded by v2 in early development. Challenge() only
	// ever issues v2 (see meshChallengeResponse.TokenVersion in Challenge),
	// so the v1 branch is dead — tighten the gate to v2-only and drop the
	// v1 verifier entirely below to remove a maintenance trap.
	if tokenVersion != meshTokenVersionV2 {
		return meshAuthResult{}, errors.New("unsupported bearer token version")
	}
	ephPub := token[1:33]
	quick := token[33:65]
	body := token[65 : len(token)-32]
	wantHash := token[len(token)-32:]

	addrBinding, err := meshAddrBindingFromRemote(r.RemoteAddr)
	if err != nil {
		return meshAuthResult{}, err
	}
	now := time.Now()
	states, serverPubBytes, err := a.challengeCandidates(now)
	if err != nil {
		return meshAuthResult{}, err
	}
	for _, state := range states {
		if subtle.ConstantTimeCompare(meshQuickCheck(serverPubBytes, state.pub, addrBinding), quick) != 1 {
			continue
		}
		res, err := a.verifyWithState(tokenVersion, state, ephPub, body, wantHash, addrBinding, r.RemoteAddr)
		if err == nil {
			return res, nil
		}
	}
	return meshAuthResult{}, errors.New("invalid bearer token")
}

func (a *meshControlAuthenticator) verifyWithState(tokenVersion byte, state meshChallengeState, ephPub, body, wantHash, addrBinding []byte, remote string) (meshAuthResult, error) {
	eph, err := a.curve.NewPublicKey(append([]byte(nil), ephPub...))
	if err != nil {
		return meshAuthResult{}, err
	}
	k1, err := state.priv.ECDH(eph)
	if err != nil {
		return meshAuthResult{}, err
	}
	// v2 binds the server static key into the auth key alongside the
	// challenge ephemeral so a future leak of the challenge ECDH does not on
	// its own forge tokens. v1 (which only used k1) is no longer accepted.
	_ = tokenVersion
	staticShared, err := a.privKey.ECDH(eph)
	if err != nil {
		return meshAuthResult{}, err
	}
	authKey := meshAuthKey(k1, staticShared)
	plain, err := meshOpen(body, authKey, meshAuthContextLabel)
	if err != nil {
		return meshAuthResult{}, err
	}
	if len(plain) != 32 {
		return meshAuthResult{}, errors.New("invalid mesh auth identity size")
	}
	peerKey := wgtypes.Key(plain)
	peer, idx, ok := a.e.meshPeerConfig(peerKey.String())
	if !ok || !peer.MeshEnabled {
		return meshAuthResult{}, errors.New("mesh peer not enabled")
	}
	src := addrFromNetAddr(mustResolveTCPAddr(remote))
	if !src.IsValid() || a.e.peerKeyForIP(src) != peer.PublicKey {
		return meshAuthResult{}, errors.New("mesh peer source mismatch")
	}
	peerPub, err := a.curve.NewPublicKey(plain)
	if err != nil {
		return meshAuthResult{}, err
	}
	k2, err := state.priv.ECDH(peerPub)
	if err != nil {
		return meshAuthResult{}, err
	}
	secret := meshSharedSecret(authKey, k2, meshPeerPSKBytes(peer), addrBinding)
	gotHash := sha256.Sum256(secret)
	if subtle.ConstantTimeCompare(gotHash[:], wantHash) != 1 {
		return meshAuthResult{}, errors.New("mesh shared secret mismatch")
	}
	return meshAuthResult{
		PeerPublicKey: peer.PublicKey,
		PeerIndex:     idx,
		SharedSecret:  secret,
	}, nil
}

func (a *meshControlAuthenticator) challengeState(now time.Time) (meshChallengeState, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	rotate := time.Duration(a.e.cfg.MeshControl.ChallengeRotateSeconds) * time.Second
	if rotate <= 0 {
		rotate = 120 * time.Second
	}
	if a.current.priv == nil || !now.Before(a.current.expires) {
		a.prev = a.current
		priv, err := a.curve.GenerateKey(rand.Reader)
		if err != nil {
			return meshChallengeState{}, nil, err
		}
		a.current = meshChallengeState{
			priv:    priv,
			pub:     append([]byte(nil), priv.PublicKey().Bytes()...),
			expires: now.Add(rotate),
		}
	}
	return a.current, a.pubKey[:], nil
}

func (a *meshControlAuthenticator) challengeCandidates(now time.Time) ([]meshChallengeState, []byte, error) {
	current, serverPubBytes, err := a.challengeState(now)
	if err != nil {
		return nil, nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	states := []meshChallengeState{current}
	// The previous challenge state is honored for one extra rotation window
	// past its own expiry. This intentionally widens the verifier so that
	// clients which fetched a challenge moments before rotation still
	// authenticate cleanly. Effective lifetime of any single ephemeral is
	// therefore 2 * MeshControl.ChallengeRotateSeconds; size that field
	// accordingly.
	if a.prev.priv != nil && now.Before(a.prev.expires.Add(time.Duration(a.e.cfg.MeshControl.ChallengeRotateSeconds)*time.Second)) {
		states = append(states, a.prev)
	}
	return states, serverPubBytes, nil
}

// startMeshControlServer binds the opt-in mesh control HTTP service inside the
// userspace WireGuard netstack. It is intentionally tunnel-only, similar to
// dns_server.listen, and does not expose a host listener.
func (e *Engine) startMeshControlServer() error {
	if e.cfg.MeshControl.Listen == "" {
		return nil
	}
	addr, err := netip.ParseAddrPort(e.cfg.MeshControl.Listen)
	if err != nil {
		return err
	}
	baseLn, err := e.net.ListenTCPAddrPort(addr)
	if err != nil {
		return fmt.Errorf("mesh control listen: %w", err)
	}
	auth, err := newMeshControlAuthenticator(e)
	if err != nil {
		_ = baseLn.Close()
		return err
	}
	e.meshAuth = auth
	ln := e.wrapPeerListener(baseLn)
	e.addListener("mesh-control", ln)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/challenge", e.handleMeshControlChallenge)
	mux.HandleFunc("/v1/peers", e.handleMeshControlPeers)
	mux.HandleFunc("/v1/acls", e.handleMeshControlACLs)
	mux.HandleFunc("/v1/nets", e.handleMeshControlNets)
	mux.HandleFunc("/v1/p2p", e.handleMeshControlP2P)
	mux.HandleFunc("/v1/subscribe", e.handleMeshControlSubscribe)

	server := e.proxyHTTPServer(e.meshControlRateLimit(mux))
	go func() {
		if err := server.Serve(ln); err != nil && !isClosedErr(err) {
			e.log.Infof("mesh control stopped: %v", err)
		}
	}()
	return nil
}

// meshControlRateLimit caps requests-per-second per source IP for the mesh
// control HTTP listener. WireGuard peers themselves are NOT trusted in this
// project's threat model — anyone who handshakes can hit the listener — so a
// chatty (or hostile) peer hammering /v1/challenge or /v1/peers must not be
// able to keep the mesh control loop hot or evict legitimate peers' state.
//
// The HTTP and SOCKS5 proxy listeners deliberately do NOT use this: they are
// intended for internal/local use, where rate-limiting trades off ergonomics
// for a defense the deployment doesn't need.
const (
	meshControlRequestsPerSecond = 10
	meshControlBurst             = 20
	meshControlMaxBuckets        = 4096
)

func (e *Engine) meshControlRateLimit(next http.Handler) http.Handler {
	bucketsMu := sync.Mutex{}
	buckets := make(map[string]*meshRateBucket)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteHostOnly(r.RemoteAddr)
		now := time.Now()
		bucketsMu.Lock()
		b := buckets[ip]
		if b == nil {
			// Cap the map so a peer cycling through source ports (or a
			// flood from a spoofed-source IPv6 range) cannot grow it
			// without bound. When full, drop the oldest entry rather
			// than refusing the new one — eviction is cheaper than the
			// cost of letting state grow unbounded.
			if len(buckets) >= meshControlMaxBuckets {
				evictOldestRateBucket(buckets)
			}
			b = &meshRateBucket{tokens: meshControlBurst, last: now}
			buckets[ip] = b
		}
		// Token bucket: refill since last touch, then try to spend one.
		elapsed := now.Sub(b.last).Seconds()
		b.tokens = minFloat(float64(meshControlBurst), b.tokens+elapsed*float64(meshControlRequestsPerSecond))
		b.last = now
		ok := b.tokens >= 1
		if ok {
			b.tokens--
		}
		bucketsMu.Unlock()
		if !ok {
			if e.metrics != nil {
				e.metrics.meshRequestsRateLimited.Add(1)
			}
			w.Header().Set("Retry-After", "1")
			writeAPIError(w, http.StatusTooManyRequests, "mesh control rate limit exceeded")
			return
		}
		if e.metrics != nil {
			e.metrics.meshRequestsOK.Add(1)
		}
		next.ServeHTTP(w, r)
	})
}

type meshRateBucket struct {
	tokens float64
	last   time.Time
}

func evictOldestRateBucket(buckets map[string]*meshRateBucket) {
	var oldestKey string
	var oldest time.Time
	for k, v := range buckets {
		if oldestKey == "" || v.last.Before(oldest) {
			oldestKey = k
			oldest = v.last
		}
	}
	if oldestKey != "" {
		delete(buckets, oldestKey)
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// remoteHostOnly returns just the IP portion of a "host:port" RemoteAddr, so
// a peer cycling source ports doesn't get a fresh bucket each time.
func remoteHostOnly(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

func (e *Engine) handleMeshControlChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	resp, err := e.meshAuth.Challenge(time.Now())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeAPIJSON(w, http.StatusOK, resp)
}

func (e *Engine) handleMeshControlPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	authRes, err := e.meshAuth.Verify(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	peers, err := e.meshPeersForRequester(authRes.PeerPublicKey)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	payload, err := json.Marshal(peers)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sealed, err := meshSealRandom(payload, authRes.SharedSecret, meshBodyContextLabel)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (e *Engine) handleMeshControlACLs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	authRes, err := e.meshAuth.Verify(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	resp, err := e.meshACLsForRequester(authRes.PeerPublicKey)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sealed, err := meshSealRandom(payload, authRes.SharedSecret, meshBodyContextLabel)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (e *Engine) handleMeshControlNets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	authRes, err := e.meshAuth.Verify(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	resp, err := e.meshNetsForRequester(authRes.PeerPublicKey)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sealed, err := meshSealRandom(payload, authRes.SharedSecret, meshBodyContextLabel)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

// meshNetsForRequester returns the IP prefixes the server has allocated to
// the requesting peer (its AllowedIPs as configured on the server).
func (e *Engine) meshNetsForRequester(requester string) (meshNetsResponse, error) {
	peer, _, ok := e.meshPeerConfig(requester)
	if !ok {
		return meshNetsResponse{}, errors.New("peer not found")
	}
	prefixes := append([]string(nil), peer.AllowedIPs...)
	sort.Strings(prefixes)
	return meshNetsResponse{Prefixes: prefixes}, nil
}

// meshSubscribeContextLabel is mixed into the key derivation for
// /v1/subscribe frames, distinct from the request-body label so the
// same secret cannot be replayed across endpoints.
const meshSubscribeContextLabel = "uwgsocks-mesh-subscribe"

// meshSubscribeHeartbeat is the interval between heartbeat frames on an
// idle subscribe connection. The client must reconnect if no frame has
// arrived within 3× this window (~90s).
const meshSubscribeHeartbeat = 30 * time.Second

// meshSubscribeFrame is the JSON envelope for all frames emitted over
// a /v1/subscribe stream.
type meshSubscribeFrame struct {
	Type  string               `json:"type"` // "state" or "heartbeat"
	Peers []meshDiscoveredPeer `json:"peers,omitempty"`
	ACLs  *meshACLResponse     `json:"acls,omitempty"`
}

// handleMeshControlSubscribe opens an encrypted octet-stream event subscription
// for the authenticated peer. The frame format is:
//
//	[2-byte big-endian payload length][XChaCha20-Poly1305 ciphertext]
//
// The key is derived once from the per-connection shared secret. The nonce
// is counter-based (counter 1, 2, 3…) encoded as a little-endian uint64 in
// the first 8 bytes of the 24-byte nonce (remaining 16 bytes zero). The
// receiver increments its own counter to decrypt each frame without a
// transmitted nonce.
//
// Nonce safety: every /v1/subscribe connection requires a full challenge-
// response auth that generates a fresh ECDH ephemeral pair, making the
// SharedSecret and its derived key unique per connection. A counter starting
// at 1 under a unique key therefore never reuses a (key, nonce) pair —
// catastrophic under XChaCha20-Poly1305 (XOR stream) if violated.
//
// The first frame is always "state" (full peers + ACLs for the requester).
// Subsequent "state" frames follow any mesh change event. "heartbeat" frames
// are sent every 30s on idle connections so the client can detect a stale
// connection.
func (e *Engine) handleMeshControlSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	authRes, err := e.meshAuth.Verify(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Derive the per-connection stream key from the shared secret.
	key, _ := meshKeyNonce(authRes.SharedSecret, meshSubscribeContextLabel)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "cipher init failed")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Accel-Buffering", "no") // hint to nginx: disable proxy buffering
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	// Register for change notifications.
	notifyCh := e.meshSubsAdd()
	defer e.meshSubsRemove(notifyCh)

	var counter uint64
	sendFrame := func(evType string, requester string) error {
		frame := meshSubscribeFrame{Type: evType}
		if evType == "state" {
			if peers, ferr := e.meshPeersForRequester(requester); ferr == nil {
				frame.Peers = peers
			}
			if aclResp, ferr := e.meshACLsForRequester(requester); ferr == nil {
				frame.ACLs = &aclResp
			}
		}
		plain, merr := json.Marshal(frame)
		if merr != nil {
			return merr
		}
		counter++
		nonce := meshSubscribeNonce(counter)
		ct := aead.Seal(nil, nonce, plain, nil)
		if len(ct) > 0xffff {
			return errors.New("frame too large")
		}
		var hdr [2]byte
		hdr[0] = byte(len(ct) >> 8)
		hdr[1] = byte(len(ct))
		if _, werr := w.Write(hdr[:]); werr != nil {
			return werr
		}
		if _, werr := w.Write(ct); werr != nil {
			return werr
		}
		if canFlush {
			flusher.Flush()
		}
		return nil
	}

	// First frame: full state snapshot.
	if err = sendFrame("state", authRes.PeerPublicKey); err != nil {
		return
	}

	heartbeat := time.NewTicker(meshSubscribeHeartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-e.closed:
			return
		case <-notifyCh:
			if err = sendFrame("state", authRes.PeerPublicKey); err != nil {
				return
			}
		case <-heartbeat.C:
			if err = sendFrame("heartbeat", authRes.PeerPublicKey); err != nil {
				return
			}
		}
	}
}

// meshSubscribeNonce encodes counter (1-based) as a little-endian uint64
// in the first 8 bytes of a 24-byte XChaCha20 nonce.
func meshSubscribeNonce(counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSizeX)
	n[0] = byte(counter)
	n[1] = byte(counter >> 8)
	n[2] = byte(counter >> 16)
	n[3] = byte(counter >> 24)
	n[4] = byte(counter >> 32)
	n[5] = byte(counter >> 40)
	n[6] = byte(counter >> 48)
	n[7] = byte(counter >> 56)
	return n
}

// meshSubsAdd registers a new subscriber and returns its notification channel.
func (e *Engine) meshSubsAdd() chan struct{} {
	ch := make(chan struct{}, 1)
	e.meshSubsMu.Lock()
	if e.meshSubs == nil {
		e.meshSubs = make(map[uint64]chan struct{})
	}
	id := e.meshSubsNext
	e.meshSubsNext++
	e.meshSubs[id] = ch
	e.meshSubsMu.Unlock()
	return ch
}

// meshSubsRemove unregisters the subscription channel returned by meshSubsAdd.
func (e *Engine) meshSubsRemove(ch chan struct{}) {
	e.meshSubsMu.Lock()
	for id, c := range e.meshSubs {
		if c == ch {
			delete(e.meshSubs, id)
			break
		}
	}
	e.meshSubsMu.Unlock()
}

// notifyMeshSubscribers sends a non-blocking notification to all active
// /v1/subscribe connections. Called whenever mesh state changes.
func (e *Engine) notifyMeshSubscribers() {
	e.meshSubsMu.Lock()
	for _, ch := range e.meshSubs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	e.meshSubsMu.Unlock()
}

// handleMeshControlP2P lets authenticated peers declare their P2P capability.
// POST /v1/p2p with body {"p2p":"active"} (or disable/passive/remote/server).
// The declaration is stored server-side and reflected in subsequent /v1/peers
// responses as the "type" field for that peer.
func (e *Engine) handleMeshControlP2P(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.meshAuth == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mesh control is not available")
		return
	}
	authRes, err := e.meshAuth.Verify(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req struct {
		P2P string `json:"p2p"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.P2P {
	case "disable", "passive", "active", "server", "remote":
	default:
		writeAPIError(w, http.StatusBadRequest, `p2p must be one of: disable, passive, active, remote`)
		return
	}
	// "server" is an alias for "remote" — same semantics, kept for compat.
	if req.P2P == "server" {
		req.P2P = "remote"
	}
	e.meshP2PMu.Lock()
	e.meshP2PDecls[authRes.PeerPublicKey] = req.P2P
	e.meshP2PMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// peerTypeFromDeclaration maps a stored p2p declaration to the type string
// returned in /v1/peers responses.
func peerTypeFromDeclaration(decl string) string {
	switch decl {
	case "remote":
		return "remote"
	case "active":
		return "p2p"
	case "disable":
		return "client"
	default: // "passive" or not yet declared
		return "p2p-maybe"
	}
}

func (e *Engine) meshPeersForRequester(requester string) ([]meshDiscoveredPeer, error) {
	status, err := e.Status()
	if err != nil {
		return nil, err
	}
	requesterPeer, _, ok := e.meshPeerConfig(requester)
	if !ok || !requesterPeer.MeshAcceptACLs {
		return nil, nil
	}
	e.cfgMu.RLock()
	configPeers := append([]config.Peer(nil), e.cfg.WireGuard.Peers...)
	transports := append([]transport.Config(nil), e.cfg.Transports...)
	defaultTransport := transport.ResolveDefaultTransportName(transports, e.cfg.WireGuard.DefaultTransport)
	window := time.Duration(e.cfg.MeshControl.ActivePeerWindowSeconds) * time.Second
	advertiseSelf := e.cfg.MeshControl.AdvertiseSelf
	e.cfgMu.RUnlock()
	if window <= 0 {
		window = 120 * time.Second
	}

	e.meshP2PMu.RLock()
	requesterDecl := e.meshP2PDecls[requester]
	e.meshP2PMu.RUnlock()
	requesterDisabled := requesterDecl == "disable"

	now := time.Now()
	statusByKey := make(map[string]PeerStatus, len(status.Peers))
	for _, st := range status.Peers {
		statusByKey[st.PublicKey] = st
	}

	out := make([]meshDiscoveredPeer, 0, len(configPeers))
	for _, peer := range configPeers {
		if peer.PublicKey == requester {
			continue
		}
		if !peer.MeshAcceptACLs && peer.MeshTrust == config.MeshTrustUntrusted {
			continue
		}
		if !advertiseSelf && peer.PublicKey == e.meshServerPublicKey() {
			continue
		}
		if peer.MeshAdvertise != nil && !*peer.MeshAdvertise {
			continue
		}
		st, ok := statusByKey[peer.PublicKey]
		if !ok || !st.HasHandshake {
			continue
		}
		if last := time.Unix(st.LastHandshakeTimeSec, st.LastHandshakeTimeNsec); now.Sub(last) > window {
			continue
		}

		e.meshP2PMu.RLock()
		peerDecl := e.meshP2PDecls[peer.PublicKey]
		e.meshP2PMu.RUnlock()
		peerType := peerTypeFromDeclaration(peerDecl)

		// A requester that declared "disable" only receives remote peers.
		if requesterDisabled && peerType != "remote" {
			continue
		}

		allowed := slices.Clone(peer.AllowedIPs)
		sort.Strings(allowed)
		psk, err := e.meshPairPSK(requester, peer.PublicKey)
		if err != nil {
			return nil, err
		}
		endpoint := meshAdvertisedEndpoint(peer, st, transports, defaultTransport)
		out = append(out, meshDiscoveredPeer{
			PublicKey:  peer.PublicKey,
			Endpoint:   endpoint,
			AllowedIPs: allowed,
			PSK:        base64.StdEncoding.EncodeToString(psk),
			MeshAccept: peer.MeshAcceptACLs,
			MeshTrust:  string(peer.MeshTrust),
			Type:       peerType,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

func (e *Engine) meshACLsForRequester(requester string) (meshACLResponse, error) {
	peer, _, ok := e.meshPeerConfig(requester)
	if !ok || !peer.MeshAcceptACLs {
		return meshACLResponse{}, nil
	}
	requesterPrefixes, err := config.PeerAllowedPrefixes([]config.Peer{peer})
	if err != nil {
		return meshACLResponse{}, err
	}
	e.aclMu.RLock()
	rules := append([]acl.Rule(nil), e.relACL.Rules...)
	def := e.relACL.Default
	e.aclMu.RUnlock()
	inbound := make([]acl.Rule, 0, len(rules))
	outbound := make([]acl.Rule, 0, len(rules))
	for _, rule := range rules {
		if projected, ok := meshProjectRelayRuleForDestination(rule, requesterPrefixes); ok {
			inbound = append(inbound, projected)
		}
		if projected, ok := meshProjectRelayRuleForSource(rule, requesterPrefixes); ok {
			outbound = append(outbound, projected)
		}
	}
	return meshACLResponse{Default: def, Inbound: inbound, Outbound: outbound}, nil
}

func meshAdvertisedEndpoint(peer config.Peer, st PeerStatus, transports []transport.Config, defaultTransport string) string {
	if st.Endpoint == "" {
		return ""
	}
	if len(transports) == 0 {
		return st.Endpoint
	}
	name := peer.Transport
	if name == "" {
		name = defaultTransport
	}
	if name == "" {
		return st.Endpoint
	}
	for _, tc := range transports {
		tc = transport.NormalizeConfig(tc)
		if tc.Name != name {
			continue
		}
		switch tc.Base {
		case "", "udp":
			return st.Endpoint
		case "turn":
			proto := strings.ToLower(strings.TrimSpace(tc.TURN.Protocol))
			if proto == "" || proto == "udp" {
				return st.Endpoint
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}

func (e *Engine) meshServerPublicKey() string {
	pub, err := e.wgPublicKey()
	if err != nil {
		return ""
	}
	return wgtypes.Key(pub).String()
}

func (e *Engine) meshPeerConfig(publicKey string) (config.Peer, int, bool) {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	for i, peer := range e.cfg.WireGuard.Peers {
		if peer.PublicKey == publicKey {
			return peer, i, true
		}
	}
	return config.Peer{}, -1, false
}

func (e *Engine) dynamicPeer(publicKey string) *dynamicPeer {
	e.dynamicMu.RLock()
	defer e.dynamicMu.RUnlock()
	return e.dynamicPeers[publicKey]
}

func (e *Engine) meshStaticPeers() []config.Peer {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return append([]config.Peer(nil), e.cfg.WireGuard.Peers...)
}

func (e *Engine) startMeshPolling() {
	peers := e.meshStaticPeers()
	enabled := false
	for _, peer := range peers {
		if peer.MeshEnabled && peer.MeshAcceptACLs && peer.ControlURL != "" {
			enabled = true
			break
		}
	}
	if !enabled {
		return
	}
	go e.meshPollingLoop()
	go e.keepaliveProbingLoop()
	e.startMeshSubscribeLoops(peers)
}

// startMeshSubscribeLoops launches one long-lived subscribe goroutine per
// parent peer. Each goroutine maintains a /v1/subscribe connection; when
// connected, it suppresses the per-parent polling ticker. On disconnect it
// clears the flag and retries after a 5-second backoff.
func (e *Engine) startMeshSubscribeLoops(peers []config.Peer) {
	for _, peer := range peers {
		if !peer.MeshEnabled || !peer.MeshAcceptACLs || peer.ControlURL == "" {
			continue
		}
		p := peer
		go e.meshSubscribeLoopPeer(p)
	}
}

// meshSubscribeNotImplemented is the sentinel returned by the subscribe
// attempt when the server returns 501 (older server without subscribe support).
var meshSubscribeNotImplemented = errors.New("subscribe: server returned 501")

func (e *Engine) meshSubscribeLoopPeer(parent config.Peer) {
	usePolling := false // set after first 501 → permanent polling fallback
	for {
		select {
		case <-e.closed:
			return
		default:
		}
		if usePolling {
			// Server doesn't support subscribe; poll on normal interval.
			select {
			case <-e.closed:
				return
			case <-time.After(15 * time.Second):
				e.runMeshPollingPeer(parent)
			}
			continue
		}

		err := e.runMeshSubscribePeer(parent)
		if errors.Is(err, meshSubscribeNotImplemented) {
			usePolling = true
			continue
		}
		// Any other error (network, auth, etc.): wait and retry.
		select {
		case <-e.closed:
			return
		case <-time.After(5 * time.Second):
		}
	}
}


// meshSubscribeHeartbeatTimeout is how long the subscribe client waits for a
// frame before treating the connection as stale and reconnecting.
const meshSubscribeHeartbeatTimeout = 3 * meshSubscribeHeartbeat // 90s

// runMeshSubscribePeer connects to /v1/subscribe for one parent peer,
// reads frames, and applies state changes. Returns meshSubscribeNotImplemented
// when the server returns HTTP 501. Any other error means "retry later".
func (e *Engine) runMeshSubscribePeer(parent config.Peer) error {
	local := e.meshSourceAddr()
	if !local.IsValid() {
		return errors.New("no local WireGuard address")
	}
	remote := netip.AddrPortFrom(local, 0)

	// Use a context with no client timeout; the connection is long-lived.
	// The heartbeat watchdog provides disconnect semantics.
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()

	// Build a separate client without the 15s response timeout.
	key, err := wgtypes.ParseKey(e.cfg.WireGuard.PrivateKey)
	if err != nil {
		return err
	}
	subClient := &meshControlClient{
		peer:       parent,
		privateKey: key,
		httpClient: &http.Client{
			// No timeout — frame reading uses read deadlines via context.
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if testMeshDialContextOverride != nil {
						return testMeshDialContextOverride(ctx, network, addr)
					}
					return e.DialTunnelContext(ctx, network, addr)
				},
				// Disable keep-alive so reconnects create fresh TCP connections.
				DisableKeepAlives: true,
			},
		},
	}
	u, err := url.Parse(parent.ControlURL)
	if err != nil {
		return err
	}
	subClient.controlURL = u

	challenge, err := subClient.fetchChallenge(ctx)
	if err != nil {
		return err
	}
	token, secret, err := subClient.bearerToken(remote, challenge)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subClient.controlURL.ResolveReference(&url.URL{Path: "/v1/subscribe"}).String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := subClient.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotImplemented {
		return meshSubscribeNotImplemented
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("subscribe: server status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Derive the stream key (same as server side).
	streamKey, _ := meshKeyNonce(secret, meshSubscribeContextLabel)
	aead, err := chacha20poly1305.NewX(streamKey)
	if err != nil {
		return err
	}

	br := bufio.NewReader(resp.Body)
	var counter uint64
	var lastFrameNs atomic.Int64
	lastFrameNs.Store(time.Now().UnixNano())

	readFrame := func() (meshSubscribeFrame, error) {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return meshSubscribeFrame{}, err
		}
		length := int(hdr[0])<<8 | int(hdr[1])
		if length == 0 || length > 0xffff {
			return meshSubscribeFrame{}, errors.New("invalid frame length")
		}
		ct := make([]byte, length)
		if _, err := io.ReadFull(br, ct); err != nil {
			return meshSubscribeFrame{}, err
		}
		counter++
		nonce := meshSubscribeNonce(counter)
		plain, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return meshSubscribeFrame{}, fmt.Errorf("subscribe frame decrypt: %w", err)
		}
		var frame meshSubscribeFrame
		if err := json.Unmarshal(plain, &frame); err != nil {
			return meshSubscribeFrame{}, err
		}
		lastFrameNs.Store(time.Now().UnixNano())
		return frame, nil
	}

	// heartbeat watchdog: cancel context if no frame within timeout.
	watchdog := make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-e.closed:
				cancel()
				return
			case <-watchdog:
			case <-t.C:
				if time.Duration(time.Now().UnixNano()-lastFrameNs.Load()) > meshSubscribeHeartbeatTimeout {
					cancel()
					return
				}
			}
		}
	}()

	for {
		frame, err := readFrame()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case watchdog <- struct{}{}:
		default:
		}
		if frame.Type == "state" {
			select {
			case <-e.closed:
				return nil
			default:
			}
			if frame.Peers != nil {
				if applyErr := e.applyMeshDiscoveredPeers(parent, frame.Peers); applyErr != nil {
					return applyErr
				}
			}
			if frame.ACLs != nil {
				if applyErr := e.applyMeshACLsWithDefault(parent.PublicKey, frame.ACLs.Default, frame.ACLs.Inbound, frame.ACLs.Outbound); applyErr != nil {
					return applyErr
				}
			}
			// Trigger activity refresh so newly discovered peers activate
			// without waiting for the next 15s polling tick.
			e.refreshDynamicPeerActivity()
		}
	}
}

// runMeshPollingPeer runs one poll cycle for a single parent peer.
// Used by the subscribe fallback path when the server doesn't support subscribe.
func (e *Engine) runMeshPollingPeer(parent config.Peer) {
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	client, err := e.newMeshControlClient(ctx, parent)
	if err != nil {
		return
	}
	local := e.meshSourceAddr()
	if !local.IsValid() {
		return
	}
	remote := netip.AddrPortFrom(local, 0)
	e.cfgMu.RLock()
	p2pMode := e.cfg.MeshControl.P2PMode
	e.cfgMu.RUnlock()
	if p2pMode != "" {
		if postErr := client.postP2PMode(ctx, remote, p2pMode); postErr != nil {
			e.log.Errorf("mesh control p2p declare for %s failed: %v", parent.PublicKey, postErr)
		}
	}
	peers, err := client.fetchPeers(ctx, remote)
	if err != nil {
		e.log.Errorf("mesh control poll for %s failed: %v", parent.PublicKey, err)
		return
	}
	if err = e.applyMeshDiscoveredPeers(parent, peers); err != nil {
		return
	}
	aclResp, err := client.fetchACLs(ctx, remote)
	if err != nil {
		return
	}
	_ = e.applyMeshACLsWithDefault(parent.PublicKey, aclResp.Default, aclResp.Inbound, aclResp.Outbound)
	netsResp, err := client.fetchNets(ctx, remote)
	if err != nil {
		return
	}
	_ = e.applyMeshSelfPrefixes(parent.PublicKey, netsResp.Prefixes)
	e.meshACLMu.Lock()
	e.meshParentReady[parent.PublicKey] = true
	e.meshACLMu.Unlock()
	e.refreshDynamicPeerActivity()
}

func (e *Engine) meshPollingLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
			e.runMeshPolling()
		}
	}
}

func (e *Engine) runMeshPolling() {
	peers := e.meshStaticPeers()
	for _, parent := range peers {
		if !parent.MeshEnabled || !parent.MeshAcceptACLs || parent.ControlURL == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		client, err := e.newMeshControlClient(ctx, parent)
		if err == nil {
			local := e.meshSourceAddr()
			if local.IsValid() {
				remote := netip.AddrPortFrom(local, 0)
				// Declare our P2P role before fetching peers so the hub
				// can apply filtering for our declaration in the same poll
				// cycle (e.g. a "disable" client gets only remote peers).
				// Non-fatal: a failed declaration just means the hub keeps
				// the previous value.
				e.cfgMu.RLock()
				p2pMode := e.cfg.MeshControl.P2PMode
				e.cfgMu.RUnlock()
				if p2pMode != "" {
					if postErr := client.postP2PMode(ctx, remote, p2pMode); postErr != nil {
						e.log.Errorf("mesh control p2p declare for %s failed: %v", parent.PublicKey, postErr)
					}
				}
				var peers []meshDiscoveredPeer
				peers, err = client.fetchPeers(ctx, remote)
				if err == nil {
					err = e.applyMeshDiscoveredPeers(parent, peers)
				}
				if err == nil {
					var aclResp meshACLResponse
					aclResp, err = client.fetchACLs(ctx, remote)
					if err == nil {
						err = e.applyMeshACLsWithDefault(parent.PublicKey, aclResp.Default, aclResp.Inbound, aclResp.Outbound)
					}
				}
				if err == nil {
					var netsResp meshNetsResponse
					netsResp, err = client.fetchNets(ctx, remote)
					if err == nil {
						err = e.applyMeshSelfPrefixes(parent.PublicKey, netsResp.Prefixes)
					}
				}
				// Only mark this parent ready once ALL three fetches have
				// succeeded in the same poll cycle. Dynamic peer packets are
				// denied until this flag is set (deny-until-ready).
				if err == nil {
					e.meshACLMu.Lock()
					e.meshParentReady[parent.PublicKey] = true
					e.meshACLMu.Unlock()
				}
			} else {
				err = errors.New("no local WireGuard address for mesh control")
			}
		}
		cancel()
		if err != nil {
			e.log.Errorf("mesh control poll for %s failed: %v", parent.PublicKey, err)
		}
	}
	e.refreshDynamicPeerActivity()
}

func (e *Engine) meshSourceAddr() netip.Addr {
	for _, addr := range e.localAddrs {
		if addr.IsValid() {
			return addr
		}
	}
	return netip.Addr{}
}

func (e *Engine) applyMeshDiscoveredPeers(parent config.Peer, discovered []meshDiscoveredPeer) error {
	now := time.Now()
	parentPrefixes, err := config.PeerAllowedPrefixes([]config.Peer{parent})
	if err != nil {
		return err
	}
	static := e.meshStaticPeers()
	staticKeys := make(map[string]struct{}, len(static))
	for _, peer := range static {
		staticKeys[peer.PublicKey] = struct{}{}
	}
	type update struct {
		key         string
		peer        config.Peer
		keepaliveIP netip.Addr
	}
	type candidate struct {
		key      string
		peer     config.Peer
		peerType string // from disc.Type
	}
	candidateIndex := make(map[string]int, len(discovered))
	candidates := make([]candidate, 0, len(discovered))
	for _, disc := range discovered {
		if disc.PublicKey == parent.PublicKey {
			continue
		}
		if _, ok := staticKeys[disc.PublicKey]; ok {
			continue
		}
		allowed := meshTrimAllowedIPs(disc.AllowedIPs, parentPrefixes)
		if len(allowed) == 0 {
			continue
		}
		trust := config.MeshTrust(disc.MeshTrust)
		switch trust {
		case "", config.MeshTrustUntrusted:
			trust = config.MeshTrustUntrusted
		case config.MeshTrustTrustedAlways, config.MeshTrustTrustedIfDynamicACLs:
		default:
			trust = config.MeshTrustUntrusted
		}
		peer := config.Peer{
			PublicKey:           disc.PublicKey,
			PresharedKey:        disc.PSK,
			Endpoint:            disc.Endpoint,
			AllowedIPs:          allowed,
			PersistentKeepalive: meshDynamicKeepalive(parent),
			MeshAcceptACLs:      disc.MeshAccept,
			MeshTrust:           trust,
		}
		if idx, ok := candidateIndex[disc.PublicKey]; ok {
			candidates[idx].peer = peer
			candidates[idx].peerType = disc.Type
			continue
		}
		candidateIndex[disc.PublicKey] = len(candidates)
		candidates = append(candidates, candidate{key: disc.PublicKey, peer: peer, peerType: disc.Type})
	}
	var upserts []update
	var removals []string

	e.dynamicMu.Lock()
	for key, dp := range e.dynamicPeers {
		if dp.ParentPublicKey == parent.PublicKey {
			if _, ok := candidateIndex[key]; !ok {
				removals = append(removals, key)
				delete(e.dynamicPeers, key)
			}
		}
	}
	for _, cand := range candidates {
		dp, exists := e.dynamicPeers[cand.key]
		if exists && dp.ParentPublicKey != parent.PublicKey {
			continue
		}
		if !exists && len(e.dynamicPeers) >= meshDynamicPeerLimit {
			continue
		}
		peer := cand.peer
		if exists && dp.Active && dp.Peer.Endpoint != "" && cand.peer.Endpoint == dp.LastHubEndpoint {
			// Hub's endpoint unchanged since last apply. Preserve whatever
			// WG endpoint is stored — it may be a test-forced direct-path
			// override or a WG-roamed address that is better than hub's view.
			peer.Endpoint = dp.Peer.Endpoint
		}
		if !exists {
			dp = &dynamicPeer{ParentPublicKey: parent.PublicKey}
			e.dynamicPeers[cand.key] = dp
		}
		dp.LastHubEndpoint = cand.peer.Endpoint
		dp.Peer = peer
		dp.LastControl = now
		// Update peer type from server's current declaration.
		if cand.peerType != "" {
			dp.PeerType = cand.peerType
		} else if dp.PeerType == "" {
			dp.PeerType = "p2p-maybe"
		}
		// Allocate a keepalive probe IP for non-remote peers that don't have
		// one yet. Remote peers are forced-active and don't need probing.
		if dp.PeerType != "remote" && !dp.KeepaliveIP.IsValid() {
			if ip := e.allocKeepaliveIPLocked(cand.key); ip.IsValid() {
				dp.KeepaliveIP = ip
			} else if e.keepaliveSubnet.IsValid() {
				e.log.Warnf("mesh: keepalive subnet %s exhausted, no probe IP for %s", e.keepaliveSubnet, cand.key)
			}
		}
		upserts = append(upserts, update{key: cand.key, peer: peer, keepaliveIP: dp.KeepaliveIP})
	}
	e.dynamicMu.Unlock()

	// Re-validate each upsert under the lock before pushing to
	// wireguard-go. Between the Unlock above and these IpcSets, a
	// concurrent runtime-API mutation (e.g. SetWireGuardConfig →
	// reconcileDynamicPeersWithStatic) could have deleted entries
	// from dynamicPeers. Without this re-check, we'd push a peer
	// to WG-go that no longer exists in our model, leaving the
	// device + map state desynchronised. M6 race-tier-2 finding.
	for _, up := range upserts {
		e.dynamicMu.RLock()
		_, stillTracked := e.dynamicPeers[up.key]
		e.dynamicMu.RUnlock()
		if !stillTracked {
			continue
		}
		if err := e.upsertDynamicPeerDevice(up.peer, up.keepaliveIP); err != nil {
			return err
		}
	}
	for _, key := range removals {
		if err := e.removeDynamicPeerDevice(key); err != nil {
			return err
		}
	}
	if len(upserts) > 0 || len(removals) > 0 {
		e.notifyMeshSubscribers()
	}
	return e.reconcileDynamicPeerPriority()
}

func meshDynamicKeepalive(parent config.Peer) int {
	if parent.PersistentKeepalive > 0 {
		return parent.PersistentKeepalive
	}
	return 15
}

func meshTrimAllowedIPs(raw []string, parents []netip.Prefix) []string {
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		for _, parent := range parents {
			if parent.Addr().BitLen() != prefix.Addr().BitLen() {
				continue
			}
			if parent.Bits() <= prefix.Bits() && parent.Contains(prefix.Addr()) {
				out = append(out, prefix.String())
				break
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func meshProjectRelayRuleForDestination(rule acl.Rule, allowed []netip.Prefix) (acl.Rule, bool) {
	projected := rule
	projectedDsts := meshProjectDestinations(rule.Destination, rule.Destinations, allowed)
	if len(projectedDsts) == 0 {
		return acl.Rule{}, false
	}
	projected.Destination = ""
	projected.Destinations = projectedDsts
	if err := projected.Normalize(); err != nil {
		return acl.Rule{}, false
	}
	return projected, true
}

func meshProjectRelayRuleForSource(rule acl.Rule, allowed []netip.Prefix) (acl.Rule, bool) {
	projected := rule
	projectedSrcs := meshProjectDestinations(rule.Source, rule.Sources, allowed)
	if len(projectedSrcs) == 0 {
		return acl.Rule{}, false
	}
	projected.Source = ""
	projected.Sources = projectedSrcs
	if err := projected.Normalize(); err != nil {
		return acl.Rule{}, false
	}
	return projected, true
}

func meshProjectDestinations(single string, many []string, allowed []netip.Prefix) []string {
	raws := make([]string, 0, 1+len(many))
	if single != "" {
		raws = append(raws, single)
	}
	raws = append(raws, many...)
	if len(raws) == 0 {
		for _, prefix := range allowed {
			raws = append(raws, prefix.Masked().String())
		}
	}
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		if raw == "" {
			continue
		}
		prefix, ok := meshParseCIDROrAddr(raw)
		if !ok {
			continue
		}
		prefix = prefix.Masked()
		for _, allow := range allowed {
			allow = allow.Masked()
			projected, ok := meshPrefixIntersection(prefix, allow)
			if ok {
				out = append(out, projected.String())
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func meshAnyPrefixIntersects(prefix netip.Prefix, allowed []netip.Prefix) bool {
	for _, want := range allowed {
		if prefix.Addr().BitLen() != want.Addr().BitLen() {
			continue
		}
		if prefix.Bits() <= want.Bits() && prefix.Contains(want.Addr()) {
			return true
		}
		if want.Bits() <= prefix.Bits() && want.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func meshPrefixIntersection(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Addr().BitLen() != b.Addr().BitLen() {
		return netip.Prefix{}, false
	}
	a = a.Masked()
	b = b.Masked()
	if a.Bits() <= b.Bits() && a.Contains(b.Addr()) {
		return b, true
	}
	if b.Bits() <= a.Bits() && b.Contains(a.Addr()) {
		return a, true
	}
	return netip.Prefix{}, false
}

func meshParseCIDROrAddr(raw string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked(), true
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(ip.Unmap(), bits), true
	}
	return netip.Prefix{}, false
}

func (e *Engine) upsertDynamicPeerDevice(peer config.Peer, keepaliveIP netip.Addr) error {
	if e.dev == nil {
		return nil
	}
	if keepaliveIP.IsValid() {
		peer.AllowedIPs = append(append([]string(nil), peer.AllowedIPs...), keepaliveIP.String()+"/32")
	}
	uapi, err := peerUAPI(peer, false, nil, "")
	if err != nil {
		return err
	}
	return e.dev.IpcSet(uapi)
}

func (e *Engine) removeDynamicPeerDevice(publicKey string) error {
	if e.dev == nil {
		return nil
	}
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	return e.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", base64ToHex(key[:])))
}

func base64ToHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

func (e *Engine) reconcileDynamicPeerPriority() error {
	if e.dev == nil {
		return e.applyPeerTrafficState(e.meshStaticPeers())
	}
	static := e.meshStaticPeers()
	type orderedDynamic struct {
		parentIndex int
		peer        config.Peer
		keepaliveIP netip.Addr
	}
	var active []orderedDynamic
	e.dynamicMu.RLock()
	for _, dp := range e.dynamicPeers {
		if dp == nil || !dp.Active {
			continue
		}
		active = append(active, orderedDynamic{
			parentIndex: e.meshStaticPeerIndex(dp.ParentPublicKey, static),
			peer:        dp.Peer,
			keepaliveIP: dp.KeepaliveIP,
		})
	}
	e.dynamicMu.RUnlock()
	sort.Slice(active, func(i, j int) bool {
		if active[i].parentIndex == active[j].parentIndex {
			return active[i].peer.PublicKey < active[j].peer.PublicKey
		}
		return active[i].parentIndex < active[j].parentIndex
	})
	e.cfgMu.RLock()
	transports := append([]transport.Config(nil), e.cfg.Transports...)
	defaultTransport := transport.ResolveDefaultTransportName(transports, e.cfg.WireGuard.DefaultTransport)
	e.cfgMu.RUnlock()
	for _, parent := range static {
		hasChild := false
		var inactiveChildIPs []string
		e.dynamicMu.RLock()
		for _, dp := range e.dynamicPeers {
			if dp == nil || dp.ParentPublicKey != parent.PublicKey {
				continue
			}
			hasChild = true
			if !dp.Active {
				// Claim inactive child's IPs under the parent so
				// wireguard-go routes them to the relay hub rather
				// than the unreachable direct endpoint. When the
				// child is active it is pushed after the parent and
				// wins the trie for equal-length prefixes.
				inactiveChildIPs = append(inactiveChildIPs, dp.Peer.AllowedIPs...)
			}
		}
		e.dynamicMu.RUnlock()
		if !hasChild {
			continue
		}
		pushParent := parent
		if len(inactiveChildIPs) > 0 {
			pushParent.AllowedIPs = append(append([]string(nil), parent.AllowedIPs...), inactiveChildIPs...)
		}
		uapi, err := peerUAPI(pushParent, false, transports, defaultTransport)
		if err != nil {
			return err
		}
		if err := e.dev.IpcSet(uapi); err != nil {
			return err
		}
	}
	for _, item := range active {
		p := item.peer
		if item.keepaliveIP.IsValid() {
			p.AllowedIPs = append(append([]string(nil), item.peer.AllowedIPs...), item.keepaliveIP.String()+"/32")
		}
		uapi, err := peerUAPI(p, false, nil, "")
		if err != nil {
			return err
		}
		if err := e.dev.IpcSet(uapi); err != nil {
			return err
		}
	}
	return e.applyPeerTrafficState(static)
}

func (e *Engine) meshStaticPeerIndex(publicKey string, peers []config.Peer) int {
	for i, peer := range peers {
		if peer.PublicKey == publicKey {
			return i
		}
	}
	return len(peers)
}

// allocKeepaliveIPLocked allocates a unique address in e.keepaliveSubnet for
// the given peer key. Must be called with e.dynamicMu held (write lock).
// Returns a zero Addr if the subnet is not configured or is exhausted.
func (e *Engine) allocKeepaliveIPLocked(peerKey string) netip.Addr {
	if !e.keepaliveSubnet.IsValid() || !e.keepaliveSrcIP.IsValid() {
		return netip.Addr{}
	}
	// Build set of addresses already in use by other peers.
	inUse := make(map[netip.Addr]struct{}, len(e.dynamicPeers)+1)
	inUse[e.keepaliveSrcIP] = struct{}{}
	for k, dp := range e.dynamicPeers {
		if k != peerKey && dp != nil && dp.KeepaliveIP.IsValid() {
			inUse[dp.KeepaliveIP] = struct{}{}
		}
	}
	// Deterministic candidate derived from peer key bytes (byte-aligned
	// prefixes only; falls through to scan for non-aligned subnets).
	keyBytes, err := base64.StdEncoding.DecodeString(peerKey)
	if err == nil && len(keyBytes) > 0 {
		if candidate := e.keepaliveIPFromKeyBytes(keyBytes); candidate.IsValid() {
			if _, used := inUse[candidate]; !used {
				return candidate
			}
		}
	}
	// Linear scan starting just after the source address.
	candidate := e.keepaliveSrcIP.Next()
	for e.keepaliveSubnet.Contains(candidate) {
		if _, used := inUse[candidate]; !used {
			return candidate
		}
		next := candidate.Next()
		if !next.IsValid() {
			break
		}
		candidate = next
	}
	return netip.Addr{} // exhausted
}

// keepaliveIPFromKeyBytes derives a deterministic address within
// e.keepaliveSubnet from peer key bytes. Only works for byte-aligned IPv4
// prefix lengths (/8, /16, /24). Returns a zero Addr otherwise.
func (e *Engine) keepaliveIPFromKeyBytes(key []byte) netip.Addr {
	if !e.keepaliveSubnet.Addr().Is4() {
		return netip.Addr{}
	}
	prefixBits := e.keepaliveSubnet.Bits()
	if prefixBits%8 != 0 || prefixBits >= 32 {
		return netip.Addr{}
	}
	a4 := e.keepaliveSubnet.Addr().As4()
	prefixBytes := prefixBits / 8
	for i := 0; i < 4-prefixBytes && i < len(key); i++ {
		b := key[i]
		if b == 0 {
			b = 1 // avoid the network address byte
		}
		a4[prefixBytes+i] = b
	}
	candidate := netip.AddrFrom4(a4)
	if !e.keepaliveSubnet.Contains(candidate) || candidate == e.keepaliveSrcIP {
		return netip.Addr{}
	}
	return candidate
}

const (
	// wgDeadPathTimeout is KEEPALIVE_TIMEOUT + REKEY_TIMEOUT (10s + 5s).
	// If we have sent data but the handshake hasn't refreshed within this
	// window, the direct path is dead.
	wgDeadPathTimeout = 15 * time.Second
	// wgDeadPathTimeoutP2P is the tighter dead-path window for "p2p" peers
	// that are expected to send their own keepalives promptly.
	wgDeadPathTimeoutP2P = 3 * time.Second
	// dynPeerGraceWindow is the confirmation window after a new handshake.
	// ReceiveBytes must grow before the next poll or the path is rejected.
	dynPeerGraceWindow = 5 * time.Second
	// dynPeerNoRxTimeout marks a peer inactive if no data has arrived for
	// this long while the peer is considered active.
	dynPeerNoRxTimeout = 30 * time.Second
)

func (e *Engine) refreshDynamicPeerActivity() {
	status, err := e.Status()
	if err != nil {
		return
	}
	now := time.Now()
	byKey := make(map[string]PeerStatus, len(status.Peers))
	for _, st := range status.Peers {
		byKey[st.PublicKey] = st
	}
	changed := false
	e.dynamicMu.Lock()
	for key, dp := range e.dynamicPeers {
		// "remote" peers are always considered active — they have stable
		// public endpoints and manage their own session liveness.
		if dp.PeerType == "remote" {
			if !dp.Active {
				dp.Active = true
				changed = true
			}
			continue
		}

		st, ok := byKey[key]
		if !ok || !st.HasHandshake {
			if dp.Active {
				dp.Active = false
				dp.ActiveSince = time.Time{}
				changed = true
			}
			continue
		}

		handshakeAge := now.Sub(time.Unix(st.LastHandshakeTimeSec, st.LastHandshakeTimeNsec))
		txGrew := st.TransmitBytes > dp.PrevTxSnap
		rxGrew := st.ReceiveBytes > dp.PrevRxSnap
		dp.PrevTxSnap = st.TransmitBytes
		dp.PrevRxSnap = st.ReceiveBytes

		if !dp.Active {
			// Activate on a new handshake that's fresher than the last one
			// that triggered activation (prevents re-activation on the same
			// stale handshake after a grace-period failure).
			if st.LastHandshakeTimeSec != dp.ActiveOnHandshake && handshakeAge < 120*time.Second {
				dp.Active = true
				dp.ActiveOnHandshake = st.LastHandshakeTimeSec
				dp.ActiveSince = now
				dp.GraceRxSnap = st.ReceiveBytes
				dp.LastRxGrow = now
				changed = true
			}
			continue
		}

		// --- Active peer: check for failure conditions ---

		// 1. Grace-period confirmation: RxBytes must grow before the next
		//    poll after activation (dynPeerGraceWindow = 5s, but effective
		//    resolution is the polling interval ~15s).
		if !dp.ActiveSince.IsZero() && now.Sub(dp.ActiveSince) >= dynPeerGraceWindow {
			if st.ReceiveBytes <= dp.GraceRxSnap {
				dp.Active = false
				dp.ActiveSince = time.Time{}
				changed = true
				continue
			}
			dp.ActiveSince = time.Time{} // confirmed
		}

		// 2. Dead-path: TX grew but no RX in this poll window AND handshake
		// stale. The !rxGrew guard is load-bearing: without it, a healthy
		// session naturally has handshakeAge > 15s between rekeys and would
		// trigger this condition on every poll with traffic.
		deadPathTimeout := wgDeadPathTimeout
		if dp.PeerType == "p2p" {
			deadPathTimeout = wgDeadPathTimeoutP2P
		}
		if txGrew && !rxGrew && handshakeAge > deadPathTimeout {
			dp.Active = false
			dp.ActiveSince = time.Time{}
			changed = true
			continue
		}

		// 3. No-RX timeout: no data has arrived for dynPeerNoRxTimeout.
		if rxGrew {
			dp.LastRxGrow = now
		}
		if !dp.LastRxGrow.IsZero() && now.Sub(dp.LastRxGrow) >= dynPeerNoRxTimeout {
			dp.Active = false
			dp.ActiveSince = time.Time{}
			changed = true
		}
	}
	e.dynamicMu.Unlock()
	if changed {
		_ = e.reconcileDynamicPeerPriority()
		e.notifyMeshSubscribers()
	}
}

// keepaliveEntry tracks per-peer timing state for the keepalive probe goroutine.
type keepaliveEntry struct {
	prevTx uint64
	prevRx uint64
	lastTx time.Time // when WG TX bytes last grew for this peer
	lastRx time.Time // when WG RX bytes last grew for this peer
}

// keepaliveProbeInterval mirrors WireGuard's KEEPALIVE_TIMEOUT (10s): send a
// probe if we received from the peer more recently than we sent, and haven't
// sent anything in this window.
const keepaliveProbeInterval = 10 * time.Second

func (e *Engine) keepaliveProbingLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	snaps := make(map[string]*keepaliveEntry)
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
			e.runKeepaliveProbe(snaps)
		}
	}
}

func (e *Engine) runKeepaliveProbe(snaps map[string]*keepaliveEntry) {
	if e.net == nil {
		return
	}
	status, err := e.Status()
	if err != nil {
		return
	}
	now := time.Now()
	byKey := make(map[string]PeerStatus, len(status.Peers))
	for _, st := range status.Peers {
		byKey[st.PublicKey] = st
	}

	var toProbe []netip.Addr

	e.dynamicMu.RLock()
	for key, dp := range e.dynamicPeers {
		if !dp.Active || !dp.KeepaliveIP.IsValid() || dp.PeerType == "remote" {
			delete(snaps, key)
			continue
		}
		st, ok := byKey[key]
		if !ok || !st.HasHandshake {
			delete(snaps, key)
			continue
		}
		snap, exists := snaps[key]
		if !exists {
			snap = &keepaliveEntry{prevTx: st.TransmitBytes, prevRx: st.ReceiveBytes}
			snaps[key] = snap
			continue // seed, no diff yet
		}

		if st.TransmitBytes > snap.prevTx {
			snap.lastTx = now
			snap.prevTx = st.TransmitBytes
		}
		if st.ReceiveBytes > snap.prevRx {
			snap.lastRx = now
			snap.prevRx = st.ReceiveBytes
		}

		// Probe condition (mirrors WireGuard KEEPALIVE_TIMEOUT semantics):
		// we have received from the peer more recently than we sent, and
		// the keepalive interval has elapsed since our last TX. Probes
		// count as TX (snap.lastTx is set optimistically before sending),
		// so this naturally fires at most once per keepaliveProbeInterval
		// without a separate cooldown mechanism.
		if snap.lastRx.IsZero() {
			continue
		}
		txStale := snap.lastTx.IsZero() || snap.lastRx.After(snap.lastTx)
		if txStale {
			sinceLastTx := now.Sub(snap.lastTx)
			if snap.lastTx.IsZero() {
				sinceLastTx = now.Sub(snap.lastRx)
			}
			if sinceLastTx >= keepaliveProbeInterval {
				// Set optimistically so back-to-back ticks don't re-trigger.
				snap.lastTx = now
				toProbe = append(toProbe, dp.KeepaliveIP)
			}
		}
	}
	e.dynamicMu.RUnlock()

	for _, ip := range toProbe {
		e.sendKeepaliveProbe(ip)
	}
}

// sendKeepaliveProbe sends a single 1-byte UDP packet to ip:1 through the
// gVisor netstack → WireGuard tunnel. The remote peer has no route for
// 250.x.x.x so the IP layer drops it, but the WireGuard session processes
// the packet (bumping TX on our side, RX on theirs) keeping the session alive.
func (e *Engine) sendKeepaliveProbe(ip netip.Addr) {
	dst := netip.AddrPortFrom(ip, 1)
	conn, err := e.net.DialUDPAddrPort(netip.AddrPort{}, dst)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
}

func (e *Engine) reconcileDynamicPeersWithStatic() {
	static := e.meshStaticPeers()
	staticKeys := make(map[string]struct{}, len(static))
	staticParents := make(map[string]config.Peer, len(static))
	for _, peer := range static {
		staticKeys[peer.PublicKey] = struct{}{}
		staticParents[peer.PublicKey] = peer
	}
	var removals []string
	e.dynamicMu.Lock()
	for key, dp := range e.dynamicPeers {
		if dp == nil {
			continue
		}
		if _, clash := staticKeys[key]; clash {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
			continue
		}
		parent, ok := staticParents[dp.ParentPublicKey]
		if !ok {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
			continue
		}
		if !parent.MeshAcceptACLs {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
			continue
		}
		parentPrefixes, err := config.PeerAllowedPrefixes([]config.Peer{parent})
		if err != nil {
			continue
		}
		dp.Peer.AllowedIPs = meshTrimAllowedIPs(dp.Peer.AllowedIPs, parentPrefixes)
		if len(dp.Peer.AllowedIPs) == 0 {
			removals = append(removals, key)
			delete(e.dynamicPeers, key)
		}
	}
	e.dynamicMu.Unlock()
	for _, key := range removals {
		_ = e.removeDynamicPeerDevice(key)
	}
	_ = e.reconcileDynamicPeerPriority()
}

func (e *Engine) applyMeshACLs(parentPublicKey string, rules []acl.Rule) error {
	return e.applyMeshACLsWithDefault(parentPublicKey, acl.Deny, rules, nil)
}

// applyMeshSelfPrefixes stores the IP prefixes the mesh control server
// allocated to this node for the given parent. Called after a successful
// /v1/nets fetch in the polling loop.
func (e *Engine) applyMeshSelfPrefixes(parentKey string, raw []string) error {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return fmt.Errorf("invalid mesh nets prefix %q: %w", s, err)
			}
			bits := 32
			if a.Is6() {
				bits = 128
			}
			p = netip.PrefixFrom(a, bits)
		}
		prefixes = append(prefixes, p.Masked())
	}
	e.meshACLMu.Lock()
	e.meshSelfPrefixesByParent[parentKey] = prefixes
	e.meshACLMu.Unlock()
	return nil
}

func (e *Engine) applyMeshACLsWithDefault(parentPublicKey string, def acl.Action, inboundRules, outboundRules []acl.Rule) error {
	inList := acl.List{Default: def, Rules: append([]acl.Rule(nil), inboundRules...)}
	if err := inList.Normalize(); err != nil {
		return err
	}
	outList := acl.List{Default: def, Rules: append([]acl.Rule(nil), outboundRules...)}
	if err := outList.Normalize(); err != nil {
		return err
	}
	e.meshACLMu.Lock()
	if e.meshACLsIn == nil {
		e.meshACLsIn = make(map[string]acl.List)
	}
	if e.meshACLsOut == nil {
		e.meshACLsOut = make(map[string]acl.List)
	}
	if e.meshACLFlows == nil {
		e.meshACLFlows = make(map[string]map[relayFlowKey]*relayFlow)
	}
	if e.meshACLLastSweep == nil {
		e.meshACLLastSweep = make(map[string]time.Time)
	}
	e.meshACLsIn[parentPublicKey] = inList
	e.meshACLsOut[parentPublicKey] = outList
	if _, ok := e.meshACLFlows[parentPublicKey]; !ok {
		e.meshACLFlows[parentPublicKey] = make(map[relayFlowKey]*relayFlow)
	}
	e.meshACLMu.Unlock()
	return nil
}

func (e *Engine) meshInboundACLAllowed(meta relayPacketMeta) bool {
	// Relay ACLs govern peer-to-peer traffic; they do not restrict the static
	// parent server's own packets (mesh polling responses, keepalives). Only
	// apply the ACL check when the source is a dynamic (mesh-discovered) peer.
	if !e.isKnownDynamicPeerIP(meta.src.Addr()) {
		return true
	}
	parent, rules, _, _, ok := e.meshACLListsForPeerIP(meta.src.Addr())
	if !ok {
		return true
	}
	return e.allowMeshACLTracked(parent, rules, meta, time.Now())
}

// isKnownDynamicPeerIP returns true if ip belongs to a dynamically discovered
// mesh peer (by scanning dynamicPeers AllowedIPs directly, independent of
// whether peerRoutes has been updated).
func (e *Engine) isKnownDynamicPeerIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	e.dynamicMu.RLock()
	defer e.dynamicMu.RUnlock()
	for _, dp := range e.dynamicPeers {
		if dp == nil {
			continue
		}
		for _, raw := range dp.Peer.AllowedIPs {
			prefix, ok := meshParseCIDROrAddr(raw)
			if !ok {
				continue
			}
			if prefix.Masked().Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) meshAllowLocalACL(meta relayPacketMeta) bool {
	if !e.localAddrContains(meta.src.Addr()) {
		return true
	}
	parent, _, rules, peer, ok := e.meshACLListsForPeerIP(meta.dst.Addr())
	if !ok {
		return true
	}
	switch peer.MeshTrust {
	case config.MeshTrustTrustedAlways, config.MeshTrustTrustedIfDynamicACLs:
		return e.allowMeshACLTracked(parent, rules, meta, time.Now())
	default:
		return true
	}
}

func (e *Engine) meshTrackLocalACL(meta relayPacketMeta) {
	if !e.localAddrContains(meta.src.Addr()) {
		return
	}
	parent, _, rules, _, ok := e.meshACLListsForPeerIP(meta.dst.Addr())
	if !ok {
		return
	}
	e.trackMeshACLOutbound(parent, rules, meta, time.Now())
}

func (e *Engine) meshACLListsForPeerIP(ip netip.Addr) (string, acl.List, acl.List, config.Peer, bool) {
	ip = ip.Unmap()
	bestParent := ""
	bestBits := -1
	bestPeer := config.Peer{}
	e.dynamicMu.RLock()
	for _, dp := range e.dynamicPeers {
		if dp == nil {
			continue
		}
		for _, raw := range dp.Peer.AllowedIPs {
			prefix, ok := meshParseCIDROrAddr(raw)
			if !ok {
				continue
			}
			prefix = prefix.Masked()
			if prefix.Contains(ip) && prefix.Bits() > bestBits {
				bestBits = prefix.Bits()
				bestParent = dp.ParentPublicKey
				bestPeer = dp.Peer
			}
		}
	}
	e.dynamicMu.RUnlock()
	if bestParent == "" {
		e.cfgMu.RLock()
		for _, peer := range e.cfg.WireGuard.Peers {
			if !peer.MeshAcceptACLs && peer.MeshTrust == config.MeshTrustUntrusted {
				continue
			}
			for _, raw := range peer.AllowedIPs {
				prefix, ok := meshParseCIDROrAddr(raw)
				if !ok {
					continue
				}
				prefix = prefix.Masked()
				if prefix.Contains(ip) && prefix.Bits() > bestBits {
					bestBits = prefix.Bits()
					bestParent = peer.PublicKey
					bestPeer = peer
				}
			}
		}
		e.cfgMu.RUnlock()
	}
	if bestParent == "" {
		return "", acl.List{}, acl.List{}, config.Peer{}, false
	}
	e.meshACLMu.Lock()
	defer e.meshACLMu.Unlock()
	inList, ok := e.meshACLsIn[bestParent]
	if !ok {
		return "", acl.List{}, acl.List{}, config.Peer{}, false
	}
	outList := e.meshACLsOut[bestParent]
	return bestParent, inList, outList, bestPeer, true
}

func (e *Engine) allowMeshACLTracked(parent string, rules acl.List, meta relayPacketMeta, now time.Time) bool {
	if meta.icmpErr {
		e.meshACLMu.Lock()
		defer e.meshACLMu.Unlock()
		e.ensureMeshACLFlowsLocked(parent)
		e.meshACLSweepLocked(parent, now)
		return e.allowMeshACLICMPErrorLocked(parent, meta, now)
	}
	if !relayTrackable(meta) {
		return rules.Allowed(meta.src, meta.dst, meta.network)
	}

	e.meshACLMu.Lock()
	e.ensureMeshACLFlowsLocked(parent)
	e.meshACLSweepLocked(parent, now)
	if flow, forward, ok := e.meshACLFindFlowLocked(parent, meta); ok {
		allowed := e.allowExistingMeshACLFlowLocked(parent, flow, forward, meta, now)
		e.meshACLMu.Unlock()
		return allowed
	}
	e.meshACLMu.Unlock()

	if !rules.Allowed(meta.src, meta.dst, meta.network) {
		return false
	}
	if !relayCanOpenFlow(meta) {
		return false
	}

	e.meshACLMu.Lock()
	defer e.meshACLMu.Unlock()
	e.ensureMeshACLFlowsLocked(parent)
	e.meshACLSweepLocked(parent, now)
	if flow, forward, ok := e.meshACLFindFlowLocked(parent, meta); ok {
		return e.allowExistingMeshACLFlowLocked(parent, flow, forward, meta, now)
	}
	e.meshACLFlows[parent][relayForwardKey(meta)] = newRelayFlow(meta, now)
	return true
}

func (e *Engine) trackMeshACLOutbound(parent string, rules acl.List, meta relayPacketMeta, now time.Time) {
	if meta.icmpErr {
		return
	}
	if !relayTrackable(meta) {
		return
	}
	e.meshACLMu.Lock()
	defer e.meshACLMu.Unlock()
	e.ensureMeshACLFlowsLocked(parent)
	e.meshACLSweepLocked(parent, now)
	if flow, forward, ok := e.meshACLFindFlowLocked(parent, meta); ok {
		_ = e.allowExistingMeshACLFlowLocked(parent, flow, forward, meta, now)
		return
	}
	if !rules.Allowed(meta.src, meta.dst, meta.network) || !relayCanOpenFlow(meta) {
		return
	}
	e.meshACLFlows[parent][relayForwardKey(meta)] = newRelayFlow(meta, now)
}

func (e *Engine) ensureMeshACLFlowsLocked(parent string) {
	if _, ok := e.meshACLFlows[parent]; !ok {
		e.meshACLFlows[parent] = make(map[relayFlowKey]*relayFlow)
	}
}

func (e *Engine) meshACLSweepLocked(parent string, now time.Time) {
	flows := e.meshACLFlows[parent]
	if len(flows) == 0 {
		return
	}
	last := e.meshACLLastSweep[parent]
	if !last.IsZero() && now.Sub(last) < time.Second {
		return
	}
	e.meshACLLastSweep[parent] = now
	for key, flow := range flows {
		if relayFlowExpired(flow, now, e.tcpIdleTimeout(), e.udpIdleTimeout()) {
			delete(flows, key)
		}
	}
}

func (e *Engine) meshACLFindFlowLocked(parent string, meta relayPacketMeta) (*relayFlow, bool, bool) {
	flows := e.meshACLFlows[parent]
	if flow, ok := flows[relayForwardKey(meta)]; ok {
		return flow, true, true
	}
	if flow, ok := flows[relayReverseKey(meta)]; ok {
		return flow, false, true
	}
	return nil, false, false
}

func (e *Engine) allowExistingMeshACLFlowLocked(parent string, flow *relayFlow, forward bool, meta relayPacketMeta, now time.Time) bool {
	flows := e.meshACLFlows[parent]
	switch flow.state {
	case relayFlowUDP:
		flow.last = now
		return true
	case relayFlowICMP:
		if forward && relayICMPEchoRequest(meta) || !forward && relayICMPEchoReply(meta) {
			flow.last = now
			return true
		}
		return false
	case relayTCPSynSent:
		if forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK == 0 {
			flow.last = now
			return true
		}
		if !forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK != 0 {
			flow.state = relayTCPSynRecv
			flow.last = now
			return true
		}
		return false
	case relayTCPSynRecv:
		if !forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK != 0 {
			flow.last = now
			return true
		}
		if forward && meta.tcpFlags&tcpFlagACK != 0 && meta.tcpFlags&tcpFlagSYN == 0 {
			flow.state = relayTCPEstablished
			flow.last = now
			e.updateRelayTCPClosingLocked(flow, forward, meta)
			return true
		}
		return false
	case relayTCPEstablished, relayTCPFinWait, relayTCPTimeWait:
		flow.last = now
		if meta.tcpFlags&tcpFlagRST != 0 {
			delete(flows, flow.key)
			return true
		}
		e.updateRelayTCPClosingLocked(flow, forward, meta)
		return true
	default:
		return false
	}
}

func (e *Engine) allowMeshACLICMPErrorLocked(parent string, meta relayPacketMeta, now time.Time) bool {
	if meta.inner == nil {
		return false
	}
	flow, _, ok := e.meshACLFindFlowLocked(parent, *meta.inner)
	if !ok {
		return false
	}
	if meta.dst.Addr() != flow.key.InitIP && meta.dst.Addr() != flow.key.RespIP {
		return false
	}
	flow.last = now
	return true
}

func (e *Engine) meshPairPSK(a, b string) ([]byte, error) {
	pa, _, ok := e.meshPeerConfig(a)
	if !ok {
		return nil, fmt.Errorf("mesh peer %s not found", a)
	}
	pb, _, ok := e.meshPeerConfig(b)
	if !ok {
		return nil, fmt.Errorf("mesh peer %s not found", b)
	}
	pairs := []struct {
		pub string
		psk []byte
	}{
		{pub: pa.PublicKey, psk: meshPeerPSKBytes(pa)},
		{pub: pb.PublicKey, psk: meshPeerPSKBytes(pb)},
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].pub < pairs[j].pub })
	mac := hmac.New(sha256.New, e.meshMasterKey[:])
	_, _ = mac.Write(pairs[0].psk)
	_, _ = mac.Write(pairs[1].psk)
	_, _ = mac.Write(mustParseWGKeyBytes(pairs[0].pub))
	_, _ = mac.Write(mustParseWGKeyBytes(pairs[1].pub))
	return mac.Sum(nil), nil
}

func meshPeerPSKBytes(peer config.Peer) []byte {
	if peer.PresharedKey == "" {
		return make([]byte, 32)
	}
	key, err := wgtypes.ParseKey(peer.PresharedKey)
	if err != nil {
		return make([]byte, 32)
	}
	out := make([]byte, 32)
	copy(out, key[:])
	return out
}

func meshQuickCheck(serverPub, challengePub, addrBinding []byte) []byte {
	mac := hmac.New(sha256.New, serverPub)
	_, _ = mac.Write(challengePub)
	_, _ = mac.Write(addrBinding)
	return mac.Sum(nil)
}

func meshAuthKey(ephemeralShared, staticShared []byte) []byte {
	mac := hmac.New(sha256.New, ephemeralShared)
	_, _ = mac.Write([]byte("server-static"))
	_, _ = mac.Write(staticShared)
	return mac.Sum(nil)
}

func meshSharedSecret(k1, k2, psk, addrBinding []byte) []byte {
	inner := hmac.New(sha256.New, k1)
	_, _ = inner.Write(psk)
	mac := hmac.New(sha256.New, inner.Sum(nil))
	_, _ = mac.Write(k2)
	_, _ = mac.Write(addrBinding)
	return mac.Sum(nil)
}

func meshSealDeterministic(plain, secret []byte, label string) ([]byte, error) {
	key, nonce := meshKeyNonce(secret, label)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), nonce...)
	out = aead.Seal(out, nonce, plain, nil)
	return out, nil
}

func meshSealRandom(plain, secret []byte, label string) ([]byte, error) {
	key, _ := meshKeyNonce(secret, label)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(nil), nonce...)
	out = aead.Seal(out, nonce, plain, nil)
	return out, nil
}

func meshOpen(sealed, secret []byte, label string) ([]byte, error) {
	key, _ := meshKeyNonce(secret, label)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("short sealed mesh payload")
	}
	nonce := sealed[:chacha20poly1305.NonceSizeX]
	return aead.Open(nil, nonce, sealed[chacha20poly1305.NonceSizeX:], nil)
}

func meshKeyNonce(secret []byte, label string) ([]byte, []byte) {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(label))
	sum := mac.Sum(nil)
	key := append([]byte(nil), sum...)
	mac = hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("nonce:" + label))
	nonce := mac.Sum(nil)[:chacha20poly1305.NonceSizeX]
	return key, append([]byte(nil), nonce...)
}

func meshAddrBindingFromRemote(remote string) ([]byte, error) {
	ip, err := netip.ParseAddr(remote)
	if err != nil {
		ap, apErr := netip.ParseAddrPort(remote)
		if apErr == nil {
			ip = ap.Addr()
		} else {
			host, _, splitErr := net.SplitHostPort(remote)
			if splitErr != nil {
				return nil, fmt.Errorf("mesh remote addr: %w", err)
			}
			ip, err = netip.ParseAddr(host)
			if err != nil {
				return nil, fmt.Errorf("mesh remote addr: %w", err)
			}
		}
	}
	ip = ip.Unmap()
	if !ip.IsValid() {
		return nil, errors.New("invalid mesh remote address")
	}
	var ip16 [16]byte
	if ip.Is4() {
		ip16[10], ip16[11] = 0xff, 0xff
		copy(ip16[12:], ip.AsSlice())
	} else {
		ip16 = ip.As16()
	}
	out := make([]byte, 16)
	copy(out, ip16[:])
	return out, nil
}

func mustResolveTCPAddr(remote string) net.Addr {
	ap, err := netip.ParseAddrPort(remote)
	if err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	return dummyAddr(remote)
}

type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }

func mustParseWGKeyBytes(key string) []byte {
	parsed, err := wgtypes.ParseKey(key)
	if err != nil {
		return make([]byte, 32)
	}
	out := make([]byte, 32)
	copy(out, parsed[:])
	return out
}

type meshControlClient struct {
	controlURL *url.URL
	httpClient *http.Client
	peer       config.Peer
	privateKey wgtypes.Key
}

// testMeshDialContextOverride lets tests inject a lossy / throttled / etc.
// dialer in place of the regular tunnel dial. nil in production. Set via
// SetMeshDialContextOverride from a *_test.go file in this package.
var testMeshDialContextOverride func(ctx context.Context, network, addr string) (net.Conn, error)

func (e *Engine) newMeshControlClient(ctx context.Context, peer config.Peer) (*meshControlClient, error) {
	if peer.ControlURL == "" {
		return nil, errors.New("mesh control_url is required")
	}
	u, err := url.Parse(peer.ControlURL)
	if err != nil {
		return nil, err
	}
	key, err := wgtypes.ParseKey(e.cfg.WireGuard.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &meshControlClient{
		controlURL: u,
		peer:       peer,
		privateKey: key,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if testMeshDialContextOverride != nil {
						return testMeshDialContextOverride(ctx, network, addr)
					}
					return e.DialTunnelContext(ctx, network, addr)
				},
			},
		},
	}, nil
}

func (c *meshControlClient) fetchChallenge(ctx context.Context) (meshChallengeResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL.ResolveReference(&url.URL{Path: "/v1/challenge"}).String(), nil)
	if err != nil {
		return meshChallengeResponse{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return meshChallengeResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return meshChallengeResponse{}, fmt.Errorf("mesh challenge status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out meshChallengeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, meshChallengeBodyLimit)).Decode(&out); err != nil {
		return meshChallengeResponse{}, err
	}
	return out, nil
}

func (c *meshControlClient) bearerToken(remote netip.AddrPort, challenge meshChallengeResponse) (string, []byte, error) {
	curve := ecdh.X25519()
	challengePubBytes, err := base64.StdEncoding.DecodeString(challenge.ChallengePublicKey)
	if err != nil {
		return "", nil, err
	}
	challengePub, err := curve.NewPublicKey(challengePubBytes)
	if err != nil {
		return "", nil, err
	}
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	k1, err := ephPriv.ECDH(challengePub)
	if err != nil {
		return "", nil, err
	}
	authKey := k1
	wgPriv, err := curve.NewPrivateKey(c.privateKey[:])
	if err != nil {
		return "", nil, err
	}
	k2, err := wgPriv.ECDH(challengePub)
	if err != nil {
		return "", nil, err
	}
	addrBinding, err := meshAddrBindingFromRemote(remote.String())
	if err != nil {
		return "", nil, err
	}
	peerPub := c.privateKey.PublicKey()
	serverPub, err := wgtypes.ParseKey(challenge.ServerPublicKey)
	if err != nil {
		return "", nil, err
	}
	if challenge.TokenVersion >= meshTokenVersionV2 {
		serverStaticPub, err := curve.NewPublicKey(serverPub[:])
		if err != nil {
			return "", nil, err
		}
		staticShared, err := ephPriv.ECDH(serverStaticPub)
		if err != nil {
			return "", nil, err
		}
		authKey = meshAuthKey(k1, staticShared)
	}
	sealed, err := meshSealDeterministic(peerPub[:], authKey, meshAuthContextLabel)
	if err != nil {
		return "", nil, err
	}
	secret := meshSharedSecret(authKey, k2, meshPeerPSKBytes(c.peer), addrBinding)
	x := meshQuickCheck(serverPub[:], challengePubBytes, addrBinding)
	hash := sha256.Sum256(secret)
	token := make([]byte, 0, 1+32+32+len(sealed)+32)
	tokenVersion := byte(meshTokenVersionV1)
	if challenge.TokenVersion >= meshTokenVersionV2 {
		tokenVersion = meshTokenVersionV2
	}
	token = append(token, tokenVersion)
	token = append(token, ephPriv.PublicKey().Bytes()...)
	token = append(token, x...)
	token = append(token, sealed...)
	token = append(token, hash[:]...)
	return base64.RawURLEncoding.EncodeToString(token), secret, nil
}

func (c *meshControlClient) fetchPeers(ctx context.Context, remote netip.AddrPort) ([]meshDiscoveredPeer, error) {
	challenge, err := c.fetchChallenge(ctx)
	if err != nil {
		return nil, err
	}
	token, secret, err := c.bearerToken(remote, challenge)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL.ResolveReference(&url.URL{Path: "/v1/peers"}).String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mesh peers status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	plain, err := meshOpen(sealed, secret, meshBodyContextLabel)
	if err != nil {
		return nil, err
	}
	var out []meshDiscoveredPeer
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *meshControlClient) fetchACLs(ctx context.Context, remote netip.AddrPort) (meshACLResponse, error) {
	challenge, err := c.fetchChallenge(ctx)
	if err != nil {
		return meshACLResponse{}, err
	}
	token, secret, err := c.bearerToken(remote, challenge)
	if err != nil {
		return meshACLResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL.ResolveReference(&url.URL{Path: "/v1/acls"}).String(), nil)
	if err != nil {
		return meshACLResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return meshACLResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return meshACLResponse{}, fmt.Errorf("mesh acls status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return meshACLResponse{}, err
	}
	plain, err := meshOpen(sealed, secret, meshBodyContextLabel)
	if err != nil {
		return meshACLResponse{}, err
	}
	var out meshACLResponse
	if err := json.Unmarshal(plain, &out); err != nil {
		return meshACLResponse{}, err
	}
	inList := acl.List{Default: out.Default, Rules: out.Inbound}
	if err := inList.Normalize(); err != nil {
		return meshACLResponse{}, err
	}
	outList := acl.List{Default: out.Default, Rules: out.Outbound}
	if err := outList.Normalize(); err != nil {
		return meshACLResponse{}, err
	}
	out.Default = inList.Default
	out.Inbound = inList.Rules
	out.Outbound = outList.Rules
	return out, nil
}

func (c *meshControlClient) postP2PMode(ctx context.Context, remote netip.AddrPort, mode string) error {
	challenge, err := c.fetchChallenge(ctx)
	if err != nil {
		return err
	}
	token, _, err := c.bearerToken(remote, challenge)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"p2p": mode})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.controlURL.ResolveReference(&url.URL{Path: "/v1/p2p"}).String(),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("mesh p2p declare status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *meshControlClient) fetchNets(ctx context.Context, remote netip.AddrPort) (meshNetsResponse, error) {
	challenge, err := c.fetchChallenge(ctx)
	if err != nil {
		return meshNetsResponse{}, err
	}
	token, secret, err := c.bearerToken(remote, challenge)
	if err != nil {
		return meshNetsResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL.ResolveReference(&url.URL{Path: "/v1/nets"}).String(), nil)
	if err != nil {
		return meshNetsResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return meshNetsResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return meshNetsResponse{}, fmt.Errorf("mesh nets status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return meshNetsResponse{}, err
	}
	plain, err := meshOpen(sealed, secret, meshBodyContextLabel)
	if err != nil {
		return meshNetsResponse{}, err
	}
	var out meshNetsResponse
	if err := json.Unmarshal(plain, &out); err != nil {
		return meshNetsResponse{}, err
	}
	return out, nil
}
