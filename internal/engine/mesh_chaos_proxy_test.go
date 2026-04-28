// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// chaosProxy is a minimal UDP middleman used by the production-
// faithful mesh chaos test. It listens on a local port, forwards
// every received datagram to a fixed upstream address, and applies
// a drop / delay / jitter policy that can be changed at runtime.
//
// Use case: WireGuard's outer UDP travels A → proxy → B. When the
// proxy starts dropping packets, A's WG keepalive / rekey detects
// path failure (the same way it would in production when a NAT
// drops a stale mapping or the network briefly partitions) and
// the engine's relay-fallback path kicks in "naturally" — same
// code path that fires in real-world incidents.
//
// Bidirectional: every datagram reverse-flows from B back to the
// last-seen src on the listening side. The proxy doesn't know the
// inner WG protocol; it just shuffles bytes.
//
// Concurrent-safe: policy can be updated mid-flight.
type chaosProxy struct {
	listen   *net.UDPConn // the side peers send TO
	upstream *net.UDPAddr // the side we forward TO

	mu     sync.RWMutex
	policy chaosPolicy

	// Last src seen on the listening side, used to route reverse-
	// direction replies.
	lastSrc atomic.Pointer[net.UDPAddr]

	// Stats for assertions / logging.
	pktsForward atomic.Int64
	pktsDropped atomic.Int64
	pktsDelayed atomic.Int64

	closeOnce sync.Once
	closed    chan struct{}
}

type chaosPolicy struct {
	// LossRate is the probability a datagram is silently dropped
	// instead of forwarded. Range [0.0, 1.0].
	LossRate float64
	// Jitter is the maximum random delay applied to a forwarded
	// datagram. 0 = no jitter. Each datagram's delay is
	// independent: rand.Float64() * Jitter.
	Jitter time.Duration
	// FixedLatency is added to every forwarded datagram on top of
	// the random jitter. Useful to simulate a slower path.
	FixedLatency time.Duration
}

// startChaosProxy listens on a free local port, returns the
// listening UDPAddr (so peers can be configured to send there),
// and forwards every received datagram to upstream applying the
// current policy. The proxy runs in two goroutines (one per
// direction) until Close() is called.
func startChaosProxy(upstream *net.UDPAddr, initial chaosPolicy) (*chaosProxy, error) {
	listen, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	upConn, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		_ = listen.Close()
		return nil, err
	}
	p := &chaosProxy{
		listen:   listen,
		upstream: upstream,
		policy:   initial,
		closed:   make(chan struct{}),
	}
	go p.forwardLoop(upConn) // listen → upstream
	go p.reverseLoop(upConn) // upstream → last-seen-src on listen
	return p, nil
}

func (p *chaosProxy) Addr() *net.UDPAddr {
	return p.listen.LocalAddr().(*net.UDPAddr)
}

func (p *chaosProxy) SetPolicy(pol chaosPolicy) {
	p.mu.Lock()
	p.policy = pol
	p.mu.Unlock()
}

func (p *chaosProxy) Stats() (forwarded, dropped, delayed int64) {
	return p.pktsForward.Load(), p.pktsDropped.Load(), p.pktsDelayed.Load()
}

func (p *chaosProxy) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		_ = p.listen.Close()
	})
	return nil
}

// forwardLoop reads datagrams from peers and writes them upstream
// (subject to the current policy).
func (p *chaosProxy) forwardLoop(up *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-p.closed:
			_ = up.Close()
			return
		default:
		}
		_ = p.listen.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := p.listen.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				_ = up.Close()
				return
			}
			continue
		}
		// Remember the most recent source so reverse-direction
		// packets get routed back to it.
		srcCopy := *src
		p.lastSrc.Store(&srcCopy)
		// Copy the payload before launching the (possibly
		// delayed) forward — the read buffer is reused next iter.
		payload := append([]byte(nil), buf[:n]...)
		p.applyAndForward(up.Write, payload)
	}
}

// reverseLoop reads datagrams from upstream and writes them back
// to the last-seen peer source.
func (p *chaosProxy) reverseLoop(up *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-p.closed:
			return
		default:
		}
		_ = up.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := up.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dst := p.lastSrc.Load()
		if dst == nil {
			// We haven't seen any inbound packet yet; nothing to
			// route the reverse-direction datagram to. Drop.
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		p.applyAndForward(func(b []byte) (int, error) {
			return p.listen.WriteToUDP(b, dst)
		}, payload)
	}
}

// applyAndForward applies the current policy to a single packet:
// maybe drop, maybe delay, then write via the supplied writer.
func (p *chaosProxy) applyAndForward(write func([]byte) (int, error), payload []byte) {
	p.mu.RLock()
	pol := p.policy
	p.mu.RUnlock()

	if pol.LossRate > 0 && rand.Float64() < pol.LossRate {
		p.pktsDropped.Add(1)
		return
	}
	delay := pol.FixedLatency
	if pol.Jitter > 0 {
		delay += time.Duration(rand.Float64() * float64(pol.Jitter))
	}
	if delay > 0 {
		p.pktsDelayed.Add(1)
		go func() {
			t := time.NewTimer(delay)
			defer t.Stop()
			select {
			case <-t.C:
				_, _ = write(payload)
				p.pktsForward.Add(1)
			case <-p.closed:
			}
		}()
		return
	}
	if _, err := write(payload); err == nil {
		p.pktsForward.Add(1)
	}
}

// quickProxyDial is a one-shot "is this proxy actually forwarding"
// helper. Useful in setup to confirm the proxy works before we ask
// WG to dial through it.
func quickProxyDial(ctx context.Context, p *chaosProxy) error {
	c, err := net.DialUDP("udp", nil, p.Addr())
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write([]byte("probe")); err != nil {
		return err
	}
	return nil
}
