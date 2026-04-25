// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"sync"
	"sync/atomic"
)

// metricsState owns the hot-path counters that increment regardless of
// whether the Prometheus endpoint is compiled in. The fields cost nothing
// when no scraper exists; they live in the always-built file so call sites
// in socks.go / relay_conntrack.go don't need a build-tag dance.
//
// The Prometheus exposition (registry, HTTP handler, scrape collectors)
// lives in metrics.go behind //go:build !lite. Lite builds keep the
// atomic increments but never expose them — operators who want a metrics
// endpoint build the non-lite binary.
type metricsState struct {
	// Mesh control rate-limiter outcomes. Touched by the mesh control
	// HTTP middleware on every authenticated request.
	meshRequestsOK          atomic.Uint64
	meshRequestsRateLimited atomic.Uint64
	meshRequestsAuthFailed  atomic.Uint64

	// SOCKS5 connection accepted but the global cap was full.
	socksConnectionsCapped atomic.Uint64

	// New relay flows refused because the conntrack table or per-peer
	// cap was at capacity.
	conntrackRefusals atomic.Uint64

	// Roaming events inferred by the metrics package's 30s poller (when
	// the Prometheus endpoint is compiled in). The increments live here
	// so the data path's structure doesn't change between builds.
	roamingEndpointChanges atomic.Uint64

	// Roaming poller state: last endpoint observed per peer pubkey.
	// Only touched by the metrics roaming poller goroutine.
	roamMu       sync.Mutex
	lastEndpoint map[string]string
}

func newMetricsState() *metricsState {
	return &metricsState{lastEndpoint: make(map[string]string)}
}

// netstackStatsSnapshot is the subset of gVisor stats the metrics layer
// consumes. Defined in the always-built file so engine.netstackStats() (also
// always built) can reference it without a build-tag dance; the value is
// only ever read from metrics.go in non-lite builds.
type netstackStatsSnapshot struct {
	TCPRetransmits uint64
}
