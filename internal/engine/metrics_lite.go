// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package engine

import (
	"errors"
	"net"
)

// metricsState lives in metrics_state.go for both builds — the hot-path
// counters cost nothing when no scraper exists, and keeping the field
// definitions identical means the call sites in always-built files
// don't need a build-tag dance.

// startMetricsServer fails closed in lite builds. The Prometheus client
// library is intentionally not pulled in because lite is for low-footprint
// / minimal-attack-surface deployments where any HTTP-handler surface is
// scope creep. Operators who want metrics build the non-lite binary.
func (e *Engine) startMetricsServer() error {
	if e.cfg.Metrics.Listen != "" {
		return errors.New("metrics endpoint is not available in lite builds; set metrics.listen='' or use the full build")
	}
	return nil
}

// listenForMetricsTesting is a no-op in lite. Keeps the signature stable
// across builds so test helpers compile, but always reports the listener
// is absent.
func (e *Engine) listenForMetricsTesting() (net.Addr, error) {
	return nil, errors.New("metrics not built in lite")
}
