// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeAPIJSONBodyLimitsSize(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/peers", strings.NewReader(`{"public_key":"`+strings.Repeat("A", maxAPIJSONBodyBytes)+`"}`))
	var dst apiPeer
	if err := decodeAPIJSONBody(req, &dst); err == nil {
		t.Fatal("expected oversized JSON request body to fail")
	}
}
