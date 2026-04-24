package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestWSConnReadFrameRejectsOversizedPayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		defer server.Close()
		var hdr [10]byte
		hdr[0] = 0x82
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], maxTURNWebSocketFrameSize+1)
		_, _ = server.Write(hdr[:])
	}()

	ws := &wsConn{conn: client}
	_, err := ws.ReadFrame()
	if err == nil || !strings.Contains(err.Error(), "websocket frame too large") {
		t.Fatalf("ReadFrame err=%v, want oversized-frame rejection", err)
	}
}
