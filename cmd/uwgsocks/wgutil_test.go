// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestUtilityCommands(t *testing.T) {
	t.Run("genkey", func(t *testing.T) {
		out, err := captureStdout(func() error {
			handled, err := runUtilityCommand([]string{"genkey"})
			if !handled {
				t.Fatal("genkey was not handled")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wgtypes.ParseKey(strings.TrimSpace(out)); err != nil {
			t.Fatalf("generated private key invalid: %v", err)
		}
	})

	t.Run("genpsk", func(t *testing.T) {
		out, err := captureStdout(func() error {
			handled, err := runUtilityCommand([]string{"genpsk"})
			if !handled {
				t.Fatal("genpsk was not handled")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wgtypes.ParseKey(strings.TrimSpace(out)); err != nil {
			t.Fatalf("generated preshared key invalid: %v", err)
		}
	})

	t.Run("pubkey", func(t *testing.T) {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		out, err := captureStdout(func() error {
			handled, err := runUtilityCommand([]string{"pubkey", priv.String()})
			if !handled {
				t.Fatal("pubkey was not handled")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(out) != priv.PublicKey().String() {
			t.Fatalf("pubkey output=%q want %q", strings.TrimSpace(out), priv.PublicKey().String())
		}
	})

	t.Run("genpair", func(t *testing.T) {
		tmp := t.TempDir()
		serverOut := filepath.Join(tmp, "server.conf")
		clientOut := filepath.Join(tmp, "client.conf")
		_, err := captureStdout(func() error {
			handled, err := runUtilityCommand([]string{
				"genpair",
				"--server-address", "10.0.0.1/32",
				"--client-address", "10.0.0.2/32",
				"--server-endpoint", "vpn.example.com:51820",
				"--dns", "1.1.1.1",
				"--server-out", serverOut,
				"--client-out", clientOut,
			})
			if !handled {
				t.Fatal("genpair was not handled")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		serverCfg, err := os.ReadFile(serverOut)
		if err != nil {
			t.Fatal(err)
		}
		clientCfg, err := os.ReadFile(clientOut)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(serverCfg), "ListenPort = 51820") || !strings.Contains(string(serverCfg), "AllowedIPs = 10.0.0.2/32") {
			t.Fatalf("unexpected server config:\n%s", serverCfg)
		}
		if !strings.Contains(string(clientCfg), "Endpoint = vpn.example.com:51820") || !strings.Contains(string(clientCfg), "DNS = 1.1.1.1") {
			t.Fatalf("unexpected client config:\n%s", clientCfg)
		}
	})

	t.Run("add-client", func(t *testing.T) {
		tmp := t.TempDir()
		serverKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		serverCfgPath := filepath.Join(tmp, "server.conf")
		serverCfg := "[Interface]\nPrivateKey = " + serverKey.String() + "\nAddress = 10.0.0.1/32\nListenPort = 51820\n"
		if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o600); err != nil {
			t.Fatal(err)
		}
		clientOut := filepath.Join(tmp, "client.conf")
		_, err = captureStdout(func() error {
			handled, err := runUtilityCommand([]string{
				"add-client",
				"--server-config", serverCfgPath,
				"--client-address", "10.0.0.22/32",
				"--server-endpoint", "vpn.example.com:51820",
				"--client-out", clientOut,
			})
			if !handled {
				t.Fatal("add-client was not handled")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		serverUpdated, err := os.ReadFile(serverCfgPath)
		if err != nil {
			t.Fatal(err)
		}
		clientCfg, err := os.ReadFile(clientOut)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(serverUpdated), "AllowedIPs = 10.0.0.22/32") {
			t.Fatalf("server config not updated:\n%s", serverUpdated)
		}
		if !strings.Contains(string(clientCfg), "PublicKey = "+serverKey.PublicKey().String()) || !strings.Contains(string(clientCfg), "Endpoint = vpn.example.com:51820") {
			t.Fatalf("unexpected client config:\n%s", clientCfg)
		}
	})
}

func TestRenderStatusText(t *testing.T) {
	out := renderStatusText(statusView{
		Running:           true,
		ListenPort:        51820,
		ActiveConnections: 2,
		Peers: []statusPeer{{
			PublicKey:      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd",
			Endpoint:       "198.51.100.1:51820",
			HasHandshake:   true,
			LastHandshake:  "2026-04-21T12:00:00Z",
			ReceiveBytes:   2048,
			TransmitBytes:  4096,
			TransportName:  "udp",
			Dynamic:        true,
			MeshActive:     true,
			MeshAcceptACLs: true,
		}},
	})
	if !strings.Contains(out, "public key") || !strings.Contains(out, "198.51.100.1:51820") || !strings.Contains(out, "mesh-active") {
		t.Fatalf("unexpected text output:\n%s", out)
	}
}
