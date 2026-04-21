// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func runUtilityCommand(args []string) (bool, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return false, nil
	}
	commands := map[string]func([]string) error{
		"genkey":     genkeyCommand,
		"genpsk":     genpskCommand,
		"pubkey":     pubkeyCommand,
		"genpair":    genpairCommand,
		"add-client": addClientCommand,
	}
	fn, ok := commands[args[0]]
	if !ok {
		return false, nil
	}
	return true, fn(args[1:])
}

func genkeyCommand(args []string) error {
	fs := flag.NewFlagSet("uwgsocks genkey", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, key.String())
	return err
}

func genpskCommand(args []string) error {
	fs := flag.NewFlagSet("uwgsocks genpsk", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, key.String())
	return err
}

func pubkeyCommand(args []string) error {
	fs := flag.NewFlagSet("uwgsocks pubkey", flag.ContinueOnError)
	inFile := fs.String("in", "", "private key file, or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := readSingleStringInput(*inFile, fs.Args())
	if err != nil {
		return err
	}
	key, err := wgtypes.ParseKey(raw)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, key.PublicKey().String())
	return err
}

func genpairCommand(args []string) error {
	fs := flag.NewFlagSet("uwgsocks genpair", flag.ContinueOnError)
	var serverAddrs listFlag
	var clientAddrs listFlag
	var clientAllowed listFlag
	var serverAllowed listFlag
	var dns listFlag
	serverEndpoint := fs.String("server-endpoint", "", "server endpoint host:port written into the client config")
	clientEndpoint := fs.String("client-endpoint", "", "optional client endpoint host:port written into the server config")
	listenPort := fs.Int("server-listen-port", 51820, "server WireGuard listen port")
	serverOut := fs.String("server-out", "", "optional output path for the server config")
	clientOut := fs.String("client-out", "", "optional output path for the client config")
	name := fs.String("name", "peer", "label used in output headers when writing to stdout")
	noPSK := fs.Bool("no-psk", false, "omit a generated preshared key")
	fs.Var(&serverAddrs, "server-address", "server interface address/prefix; repeatable")
	fs.Var(&clientAddrs, "client-address", "client interface address/prefix; repeatable")
	fs.Var(&clientAllowed, "client-allowed-ip", "AllowedIPs written in the client peer stanza; repeatable")
	fs.Var(&serverAllowed, "server-allowed-ip", "AllowedIPs written in the server peer stanza; repeatable")
	fs.Var(&dns, "dns", "DNS server IP written in the client interface stanza; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(serverAddrs) == 0 || len(clientAddrs) == 0 {
		return fmt.Errorf("--server-address and --client-address are required")
	}

	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	psk := ""
	if !*noPSK {
		key, err := wgtypes.GenerateKey()
		if err != nil {
			return err
		}
		psk = key.String()
	}
	if len(serverAllowed) == 0 {
		serverAllowed = append(serverAllowed, clientAddrs...)
	}
	if len(clientAllowed) == 0 {
		clientAllowed = append(clientAllowed, serverAddrs...)
	}
	serverCfg := renderWGQuick(wgQuickConfig{
		PrivateKey: serverKey.String(),
		ListenPort: *listenPort,
		Addresses:  []string(serverAddrs),
		Peers: []wgQuickPeer{{
			PublicKey:           clientKey.PublicKey().String(),
			PresharedKey:        psk,
			AllowedIPs:          []string(serverAllowed),
			Endpoint:            *clientEndpoint,
			PersistentKeepalive: 25,
		}},
	})
	clientCfg := renderWGQuick(wgQuickConfig{
		PrivateKey: clientKey.String(),
		Addresses:  []string(clientAddrs),
		DNS:        []string(dns),
		Peers: []wgQuickPeer{{
			PublicKey:           serverKey.PublicKey().String(),
			PresharedKey:        psk,
			AllowedIPs:          []string(clientAllowed),
			Endpoint:            *serverEndpoint,
			PersistentKeepalive: 25,
		}},
	})
	if *serverOut != "" {
		if err := os.WriteFile(*serverOut, []byte(serverCfg), 0o600); err != nil {
			return err
		}
	}
	if *clientOut != "" {
		if err := os.WriteFile(*clientOut, []byte(clientCfg), 0o600); err != nil {
			return err
		}
	}
	if *serverOut != "" && *clientOut != "" {
		_, err = fmt.Fprintf(os.Stdout, "wrote %s and %s\n", *serverOut, *clientOut)
		return err
	}
	if *serverOut == "" {
		if _, err := fmt.Fprintf(os.Stdout, "# %s-server.conf\n%s", *name, serverCfg); err != nil {
			return err
		}
	}
	if *clientOut == "" {
		if *serverOut == "" {
			if _, err := fmt.Fprintln(os.Stdout); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(os.Stdout, "# %s-client.conf\n%s", *name, clientCfg); err != nil {
			return err
		}
	}
	return nil
}

func addClientCommand(args []string) error {
	fs := flag.NewFlagSet("uwgsocks add-client", flag.ContinueOnError)
	serverConfigPath := fs.String("server-config", "", "server wg-quick config file to update in place")
	serverEndpoint := fs.String("server-endpoint", "", "server endpoint host:port written into the client config")
	clientOut := fs.String("client-out", "", "optional output path for the generated client config")
	name := fs.String("name", "client", "label used in stdout headers")
	noPSK := fs.Bool("no-psk", false, "omit a generated preshared key")
	var clientAddrs listFlag
	var clientAllowed listFlag
	var dns listFlag
	fs.Var(&clientAddrs, "client-address", "client interface address/prefix; repeatable")
	fs.Var(&clientAllowed, "client-allowed-ip", "AllowedIPs written in the client peer stanza; repeatable")
	fs.Var(&dns, "dns", "DNS server IP written in the client interface stanza; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverConfigPath == "" || len(clientAddrs) == 0 {
		return fmt.Errorf("--server-config and --client-address are required")
	}

	var wg config.WireGuard
	if err := config.MergeWGQuickFile(&wg, *serverConfigPath); err != nil {
		return err
	}
	if wg.PrivateKey == "" {
		return fmt.Errorf("server config has no [Interface] PrivateKey")
	}
	serverPriv, err := wgtypes.ParseKey(strings.TrimSpace(wg.PrivateKey))
	if err != nil {
		return err
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	psk := ""
	if !*noPSK {
		key, err := wgtypes.GenerateKey()
		if err != nil {
			return err
		}
		psk = key.String()
	}
	serverAllowed := append([]string(nil), clientAddrs...)
	if len(clientAllowed) == 0 {
		clientAllowed = append(clientAllowed, wg.Addresses...)
	}
	serverPeer := renderWGQuickPeer(wgQuickPeer{
		PublicKey:           clientKey.PublicKey().String(),
		PresharedKey:        psk,
		AllowedIPs:          serverAllowed,
		PersistentKeepalive: 25,
	})
	current, err := os.ReadFile(*serverConfigPath)
	if err != nil {
		return err
	}
	updated := append(bytes.TrimRight(current, "\n"), '\n', '\n')
	updated = append(updated, []byte(serverPeer)...)
	if err := os.WriteFile(*serverConfigPath, updated, 0o600); err != nil {
		return err
	}

	clientCfg := renderWGQuick(wgQuickConfig{
		PrivateKey: clientKey.String(),
		Addresses:  []string(clientAddrs),
		DNS:        []string(dns),
		Peers: []wgQuickPeer{{
			PublicKey:           serverPriv.PublicKey().String(),
			PresharedKey:        psk,
			AllowedIPs:          []string(clientAllowed),
			Endpoint:            *serverEndpoint,
			PersistentKeepalive: 25,
		}},
	})
	if *clientOut != "" {
		if err := os.WriteFile(*clientOut, []byte(clientCfg), 0o600); err != nil {
			return err
		}
		_, err = fmt.Fprintf(os.Stdout, "updated %s and wrote %s\n", *serverConfigPath, *clientOut)
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "# %s.conf\n%s", *name, clientCfg)
	return err
}

type wgQuickConfig struct {
	PrivateKey string
	ListenPort int
	Addresses  []string
	DNS        []string
	Peers      []wgQuickPeer
}

type wgQuickPeer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int
}

func renderWGQuick(cfg wgQuickConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + cfg.PrivateKey + "\n")
	if cfg.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", cfg.ListenPort))
	}
	if len(cfg.Addresses) > 0 {
		b.WriteString("Address = " + strings.Join(cfg.Addresses, ", ") + "\n")
	}
	if len(cfg.DNS) > 0 {
		b.WriteString("DNS = " + strings.Join(cfg.DNS, ", ") + "\n")
	}
	for _, peer := range cfg.Peers {
		b.WriteString("\n")
		b.WriteString(renderWGQuickPeer(peer))
	}
	return b.String()
}

func renderWGQuickPeer(peer wgQuickPeer) string {
	var b strings.Builder
	b.WriteString("[Peer]\n")
	b.WriteString("PublicKey = " + peer.PublicKey + "\n")
	if peer.PresharedKey != "" {
		b.WriteString("PresharedKey = " + peer.PresharedKey + "\n")
	}
	if len(peer.AllowedIPs) > 0 {
		b.WriteString("AllowedIPs = " + strings.Join(peer.AllowedIPs, ", ") + "\n")
	}
	if peer.Endpoint != "" {
		b.WriteString("Endpoint = " + peer.Endpoint + "\n")
	}
	if peer.PersistentKeepalive > 0 {
		b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
	}
	return b.String()
}

func readSingleStringInput(file string, args []string) (string, error) {
	switch {
	case file == "-":
		data, err := os.ReadFile("/dev/stdin")
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	case len(args) > 0:
		return strings.TrimSpace(args[0]), nil
	default:
		data, err := os.ReadFile("/dev/stdin")
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
}

func renderStatusText(st statusView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "running:\t%v\nlisten_port:\t%d\nactive_connections:\t%d\n", st.Running, st.ListenPort, st.ActiveConnections)
	if len(st.Peers) == 0 {
		return b.String()
	}
	b.WriteString("\npeers:\n")
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "public key\tendpoint\thandshake\trx\ttx\ttransport\tflags")
	for _, peer := range st.Peers {
		flags := make([]string, 0, 3)
		if peer.Dynamic {
			flags = append(flags, "dynamic")
		}
		if peer.MeshActive {
			flags = append(flags, "mesh-active")
		}
		if peer.MeshAcceptACLs {
			flags = append(flags, "mesh-acls")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			trimKey(peer.PublicKey),
			emptyDash(peer.Endpoint),
			handshakeText(peer),
			byteCountText(peer.ReceiveBytes),
			byteCountText(peer.TransmitBytes),
			emptyDash(peer.TransportName),
			emptyDash(strings.Join(flags, ",")),
		)
	}
	_ = tw.Flush()
	return b.String()
}

type statusView struct {
	Running           bool         `json:"running"`
	ListenPort        int          `json:"listen_port"`
	ActiveConnections int          `json:"active_connections"`
	Peers             []statusPeer `json:"peers"`
}

type statusPeer struct {
	PublicKey      string `json:"public_key"`
	Endpoint       string `json:"endpoint"`
	HasHandshake   bool   `json:"has_handshake"`
	LastHandshake  string `json:"last_handshake_time"`
	ReceiveBytes   uint64 `json:"receive_bytes"`
	TransmitBytes  uint64 `json:"transmit_bytes"`
	TransportName  string `json:"transport_name"`
	Dynamic        bool   `json:"dynamic"`
	MeshActive     bool   `json:"mesh_active"`
	MeshAcceptACLs bool   `json:"mesh_accept_acls"`
}

func trimKey(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "..." + s[len(s)-8:]
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func handshakeText(peer statusPeer) string {
	if !peer.HasHandshake {
		return "never"
	}
	if peer.LastHandshake != "" {
		return peer.LastHandshake
	}
	return "yes"
}

func byteCountText(v uint64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%d B", v)
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(v)/float64(div), "KMGTPE"[exp])
}
