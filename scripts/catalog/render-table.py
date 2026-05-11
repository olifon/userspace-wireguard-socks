#!/usr/bin/env python3
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
"""Render the production-applications.md catalog table from per-host
JSON results under scripts/catalog/results/.

Usage:
    python3 scripts/catalog/render-table.py
        Print the table to stdout.
    python3 scripts/catalog/render-table.py --update
        Overwrite the "## Catalog" table in docs/catalog/production-applications.md.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS = ROOT / "scripts" / "catalog" / "results"
DOC = ROOT / "docs" / "catalog" / "production-applications.md"

# Apps in display order with category and a one-line description.
CATALOG_APPS = [
    ("curl", "HTTPS client", "Baseline libc HTTP. systrap-supervised on full hosts."),
    ("wget", "HTTPS client", "Same shape as curl."),
    ("python", "HTTPS client", "Python 3 urllib — CPython + libc + the TCP_NODELAY fix this commit landed."),
    ("node", "HTTPS client", "V8 JIT survives seccomp+systrap; libc-routed connect."),
    ("ssh", "TCP client", "Dials a tunnel-internal TCP port; banner read proves interception."),
    ("rsync-ssh", "exec+ssh+stream", "Wrapped rsync forks ssh as its transport; both inherit the wrapper. Fixture transferred to a WG peer; SHA verified through the wrapper (peer's WG addr isn't on a host route)."),
    ("git", "HTTPS client", "Clones a tiny public repo; exec tree (git → git-remote-https → curl)."),
    ("pip", "HTTPS client", "PyPI fetch via CPython requests stack."),
    ("xh", "HTTPS client", "Rust HTTP client (curl alternative)."),
    ("gh", "static Go", "GitHub CLI — static Go binary; --version boots cleanly under systrap-docker."),
    ("cloudflared", "static Go daemon", "Cloudflare tunnel client — static Go binary."),
    ("java-http", "JVM", "OpenJDK HttpURLConnection — JIT, GC, NIO. Verifies the IPv4-mapped IPv6 fix."),
    ("java-minecraft", "JVM server", "Real Paper Minecraft server, TCP listener on 25565."),
    ("nginx", "C server", "nginx in foreground, worker fork model, accept loop."),
    ("apache2", "setuid C server", "Apache event-MPM bound on tunnel WG addr; setuids workers to www-data. New signal: needs --allow-uid + relaxed shared-state perms so workers can talk back to the root-owned fdproxy after privilege drop."),
    ("php", "PHP runtime", "Built-in php -S dev server bound on tunnel WG addr; peer's wrapped curl fetches a JSON-encoded response. Catches the simplest possible accept(2) → reply path (single process, no fork)."),
    ("electron", "Chromium", "Headless chromium binary boot under wrapper. Snap-confined chromium-browser shells skipped — install non-snap chrome on arm64."),
    ("caddy", "Go HTTP server", "Wrapped Caddy bound on tunnel WG addr; peer's wrapped curl gets the response body. Forces preload transport — systrap-supervised SIGILLs on caddy's IPv6 socket probe (open issue, see project memory)."),
    ("postgres", "DB client", "Docker-hosted Postgres + `psql` SELECT through wrapper."),
    ("postgres-server", "DB server", "Wrapped `postgres` daemon bound to a tunnel WG address; peer's psql reads back through WG."),
    ("mongo", "DB client", "Docker-hosted Mongo + `mongosh` ping through wrapper."),
    ("mongo-server", "DB server", "Wrapped `mongod` bound to a tunnel WG address; peer's mongosh runs `ping` end-to-end."),
    ("mariadb-server", "DB server", "Wrapped `mariadbd` bound to a tunnel WG address; auto `aa-complain`s its AppArmor profile."),
    ("redis-server", "DB server", "Wrapped `redis-server` bound to a tunnel WG address; peer's `redis-cli` runs SET/GET/DEL/PING through WG. Single-threaded epoll daemon — distinct fingerprint from the fork/thread-pool DB servers."),
    ("dig", "DNS / UDP", "BIND9 `dig @1.1.1.1` (UDP 53) through wrapper."),
    ("ntp", "NTP / UDP", "ntpdig / sntp / python NTP — exercises unconnected-UDP path to non-tunnel destinations."),
    ("iperf3-udp", "UDP", "UDP throughput against an ephemeral local iperf3 server."),
    ("udp-echo-bind", "UDP server", "Wrapped Python UDP echo server bound to a tunnel WG address; same-host loopback edge case."),
    ("mosh", "UDP roaming", "Wrapped mosh-client → unwrapped mosh-server on hub; tests the real encrypted-UDP roaming protocol. Hub row drives from arm64 over ssh."),
    ("curl-http3", "QUIC", "curl --http3-only — gated on a libcurl build with ngtcp2/nghttp3."),
    ("odoo", "Python ERP", "Full server smoke: wrapped odoo-bin inits a fresh DB against local postgres, starts the HTTP server, wrapped curl runs the CSRF login + JSON-RPC, asserts an authenticated admin session."),
    ("kubectl", "K8s control plane", "Full lifecycle through wrapper: run pod → wait → exec (websocket upgrade) → logs → watch → delete. Tests HTTP/2 long-poll + WebSocket upgrade — the new signal vs every other HTTPS client."),
    ("helm-odoo", "K8s deployed app", "End-to-end: wrapped helm deploys Odoo+Postgres to microk8s, wrapped kubectl pulls the admin password from the cluster secret, wrapped curl completes Odoo's CSRF login + JSON-RPC, gets back an authenticated admin session through the WG tunnel."),
    ("qemu-alpine", "VM under wrapper", "qemu-system-x86_64 boots an Alpine VM under uwgwrapper. KVM-accelerated where /dev/kvm + vmx is available, TCG fallback otherwise. The hardest moat row in the catalog: massive ioctl traffic, per-vCPU thread fanout, signal-heavy."),
    ("test-python-httplib", "wrapped test suite", "437 of CPython's upstream stdlib network tests (test_httplib + test_httpservers + test_http_cookies/cookiejar + test_xmlrpc) run wrapped. Proves the wrapper carries an entire HTTP-client API surface through, not just smoke."),
    ("pytorch-mnist", "ML", "PyTorch + torchvision MNIST training (vast.ai GPU host)."),
]

# Hosts in column order.
HOSTS = ["hub", "arm64", "vast", "mac"]
MAC_NOTE = "— wrapper Linux-only"


def load(host, app):
    p = RESULTS / host / f"{app}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def cell(host, app):
    if host == "mac":
        return "—"
    d = load(host, app)
    if d is None:
        return "—"
    # Transport markers that mean "environment couldn't run this" — render
    # as `—` (binary missing) or 🚧 (specific subsystem missing); NOT ❌
    # which is reserved for a wrapper-side failure.
    missing_bin_markers = {"missing-bin"}
    env_blocked_markers = {
        "no-cuda", "unsupported-java", "no-javac", "no-http3",
        "no-docker", "no-pg-user", "no-mysql-user", "no-build-info",
        "docker-failed", "download-failed", "initdb-failed", "install-db-failed",
    }
    t = d.get("transport") or "?"
    if t in missing_bin_markers:
        return "—"
    if t in env_blocked_markers:
        return "🚧"
    if d.get("wrapped_ok"):
        return f"✅ `{t}`"
    return "❌"


def render():
    out = []
    out.append("| App | Category | hub (amd64) | arm64 | vast.ai | Mac M1 | Notes |")
    out.append("|-----|----------|-------------|-------|---------|--------|-------|")
    for app, cat, note in CATALOG_APPS:
        row = [f"`{app}`", cat]
        for h in HOSTS:
            row.append(cell(h, app))
        row.append(note)
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def update_doc():
    text = DOC.read_text()
    BEGIN = "<!-- BEGIN: rendered table -->"
    END = "<!-- END: rendered table -->"
    table = render()
    if BEGIN in text and END in text:
        before, _, rest = text.partition(BEGIN)
        _, _, after = rest.partition(END)
        new = before + BEGIN + "\n\n" + table + "\n\n" + END + after
    else:
        # Append the table at the end if anchors missing — caller can move it.
        new = text + "\n\n" + BEGIN + "\n\n" + table + "\n\n" + END + "\n"
    DOC.write_text(new)
    print("Updated", DOC, file=sys.stderr)


if __name__ == "__main__":
    if "--update" in sys.argv:
        update_doc()
    else:
        print(render())
