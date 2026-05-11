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
    ("git", "HTTPS client", "Clones a tiny public repo; exec tree (git → git-remote-https → curl)."),
    ("pip", "HTTPS client", "PyPI fetch via CPython requests stack."),
    ("xh", "HTTPS client", "Rust HTTP client (curl alternative)."),
    ("gh", "static Go", "GitHub CLI — static Go binary; --version boots cleanly under systrap-docker."),
    ("cloudflared", "static Go daemon", "Cloudflare tunnel client — static Go binary."),
    ("java-http", "JVM", "OpenJDK HttpURLConnection — JIT, GC, NIO. Verifies the IPv4-mapped IPv6 fix."),
    ("java-minecraft", "JVM server", "Real Paper Minecraft server, TCP listener on 25565."),
    ("nginx", "C server", "nginx in foreground, worker fork model, accept loop."),
    ("electron", "Chromium", "Headless chromium with --no-sandbox."),
    ("odoo", "Python ERP", "Odoo --version (boot smoke; full ERP install is a separate soak)."),
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
    if d.get("transport") in ("missing-bin", "no-cuda", "unsupported-java", "no-javac"):
        if d["transport"] == "missing-bin":
            return "—"
        return "🚧"
    if d.get("wrapped_ok"):
        t = d.get("transport") or "?"
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
