#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
. "$(dirname "$0")/_http_client.sh"
install_hint="cargo install xh OR curl -L https://github.com/ducaale/xh/releases/latest/download/xh-x86_64-unknown-linux-musl.tar.gz | tar xz -C /usr/local/bin --strip-components=1"
run_http_client_test xh xh 'xh --print=h --timeout=10 GET @URL@ 2>&1 | awk "/^HTTP\/1/ {print \$2; exit}"'
