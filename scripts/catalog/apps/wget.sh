#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
. "$(dirname "$0")/_http_client.sh"
install_hint="apt-get install -y wget"
run_http_client_test wget wget 'wget -q --timeout=10 --tries=1 -O - -S @URL@ 2>&1 | awk "/HTTP\/1/ {print \$2; exit}"'
