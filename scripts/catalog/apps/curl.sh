#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
. "$(dirname "$0")/_http_client.sh"
install_hint="apt-get install -y curl"
run_http_client_test curl curl 'curl -sS --max-time 10 -o /dev/null -w "%{http_code}\n" @URL@'
