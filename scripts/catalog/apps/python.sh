#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
. "$(dirname "$0")/_http_client.sh"
install_hint="apt-get install -y python3"
# Python3 urllib follows libc DNS + libc connect — exercises systrap*'s libc fast path.
run_http_client_test python python3 'python3 -c "import sys,urllib.request; print(urllib.request.urlopen(\"@URL@\", timeout=10).status)"'
