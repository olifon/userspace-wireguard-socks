#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Wrapped qemu booting an Alpine VM to userspace.
#
# Why this is the hardest catalog row:
#   qemu-system-x86_64 is a process unlike anything else in the catalog.
#   It does:
#     - massive ioctl traffic (KVM_RUN with KVM, or TCG translation
#       cache management without)
#     - per-vCPU thread fanout with synchronous signals
#     - heavy mmap-and-mprotect patterns for the guest memory backing
#     - if --enable-kvm, hyper-rare ioctl numbers the supervisor
#       hasn't seen before
#     - if --user-mode-network (SLIRP), the wrapper's TCP/UDP socket
#       intercept has to carry guest-emitted traffic
#
#   Existing catalog rows don't exercise any of those. If qemu boots
#   a Linux kernel to userspace under uwgwrapper, the wrapper's
#   compatibility surface is *very* wide. This is the highest-value
#   moat test in the catalog — see memory:project_vm_under_wrapper_moat.md.
#
# Pass criterion: the wrapped guest reaches Alpine Init 3.x and loads
# at least one boot driver (network or block). Detected by grepping
# the serial console output for the canonical "Alpine Init <ver>" and
# "Loading boot drivers: ok" markers — both must appear.
#
# Stays in TCG mode (no KVM) on hosts that don't expose nested virt;
# bumps to KVM if /dev/kvm is readable AND vmx/svm is in /proc/cpuinfo.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="qemu-alpine"
if ! bin_exists qemu-system-x86_64; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: apt-get install -y qemu-system-x86 qemu-utils"
  exit 0
fi

# Where the Alpine virt kernel + initramfs live. Catalog operator should
# run `mkdir -p /opt/alpine-vm && cd /opt/alpine-vm && wget …` once.
VM_DIR="${ALPINE_VM_DIR:-/opt/alpine-vm}"
if [[ ! -f "$VM_DIR/vmlinuz" || ! -f "$VM_DIR/initramfs" ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-alpine-image 0 \
    "fetch Alpine virt kernel+initramfs: mkdir -p $VM_DIR && cd $VM_DIR && wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/netboot/vmlinuz-virt -O vmlinuz && wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/netboot/initramfs-virt -O initramfs"
  exit 0
fi

ACCEL="tcg"
if [[ -r /dev/kvm ]] && grep -qE '^flags.*\b(vmx|svm)\b' /proc/cpuinfo; then
  ACCEL="kvm"
fi

work=$(mktemp -d)
trap '[[ -n "${VMPID:-}" ]] && kill -9 "$VMPID" 2>/dev/null; pkill -9 -f "qemu-system-x86_64.*$VM_DIR/vmlinuz" 2>/dev/null; rm -rf "$work"' EXIT

err="$work/wrapper.err"
log_out="$work/vm.log"
start=$(date +%s.%N)

"$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    qemu-system-x86_64 \
        -accel "$ACCEL" -m 384 -nographic -no-reboot \
        -kernel "$VM_DIR/vmlinuz" -initrd "$VM_DIR/initramfs" \
        -append "console=ttyS0 panic=1" \
    </dev/null >"$log_out" 2>"$err" &
VMPID=$!

# Watch the serial console output for the two pass markers.
booted=false
drivers=false
for i in $(seq 1 90); do
  if grep -qE 'Alpine Init [0-9]+\.[0-9]+' "$log_out" 2>/dev/null; then
    booted=true
  fi
  if grep -q 'Loading boot drivers: ok' "$log_out" 2>/dev/null; then
    drivers=true
  fi
  if [[ "$booted" == "true" && "$drivers" == "true" ]]; then
    break
  fi
  if ! kill -0 $VMPID 2>/dev/null; then break; fi
  sleep 1
done
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
if [[ "$booted" == "true" && "$drivers" == "true" ]]; then
  wrapped_ok=true
fi

alpine_ver=$(grep -oE 'Alpine Init [0-9]+\.[0-9]+\.[0-9-r]+' "$log_out" 2>/dev/null | head -1)
notes="accel=$ACCEL booted=$booted drivers=$drivers alpine=$alpine_ver | vm-tail: $(tail -c 200 $log_out | tr '\n' '|' | head -c 240)"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
