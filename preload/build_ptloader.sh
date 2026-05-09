#!/bin/bash
# Build the uwgptloader.so for systrap-docker mode.
#
# Produces cmd/uwgwrapper/assets/uwgptloader-{amd64,arm64}.so:
# a freestanding ELF shared object that is used as a PT_INTERP
# interpreter for patched static binaries. The kernel loads it
# before the main binary's _start; it applies its own relocations,
# installs the systrap infrastructure (sigaltstack + SIGSYS handler +
# seccomp filter), and jumps to the original binary's entry point.
#
# Key differences from build_static.sh:
#   - Includes ptloader_entry.c (self-relocation bootstrap + kernel
#     entry point, sets ELF e_entry via --entry=uwg_ptloader_entry)
#   - Includes execve_docker.c (execve interception for child execs)
#   - The resulting .so has a custom .uwgcfg section holding the
#     uwg_ptloader_cfg struct (patched by the Go wrapper per-exec)
#   - Does NOT include static_entry.c (different entry convention)
#
# Output: cmd/uwgwrapper/assets/uwgptloader-{amd64,arm64}.so
#         (embedded into uwgwrapper via //go:embed)

set -euo pipefail
cd "$(dirname "$0")/.."

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

CFLAGS_BASE="-O2 -fPIC -shared -D_GNU_SOURCE -DUWG_FREESTANDING -I preload/core -I preload"
CFLAGS_FREESTANDING="-ffreestanding -nostdlib -fno-stack-protector"
# -Wl,-Bsymbolic: resolve internal symbol references at link time,
#   eliminating GOT-indirect accesses for locally-defined symbols.
#   This means function calls are direct PC-relative (no PLT indirection)
#   and internal data is RIP-relative (no GLOB_DAT relocation needed).
# --entry=uwg_ptloader_entry: set the PT_INTERP entry point so the
#   kernel jumps here when it finishes loading our interpreter.
CFLAGS_LDFLAGS="-Wl,-Bsymbolic -Wl,--entry=uwg_ptloader_entry"
CFLAGS_WARN="-Wall -Wextra -Wno-unused-parameter -Wno-stringop-overflow"

CC="${CC:-gcc}"
if [ "$ARCH" = "arm64" ]; then
    if echo 'int main(void){return 0;}' | "$CC" -x c -mno-outline-atomics - -o /dev/null 2>/dev/null; then
        CFLAGS_BASE="$CFLAGS_BASE -mno-outline-atomics"
    fi
fi

CORE_SRCS=(
    preload/core/sigsys.c
    preload/core/seccomp.c
    preload/core/dispatch.c
    preload/core/init.c
    preload/core/shared_state.c
    preload/core/fdproxy_sock.c
    preload/core/socket_ops.c
    preload/core/addr_utils.c
    preload/core/connect_ops.c
    preload/core/bind_ops.c
    preload/core/listener_ops.c
    preload/core/stream_ops.c
    preload/core/msg_ops.c
    preload/core/fd_ops.c
    preload/core/udp_frame.c
    preload/core/dns_force.c
    preload/core/trace.c
    preload/core/freestanding_impl.c
    preload/core/sigreturn_trampoline.c
    preload/core/freestanding_runtime.c
    preload/core/execve_docker.c
    preload/core/ptloader_entry.c
)

OUT_DIR="${1:-cmd/uwgwrapper/assets}"
mkdir -p "$OUT_DIR"
OUT_SO="$OUT_DIR/uwgptloader-${ARCH}.so"

"$CC" $CFLAGS_BASE $CFLAGS_FREESTANDING $CFLAGS_WARN $CFLAGS_LDFLAGS \
    "${CORE_SRCS[@]}" \
    -o "$OUT_SO"

ls -la "$OUT_SO"
echo "ptloader .so build OK ($(stat -c '%s' "$OUT_SO") bytes)"

# Verify no external symbols are referenced.
echo "=== external symbols (should be empty or kernel-syscall-equivalents):"
nm -u --no-demangle "$OUT_SO" 2>/dev/null | head -10

# Show the .uwgcfg section so the Go patcher can verify it exists.
echo "=== .uwgcfg section:"
readelf -S "$OUT_SO" 2>/dev/null | grep -A2 uwgcfg || echo "(not found — check build)"

# Verify the entry point is set.
echo "=== entry point (should be uwg_ptloader_entry):"
readelf -d "$OUT_SO" 2>/dev/null | grep ENTRY || true
nm "$OUT_SO" 2>/dev/null | grep uwg_ptloader_entry || echo "(symbol not found — check build)"
