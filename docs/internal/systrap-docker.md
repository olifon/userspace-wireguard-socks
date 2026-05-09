# systrap-docker internals

## Purpose

`--transport=systrap-docker` handles static binaries in Docker containers where
`ptrace(2)` is blocked by the container runtime's seccomp policy but seccomp
BPF is still allowed. It uses ELF PT_INTERP injection instead of ptrace-based
blob injection.

## Why PT_INTERP injection for Docker/static

| technique | static binary | ptrace blocked |
|-----------|--------------|----------------|
| `LD_PRELOAD` | ignored by kernel | n/a |
| `systrap` | SIGSYS handler reset at exec | n/a |
| `systrap-supervised` | requires ptrace | fails |
| `systrap-docker` (PT_INTERP inject) | works | works |

At exec time `uwgwrapper`:
1. Clones the static binary into a memfd.
2. Injects a `PT_INTERP` program header pointing to `uwgptloader.so`
   (also loaded into a memfd).
3. Writes per-exec metadata into the ptloader's `.uwgcfg` section.
4. `exec`s the patched memfd binary.

The kernel loads `uwgptloader.so` as the ELF interpreter, it runs before
`_start`, installs the systrap infrastructure (sigaltstack + SIGSYS handler +
seccomp filter), fixes the auxv entries, then jumps to the original binary's
AT_ENTRY.

## uwgptloader.so

A freestanding ELF shared object. Built by `preload/build_ptloader.sh`.
Embedded in `uwgwrapper` via `//go:embed` as
`cmd/uwgwrapper/assets/uwgptloader-{amd64,arm64}.so`.

The `.so` contains:

- All `preload/core/*.c` dispatchers (same C sources as the Phase 2 static blob)
- `preload/core/ptloader_entry.c` — self-relocation bootstrap + assembly kernel
  entry point (`uwg_ptloader_entry`, set as ELF `e_entry`)
- `preload/core/execve_docker.c` — execve interception so child exec chains in
  the patched binary also get the ptloader injected
- `.uwgcfg` ELF section holding the `uwg_ptloader_cfg` struct (patched by the
  Go patcher per-exec)

## Per-exec config struct (.uwgcfg)

```c
struct uwg_ptloader_cfg {
    uint64_t magic;             // UWG_PTLOADER_MAGIC — patcher scan target
    uint64_t original_e_phoff;  // original phdr table file offset (moved to EOF)
    uint32_t original_e_phnum;  // original phdr count
    uint32_t e_type_is_pie;     // 1 if ET_DYN (static-PIE), 0 if ET_EXEC
    uint64_t e_entry_in_file;   // e_entry from the unpatched binary
    uint64_t phdr_base_vma;     // (p_vaddr - p_offset) of the PT_LOAD that
                                // contained original_e_phoff
    int32_t  interp_fd;         // file descriptor of the ptloader memfd
};
```

The Go patcher (`cmd/uwgwrapper/systrap_docker.go`) scans the ptloader memfd
for `UWG_PTLOADER_MAGIC`, then writes the per-exec values at that offset.

## Execution flow in ptloader_entry.c

### Step 1 — assembly stub (`uwg_ptloader_entry`)

The kernel jumps here with `sp` pointing to the initial process stack.

1. Saves `sp` in a callee-saved register.
2. Aligns `sp` to 16 bytes (required by the System V ABI for function calls).
3. Calls `uwg_ptloader_start(initial_sp)`.
4. On return (value = AT_ENTRY): restores the original `sp`, zeros `rdx`/`x0`
   (tells `_start` that `rtld_fini = NULL`), jumps to AT_ENTRY.

### Step 2 — `uwg_ptloader_start` (pre-relocation bootstrap)

This function **must not access any C global variable** before calling
`uwg_apply_own_relocations`.

1. Parses the auxv from the initial stack to extract `AT_BASE` (ptloader's
   own load address in memory).
2. Calls `uwg_apply_own_relocations(AT_BASE)` to process the ptloader's own
   `DT_RELA` relocations. Without this, any initialized global pointer in the
   ptloader `.so` would have a pre-ASLR address and fault on first access.
3. Calls `uwg_ptloader_run(initial_sp)`.

Why self-relocation is needed: the kernel loads a PT_INTERP interpreter but
does **not** apply its RELATIVE relocations — that is the interpreter's own
job (just as `ld.so` does it in its bootstrap stub). Our freestanding `.so`
may have `R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE` relocations for
initialized function-pointer globals, so we process them manually.

### Step 3 — `uwg_ptloader_run` (main logic)

Accesses globals freely (relocs are applied).

1. Scans auxv for `AT_ENTRY`, `AT_BASE`, `AT_PHDR`, `AT_PHNUM`.
2. Reads the `.uwgcfg` global and checks the magic.
3. Patches auxv entries (see "auxv fixups" below).
4. Re-arms `FD_CLOEXEC` on `cfg.interp_fd` (the kernel un-armed it so the
   interpreter could be loaded; we re-arm to prevent fd leaks to child
   processes).
5. Sets `uwg_environ` so that `uwg_core_init` can read `UWGS_*` env vars.
6. Calls `uwg_ptloader_docker_init()` to read `UWGS_PTLOADER_*` env vars.
7. Calls `uwg_core_init()` — installs sigaltstack, SIGSYS handler, and the
   seccomp BPF filter. These are active **before** the binary's `_start` runs.
8. Returns `AT_ENTRY`.

## Auxv fixups

Two auxv entries need correction after PT_INTERP injection.

### AT_PHDR

`Linux fs/binfmt_elf.c` sets `AT_PHDR` only when `e_phoff` lies inside a
`PT_LOAD` segment. The patcher moves `e_phoff` to EOF (past all PT_LOAD
segments) to fit the injected PT_INTERP phdr. As a result:

- Non-PIE (`ET_EXEC`): kernel sets AT_PHDR = 0.
- PIE (`ET_DYN`): kernel sets AT_PHDR = AT_BASE (ptloader's base, not the
  phdr table).

Fix:

```
correct_AT_PHDR = phdr_base_vma + original_e_phoff + load_bias
```

where `load_bias = 0` for ET_EXEC (absolute addresses) and
`load_bias = AT_ENTRY - e_entry_in_file` for ET_DYN (ASLR shift).

`phdr_base_vma` is `(p_vaddr - p_offset)` of the PT_LOAD that originally
contained the phdr table (stored in `cfg` by the Go patcher). For typical
ET_DYN binaries it is 0 because the first PT_LOAD has `p_vaddr=0, p_offset=0`.

### AT_BASE (static-PIE only)

When PT_INTERP is present, the kernel sets `AT_BASE` to the interpreter's
(ptloader's) load address, **not** the main binary's.

Musl's `_start_c` self-relocation uses `AT_BASE`:

- `AT_BASE != 0` path: treats the value directly as `load_bias` and applies
  DT_RELA relocations relative to it.
- `AT_BASE == 0` path: uses `AT_PHDR` to find the program headers, computes
  `load_bias` from the ELF header found there, then applies DT_RELA.

If AT_BASE is left as ptloader's address, musl's `AT_BASE != 0` path writes
all global pointer fixups to garbage addresses → SIGSEGV on the first global
dereference (typically inside `_start_c` itself, after the reloc loop).

Fix: **set AT_BASE = 0** for ET_DYN binaries. This forces musl's AT_BASE=0
path which uses the correctly-patched AT_PHDR and computes the right bias.

ET_EXEC (non-PIE) binaries are unaffected: their startup code does not use
AT_BASE for self-relocation since all addresses are fixed at link time.

## Failure modes and debugging

### SIGSEGV in binary's _start after ptloader returns

Most likely AT_BASE or AT_PHDR was not patched correctly.

- Check that `cfg.e_type_is_pie` is set (binary must be ET_DYN, not ET_EXEC).
- Check that `load_bias = AT_ENTRY - cfg.e_entry_in_file` is non-zero (ASLR
  must be active; in containers that disable ASLR it can be 0 — that is fine
  because then AT_BASE=0 is already correct and AT_PHDR = original_e_phoff).
- Verify `correct_phdr` falls inside a mapped region: it should land within the
  first PT_LOAD at `load_bias + 0 .. load_bias + PT_LOAD[0].p_filesz`.

### dlsym undefined symbol on old glibc

`shim_fork.c` and `shim_posix_spawn.c` use `dlsym(RTLD_NEXT, ...)`. On glibc
< 2.34 `dlsym` lives in `libdl.so.2`, not `libc.so.6`. Build fix: link with
`-ldl` in `build_phase1.sh` (and `build_ptloader.sh`).

### "go: go.mod requires go >= 1.25.0" inside golang:1.24-alpine

The `preload-libc-matrix` CI job uses `GOTOOLCHAIN=auto` so Go 1.24 downloads
1.25.0 from dl.google.com automatically. For containers without network access,
use `golang:1.25-alpine` directly (or manually install Go 1.25 with wget like
the `musl-1.2.3` matrix entries do).

## Test coverage

`tests/preload/systrap_docker_test.go`:

- `TestSystrapDockerStaticEcho` — builds a musl-static stub (`gcc -static`),
  runs it via `--transport=systrap-docker`, asserts the expected output.
  Covers both ET_EXEC and ET_DYN (static-PIE) paths depending on the host
  toolchain's default.
- `TestSystrapDockerDynamicEcho` — same with a dynamic binary; exercises the
  non-PIE code path.

These tests run in the `preload-libc-matrix` CI job (tag-triggered,
`release.yml`). They do NOT run in the per-push `test.yml` because they
require a full Docker-in-Docker environment.
