//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgshared"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgtrace"
)

//go:embed assets/uwgpreload.so
var embeddedPreload []byte

func main() {
	var mode string
	var api string
	var apiToken string
	var socketPath string
	var preloadPath string
	var listenPath string
	var dnsMode string
	var transport string
	var forceLoopbackDNS bool
	var spawnFDProxy bool
	var noNewPrivileges bool
	var allowBind bool
	var allowLowBind bool
	var stdioConnect string
	var verbose bool

	flag.StringVar(&mode, "mode", getenv("UWGS_WRAPPER_MODE", "launch"), "mode: launch, fdproxy, or stdio")
	flag.StringVar(&api, "api", getenv("UWGS_API", "http://127.0.0.1:9090"), "uwgsocks API endpoint")
	flag.StringVar(&apiToken, "token", os.Getenv("UWGS_API_TOKEN"), "uwgsocks API bearer token")
	flag.StringVar(&socketPath, "socket-path", getenv("UWGS_SOCKET_PATH", "/uwg/socket"), "upstream socket upgrade path")
	flag.StringVar(&preloadPath, "preload", os.Getenv("UWGS_PRELOAD"), "path to preload shared library; defaults to embedded copy extracted to /tmp")
	flag.StringVar(&listenPath, "listen", getenv("UWGS_FDPROXY", ""), "Unix socket path exposed to the preload wrapper")
	flag.StringVar(&dnsMode, "dns-mode", getenv("UWGS_DNS_MODE", "full"), "DNS handling mode: full, libc, none")
	flag.StringVar(&transport, "transport", getenv("UWGS_WRAPPER_TRANSPORT", "auto"), "transport mode: auto, systrap-elf, systrap, systrap-supervised, systrap-static, preload, ptrace, ptrace-seccomp, ptrace-only (systrap-docker is a deprecated alias for systrap-elf)")
	flag.BoolVar(&forceLoopbackDNS, "force-loopback-dns", getenv("UWGS_DISABLE_LOOPBACK_DNS53", "") == "", "force loopback TCP/UDP port 53 to DNS proxy (default true)")
	flag.BoolVar(&spawnFDProxy, "spawn-fdproxy", getenv("UWGS_WRAPPER_SPAWN_FDPROXY", "") != "0", "launch built-in fdproxy daemon automatically in launch mode")
	flag.BoolVar(&noNewPrivileges, "no-new-privileges", getenv("UWGS_WRAPPER_NO_NEW_PRIVILEGES", "1") != "0", "set PR_SET_NO_NEW_PRIVS before launching the wrapped program (default true)")
	flag.BoolVar(&allowBind, "allow-bind", getenv("UWGS_FDPROXY_ALLOW_BIND", "1") != "0", "allow fdproxy-managed tunnel bind/listen requests")
	flag.BoolVar(&allowLowBind, "allow-lowbind", getenv("UWGS_FDPROXY_ALLOW_LOWBIND", "0") != "0", "allow fdproxy-managed ports below 1024")
	var allowUIDs string
	flag.StringVar(&allowUIDs, "allow-uid", getenv("UWGS_FDPROXY_ALLOW_UIDS", ""), "comma-separated list of additional uids permitted to connect to the manager socket (parent's euid + root are always allowed). Use this for servers that setuid-drop workers (apache2 → www-data, etc).")
	flag.StringVar(&stdioConnect, "stdio-connect", getenv("UWGS_STDIO_CONNECT", ""), "connect a tunnel TCP target and bridge stdin/stdout; useful as SSH ProxyCommand")
	flag.BoolVar(&verbose, "v", false, "enable wrapper diagnostics")
	var forcePreload bool
	flag.BoolVar(&forcePreload, "force-preload", false, "suppress error when --transport=preload is used against a static binary (interception will be absent)")
	flag.Parse()

	allowUIDList := parseUIDList(allowUIDs)

	switch mode {
	case "launch":
		if stdioConnect != "" {
			if err := runStdioConnect(api, apiToken, socketPath, stdioConnect, os.Stdin, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		}
		runLaunch(api, apiToken, socketPath, preloadPath, listenPath, dnsMode, transport, forceLoopbackDNS, spawnFDProxy, noNewPrivileges, allowBind, allowLowBind, verbose, forcePreload, allowUIDList)
	case "fdproxy":
		runFDProxy(api, apiToken, socketPath, listenPath, allowBind, allowLowBind, verbose || os.Getenv("UWGS_WRAPPER_DEBUG") != "", allowUIDList)
	case "stdio":
		target, err := stdioConnectTarget(stdioConnect, flag.Args())
		if err != nil {
			log.Fatal(err)
		}
		if err := runStdioConnect(api, apiToken, socketPath, target, os.Stdin, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "exec-helper":
		if err := runExecHelper(flag.Args()); err != nil {
			log.Fatal(err)
		}
	case "tracee-helper":
		if err := uwgtrace.RunTraceeHelper(flag.Args()); err != nil {
			log.Fatal(err)
		}
	case "probe-seccomp":
		runProbeSeccomp()
	case "probe-ptrace":
		runProbePtrace()
	default:
		log.Fatalf("unsupported mode %q, expected launch, fdproxy, stdio, exec-helper, tracee-helper, probe-seccomp, or probe-ptrace", mode)
	}
}

func parseUIDList(s string) []uint32 {
	if s == "" {
		return nil
	}
	var out []uint32
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.ParseUint(tok, 10, 32)
		if err != nil {
			log.Fatalf("invalid uid %q in --allow-uid list: %v", tok, err)
		}
		out = append(out, uint32(n))
	}
	return out
}

func runLaunch(api, apiToken, socketPath, preloadPath, listenPath, dnsMode, transport string, forceLoopbackDNS, spawnFDProxy, noNewPrivileges, allowBind, allowLowBind, verbose, forcePreload bool, allowedUIDs []uint32) {
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "usage: uwgwrapper [flags] -- program [args...]\n")
		flag.PrintDefaults()
		os.Exit(2)
	}

	prog := flag.Arg(0)
	progArgs := flag.Args()[1:]

	if preloadPath == "" {
		var err error
		preloadPath, err = ensureEmbeddedPreload()
		if err != nil {
			log.Fatalf("materialize embedded preload library: %v", err)
		}
	}
	if preloadPath == "" {
		log.Fatal("no preload library configured")
	}

	if listenPath == "" {
		listenPath = filepath.Join(os.TempDir(), fmt.Sprintf("uwgfdproxy-%d.sock", os.Getpid()))
	}
	debug := verbose || os.Getenv("UWGS_WRAPPER_DEBUG") != ""

	// Normalize the deprecated alias `systrap-docker` → `systrap-elf`
	// early so every downstream check sees the canonical name. The
	// alias is retained for backward compatibility with scripts and
	// docs pinned to the old name; it will be removed in a future
	// major version. Emit a one-time warning under -v.
	if transport == "systrap-docker" {
		if debug {
			log.Printf("note: --transport=systrap-docker is a deprecated alias for --transport=systrap-elf; update scripts to use the canonical name")
		}
		transport = "systrap-elf"
	}

	// systrap-elf (and auto, which may select systrap-elf for either
	// static or dynamic targets) calls syscall.Exec, which kills all Go OS
	// threads except the calling one. If the fdproxy was spawned from a
	// different OS thread, its PR_SET_PDEATHSIG fires prematurely during
	// exec and kills fdproxy before the wrapped binary can connect. Lock
	// this goroutine to its current OS thread so that fdproxy's parent
	// thread IS the thread that later calls execve — that thread survives
	// exec.
	if transport == "systrap-elf" || transport == "auto" {
		runtime.LockOSThread()
	}

	var fdproxyCmd *exec.Cmd
	if spawnFDProxy {
		_ = os.Remove(listenPath)
		fdproxyCmd = exec.Command(os.Args[0], fdproxySpawnArgs(listenPath, api, socketPath, allowBind, allowLowBind, apiToken, debug, allowedUIDs)...)
		fdproxyCmd.Stdout = os.Stderr
		fdproxyCmd.Stderr = os.Stderr
		fdproxyCmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if err := fdproxyCmd.Start(); err != nil {
			log.Fatalf("start built-in uwgfdproxy: %v", err)
		}
		defer cleanupSpawnedFDProxy(fdproxyCmd, listenPath)
		if err := waitFDProxyReady(listenPath, 5*time.Second); err != nil {
			log.Fatalf("uwgfdproxy did not become ready: %v", err)
		}
	} else {
		if err := waitFDProxyReady(listenPath, 5*time.Second); err != nil {
			log.Fatalf("existing uwgfdproxy socket %s not ready: %v", listenPath, err)
		}
	}

	target, err := exec.LookPath(prog)
	if err != nil {
		log.Fatalf("resolve target %q: %v", prog, err)
	}

	if verbose || os.Getenv("UWGS_WRAPPER_DEBUG") != "" {
		log.Printf("mode=launch target=%s transport=%s preload=%s listen=%s api=%s socketPath=%s spawnFDProxy=%t",
			target, transport, preloadPath, listenPath, api, socketPath, spawnFDProxy)
	}

	env := os.Environ()
	env = setEnv(env, "UWGS_FDPROXY", listenPath)
	env = setEnv(env, "UWGS_API", api)
	env = setEnv(env, "UWGS_SOCKET_PATH", socketPath)
	env = setEnv(env, "UWGS_DNS_MODE", dnsMode)
	if forceLoopbackDNS {
		env = setEnv(env, "UWGS_DISABLE_LOOPBACK_DNS53", "0")
	} else {
		env = setEnv(env, "UWGS_DISABLE_LOOPBACK_DNS53", "1")
	}
	if apiToken != "" {
		env = setEnv(env, "UWGS_API_TOKEN", apiToken)
	}
	shared, err := prepareSharedState()
	if err != nil {
		log.Fatalf("prepare shared state: %v", err)
	}
	// When the caller explicitly allowed additional uids (e.g. www-data
	// for apache2 workers, postgres for ident-auth pg backends), the
	// shared-state file has to be readable+writable by them too,
	// otherwise the setuid'd worker can't access the proxied-fd state
	// and every wrapped syscall fails with EACCES. The file is bounded
	// to the current wrapper run (PID-suffixed under
	// /tmp/uwgwrapper-$UID/) and only contains proxied-fd metadata
	// the wrapper already trusts the worker with — same trust scope as
	// the fdproxy AF_UNIX socket --allow-uid lets through.
	if len(allowedUIDs) > 0 {
		if err := os.Chmod(shared.Path(), 0o666); err != nil {
			log.Fatalf("relax shared-state perms for allow-uid: %v", err)
		}
	}
	env = setEnv(env, "UWGS_SHARED_STATE_PATH", shared.Path())
	env = setEnv(env, "UWGS_TRACE_SECRET", fmt.Sprintf("%d", shared.Secret()))
	env = setEnv(env, "UWGS_TRACE_NO_NEW_PRIVS", boolString(noNewPrivileges))
	statsPath := os.Getenv("UWGS_TRACE_STATS_PATH")

	traceRun := func(seccompMode uwgtrace.SeccompMode, withPreload bool) error {
		traceEnv := append([]string{}, env...)
		if withPreload {
			traceEnv = prependEnvPath(traceEnv, "LD_PRELOAD", preloadPath)
		}
		code, err := uwgtrace.Run(uwgtrace.Options{
			Args:            append([]string{target}, progArgs...),
			Env:             traceEnv,
			FDProxy:         listenPath,
			SeccompMode:     seccompMode,
			NoNewPrivileges: noNewPrivileges,
			Verbose:         debug,
			Shared:          shared,
			StatsPath:       statsPath,
		})
		if err != nil {
			return err
		}
		_ = shared.Close(true)
		os.Exit(code)
		return nil
	}

	// systrapRun = LD_PRELOAD with the .so constructor installing
	// the seccomp filter + SIGSYS handler (kernel-trap fast path
	// for raw-asm syscalls + libc hooks for the hot path).
	//
	// libcOnlyPreloadRun = LD_PRELOAD with the .so constructor
	// configured to skip seccomp + SIGSYS install; libc hooks only.
	// For hosts without seccomp/ptrace support (some containers).
	preloadInner := func(disableSystrap bool) {
		if preloadPath == "" {
			log.Fatal("no preload library configured")
		}
		envPreload := prependEnvPath(append([]string{}, env...), "LD_PRELOAD", preloadPath)
		if disableSystrap {
			envPreload = appendEnv(envPreload, "UWGS_DISABLE_SYSTRAP=1")
		}
		// Capture the shared-state path BEFORE Close zeroes out the
		// table — we want to unlink it after the child exits to avoid
		// leaking shared-state-*.bin files into /tmp/uwgwrapper-$UID/
		// across many wrapper invocations. Close(false) here doesn't
		// remove the file because the spawned child still needs the
		// inode (it mmap's the path); we defer the unlink to after
		// cmd.Run() returns, by which point the child has exited.
		statePath := shared.Path()
		_ = shared.Close(false)
		cmdArgs := append([]string{"--mode=exec-helper", "--", target}, progArgs...)
		cmd := exec.Command(os.Args[0], cmdArgs...)
		cmd.Env = envPreload
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		runErr := cmd.Run()
		if statePath != "" {
			_ = os.Remove(statePath)
		}
		if runErr != nil {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					if status.Exited() {
						os.Exit(status.ExitStatus())
					}
					if status.Signaled() {
						os.Exit(128 + int(status.Signal()))
					}
				}
			}
			log.Fatalf("run %s: %v", target, runErr)
		}
		os.Exit(0)
	}

	// systrapRun: LD_PRELOAD with seccomp + SIGSYS, no ptrace. The
	// .so constructor installs both. Static-binary descendants of
	// fork+exec lose interception (no LD_PRELOAD path on static).
	systrapRun := func() { preloadInner(false) }
	// systrapSupervisedRun: LD_PRELOAD + seccomp + SIGSYS handler
	// in-process (same as systrap), PLUS a long-running ptrace
	// supervisor that catches SECCOMP_RET_TRACE on execve /
	// execveat and re-arms across dynamic↔static boundaries:
	//   - dynamic exec child → LD_PRELOAD propagates; supervisor
	//     watches the exec event but does no injection (the
	//     constructor will re-arm).
	//   - static exec child → supervisor injects the freestanding
	//     blob (same machinery as systrap-static) at the post-exec
	//     stop and lets uwg_static_init run, then resumes the
	//     child.
	// See cmd/uwgwrapper/systrap_supervisor.go for the loop.
	systrapSupervisedRun := func() {
		blob := os.Getenv("UWGS_STATIC_BLOB")
		if blob == "" {
			blob = staticBlobPath()
		}
		// Same shared-state cleanup as preloadInner: capture the path
		// pre-Close, unlink it post-supervisor-exit. The supervisor
		// waits for its tracee tree internally, so the unlink is safe
		// once runSystrapSupervised returns.
		//
		// Capture the bypass secret BEFORE Close — the supervisor's
		// SIGSYS-stop handler (#92, scaffolded in
		// cmd/uwgwrapper/sigsys_stop_handler.go) needs it to issue
		// passthrough syscalls that skip our own seccomp filter via
		// the arg6 secret-check.
		bypassSecret := shared.Secret()
		statePath := shared.Path()
		_ = shared.Close(false)
		err := runSystrapSupervised(target, progArgs, env, preloadPath, blob, bypassSecret)
		if statePath != "" {
			_ = os.Remove(statePath)
		}
		if err != nil {
			log.Fatalf("systrap-supervised failed: %v", err)
		}
		os.Exit(0)
	}
	libcOnlyRun := func() { preloadInner(true) }

	traceSimple := func() error {
		return traceRun(uwgtrace.SeccompSimple, false)
	}
	traceNoSeccomp := func() error {
		return traceRun(uwgtrace.SeccompNone, false)
	}

	systrapStaticRun := func() {
		// Pre-flight: ptrace MUST be available. systrap-static
		// injects the freestanding blob into the target's address
		// space via PTRACE_TRACEME + remote mmap + POKEDATA at the
		// post-exec stop. There is no other way to reach a static
		// binary's address space — LD_PRELOAD is meaningless on a
		// static binary. If a container blocks ptrace, this mode
		// is unreachable on that host.
		if !probePtraceAvailable() {
			log.Fatal("systrap-static: ptrace(2) is blocked on this host (typical of restricted containers — Docker default seccomp, K8s pods without SYS_PTRACE). systrap-static fundamentally requires ptrace for blob injection. Use --transport=systrap (dynamic targets only) or --transport=ptrace if seccomp is also blocked.")
		}
		blob := os.Getenv("UWGS_STATIC_BLOB")
		if blob == "" {
			blob = staticBlobPath()
		}
		if blob == "" {
			log.Fatal("systrap-static: UWGS_STATIC_BLOB unset and no sibling uwgpreload-static-${arch}.so found")
		}
		// Same shared-state cleanup pattern as preloadInner: unlink
		// after the static-blob runner returns. The runner waits for
		// the static tracee internally.
		statePath := shared.Path()
		_ = shared.Close(false)
		err := runStaticPreload(target, progArgs, env, blob)
		if statePath != "" {
			_ = os.Remove(statePath)
		}
		if err != nil {
			log.Fatalf("systrap-static failed: %v", err)
		}
		os.Exit(0)
	}

	// Mode dispatch.
	//
	// The naming (v0.1.0-beta.56+):
	//   - preload              libc-only LD_PRELOAD. No seccomp, no
	//                          SIGSYS, no ptrace. For hosts that
	//                          block both seccomp and ptrace.
	//   - systrap              LD_PRELOAD + seccomp + in-process
	//                          SIGSYS handler. NO ptrace. Hot path
	//                          stays in libc; raw-asm traps in
	//                          process. Dynamic targets only;
	//                          static-binary descendants of
	//                          fork+exec lose interception (kernel
	//                          inherits filter but not handler).
	//   - systrap-supervised   systrap + an execve-only ptrace
	//                          supervisor that catches
	//                          SECCOMP_RET_TRACE on execve/execveat
	//                          and re-arms across dynamic↔static
	//                          boundaries. Requires ptrace. Today
	//                          runs as plain systrap with a
	//                          deprecation/forward-compat warning;
	//                          the supervisor is the Phase 1.5+2
	//                          follow-up.
	//   - systrap-static       Freestanding-blob ptrace-injection
	//                          for statically-linked targets and
	//                          their static descendants. Assumes
	//                          everything is static (no libc
	//                          hooks). Requires ptrace.
	//   - ptrace-seccomp       Per-syscall ptrace with a seccomp
	//                          pre-filter. User-selectable; auto
	//                          skips it (when seccomp+ptrace are
	//                          both available, systrap-supervised
	//                          is preferred).
	//   - ptrace-only          Per-syscall ptrace, no seccomp.
	//   - ptrace               ptrace-seccomp → ptrace-only fallback.
	//
	// auto ordering favors correctness then speed (dynamic target):
	//   systrap-elf → systrap → ptrace-seccomp → ptrace → preload
	//
	// preload (libc-only) is last because raw-asm syscalls leak past
	// the libc hooks; it's a fallback for hosts where nothing else
	// works at all. See the full cascade comment on `case "auto":`
	// below for the static-target cascade.
	switch transport {
	case "preload":
		if isStaticELF(target) && !forcePreload {
			log.Fatalf("transport=preload: target %q is a statically-linked binary; LD_PRELOAD has no effect on static binaries and interception will be absent. Use --transport=systrap-elf (seccomp OK), --transport=systrap-supervised (ptrace OK), or --transport=systrap-static. Pass --force-preload to override.", target)
		}
		libcOnlyRun()
	case "systrap":
		systrapRun()
	case "systrap-supervised":
		// Pre-flight: systrap-supervised requires ptrace for the
		// execve supervisor. Fail fast if blocked.
		if !probePtraceAvailable() {
			log.Fatal("systrap-supervised: ptrace(2) is blocked on this host. systrap-supervised needs ptrace for the execve hook. Use --transport=systrap (dynamic-only, no execve supervisor) or --transport=systrap-elf (PT_INTERP injection, no ptrace) instead.")
		}
		systrapSupervisedRun()
	case "systrap-static":
		systrapStaticRun()
	case "systrap-elf":
		// systrap-elf: ELF PT_INTERP injection via memfd_create. No
		// ptrace required. Requires seccomp (SECCOMP_RET_TRAP) and
		// memfd_create(2). Renamed from `systrap-docker` in v0.1.7
		// — the old name described the audience (Docker default-
		// seccomp containers) rather than the mechanism. The auto
		// cascade now picks this for both static AND dynamic targets
		// whenever seccomp is available, because PT_INTERP injection
		// has no concurrency surface (unlike systrap-supervised) and
		// transparently re-arms across execve boundaries.
		if !probeSeccompAvailable() {
			log.Fatal("systrap-elf: seccomp is not available on this host (SECCOMP_RET_TRAP requires kernel seccomp support). Use --transport=ptrace if seccomp is blocked but ptrace is allowed.")
		}
		if !probeMemfdAvailable() {
			log.Fatal("systrap-elf: memfd_create(2) is blocked on this host. Use --transport=systrap-supervised (PTRACE_POKETEXT-based static injection) or --transport=systrap (dynamic-only) instead.")
		}
		systrapDockerRun(target, progArgs, env, preloadPath, shared)
	case "ptrace-seccomp":
		if err := traceSimple(); err != nil {
			log.Fatalf("ptrace-seccomp mode failed: %v", err)
		}
	case "ptrace-only":
		if err := traceNoSeccomp(); err != nil {
			log.Fatalf("ptrace-only mode failed: %v", err)
		}
	case "ptrace":
		if err := traceSimple(); err == nil {
			return
		}
		if err := traceNoSeccomp(); err != nil {
			log.Fatalf("ptrace mode failed: %v", err)
		}
	case "auto":
		// Auto cascade — try each mode in this order; pick the
		// first one whose host requirements are met.
		//
		// Dynamic target cascade:
		//   1. systrap-elf          seccomp ✅ + memfd ✅
		//      PT_INTERP injection; preferred for dynamic targets too because
		//      the kernel handles loader linkage atomically and the in-tracee
		//      execve trap transparently re-arms across exec→static
		//      descendants (bash → gh, scripts → kubectl, etc.). No ptrace
		//      surface = no concurrency hazards.
		//   2. systrap              seccomp ✅ + memfd ❌
		//      Plain in-tracee SIGSYS handler. Faster (no exec round-trip)
		//      but cannot intercept static descendants — they die on the
		//      first trapped syscall after exec. Reachable only when memfd
		//      is unavailable, which is rare.
		//   3. ptrace-seccomp       seccomp ❌ + ptrace ✅
		//      ptrace with seccomp accelerator; falls back to ptrace-only
		//      if seccomp install fails inside the cascade.
		//   4. ptrace               seccomp ❌ + ptrace ✅ (fallback)
		//   5. preload              seccomp ❌ + ptrace ❌
		//
		// Static target cascade (pre-flight: isStaticELF):
		//   1. systrap-elf          seccomp ✅ + memfd ✅
		//      PT_INTERP injection — kernel loads ptloader before _start.
		//      No ptrace needed; works in Docker default-seccomp.
		//   2. systrap-supervised   seccomp ✅ + ptrace ✅ + memfd ❌
		//      PTRACE_POKETEXT-based blob injection for hosts where memfd
		//      is blocked but ptrace works (grsec/PaX, rare container
		//      shapes). Has a known concurrency bug under multi-threaded
		//      raw-syscall load — see memory:project_caddy_sigill_
		//      systrap_supervised.md.
		//   3. ptrace-seccomp       seccomp ❌ + ptrace ✅
		//   4. ptrace               seccomp ❌ + ptrace ✅ (fallback)
		//   5. FAIL fast            neither
		//
		// Note: systrap-supervised is intentionally NOT in the dynamic
		// auto cascade. systrap-elf supersedes it functionally (both
		// handle exec→static descendants) without the supervisor's
		// SIGSYS-forward race. Users who need supervised explicitly
		// (process introspection, etc.) can still select it via
		// --transport=systrap-supervised.
		//
		// ptrace-seccomp and ptrace are intentionally separate cascade
		// slots — ptrace-seccomp tries the accelerator first and only
		// falls through to ptrace-only on install failure. Both stay as
		// user-selectable modes.
		seccompOK := probeSeccompAvailable()
		ptraceOK := probePtraceAvailable()
		memfdOK := probeMemfdAvailable()

		// Static-target pre-flight: if the wrapped target is a
		// statically-linked ELF, libc-only `preload` (the last
		// cascade slot) cannot intercept anything because there's
		// no LD_PRELOAD path on a static binary, AND `systrap`
		// alone (seccomp + SIGSYS but no ptrace) leaves the
		// kernel's inherited filter active in the static child
		// without an installed handler — first trapped syscall
		// kills the child. Auto must FAIL fast if no viable mode
		// is reachable rather than silently fall through.
		targetStatic := isStaticELF(target)
		if targetStatic {
			switch {
			case seccompOK && memfdOK:
				// systrap-elf is the preferred static path: PT_INTERP
				// injection via memfd_create, no ptrace required.
				if debug {
					log.Printf("auto: chose systrap-elf (static target, seccomp=%v memfd=%v ptrace=%v)", seccompOK, memfdOK, ptraceOK)
				}
				systrapDockerRun(target, progArgs, env, preloadPath, shared)
				return
			case seccompOK && ptraceOK:
				// Fallback for the rare host where seccomp works but
				// memfd_create is blocked — use systrap-supervised's
				// PTRACE_POKETEXT-based static injection. See memory:
				// project_caddy_sigill_systrap_supervised.md for the
				// known concurrency caveat.
				if debug {
					log.Printf("auto: chose systrap-supervised (static target, seccomp=true memfd=false ptrace=true)")
				}
				systrapSupervisedRun()
				return
			case ptraceOK:
				// No seccomp: try ptrace-seccomp first (the accelerator
				// will fail at filter install and fall back internally),
				// then plain ptrace-only.
				if debug {
					log.Printf("auto: chose ptrace cascade (static target, seccomp=false ptrace=true)")
				}
				if err := traceSimple(); err == nil {
					return
				}
				if err := traceNoSeccomp(); err != nil {
					log.Fatalf("auto: ptrace cascade failed for static target %q: %v", target, err)
				}
				return
			default:
				log.Fatalf("auto: target %q is statically linked, but this host blocks both seccomp and ptrace(2); no mode can intercept a static binary. Options: (a) use a host that allows ptrace(2) or seccomp+memfd_create (systrap-elf), (b) wrap a dynamic target, or (c) use --transport=preload to accept no-interception.", target)
			}
			return
		}
		switch {
		case seccompOK && memfdOK:
			// systrap-elf for dynamic targets too. PT_INTERP injection
			// transparently re-arms across exec→static descendants
			// (bash → gh / kubectl / caddy / etc.) without the
			// systrap-supervised ptracer's SIGSYS-forward concurrency
			// surface. Same hot path as plain systrap for non-exec
			// syscalls — the in-tracee SIGSYS handler does the work.
			if debug {
				log.Printf("auto: chose systrap-elf (dynamic target, seccomp=true memfd=true ptrace=%v)", ptraceOK)
			}
			systrapDockerRun(target, progArgs, env, preloadPath, shared)
			return
		case seccompOK:
			// memfd is blocked. Fall back to plain systrap — the
			// dynamic target itself works fine via the in-tracee
			// SIGSYS handler, but exec→static descendants will lose
			// interception. Rare host shape.
			if debug {
				log.Printf("auto: chose systrap (dynamic target, seccomp=true memfd=false ptrace=%v)", ptraceOK)
			}
			systrapRun()
		case ptraceOK:
			// Try ptrace-seccomp first (it tries with-seccomp,
			// which fails-fast if seccomp is blocked, then
			// falls back to ptrace-only). Then plain ptrace-only.
			if debug {
				log.Printf("auto: chose ptrace cascade (dynamic target, seccomp=false ptrace=true)")
			}
			if err := traceSimple(); err == nil {
				return
			}
			if err := traceNoSeccomp(); err == nil {
				return
			}
			if debug {
				log.Printf("auto: ptrace cascade failed, falling back to preload")
			}
			libcOnlyRun()
		default:
			if debug {
				log.Printf("auto: chose preload (dynamic target, seccomp=false ptrace=false)")
			}
			libcOnlyRun()
		}
	default:
		log.Fatalf("unsupported transport %q (supported: auto, systrap-elf, systrap, systrap-supervised, systrap-static, preload, ptrace, ptrace-seccomp, ptrace-only; systrap-docker is a deprecated alias for systrap-elf)", transport)
	}
}

// isStaticELF returns true if `path` is an ELF binary with no
// PT_INTERP program header (i.e. a statically-linked executable
// with no dynamic linker reference). Returns false on any error,
// non-ELF input, or when path is empty — auto's caller should
// treat false as "treat as dynamic for cascade purposes".
//
// Used by `auto` to fail fast when the user wraps a static
// target on a host that blocks ptrace (no interception path
// possible).
func isStaticELF(path string) bool {
	if path == "" {
		return false
	}
	// Resolve PATH if path doesn't have a slash, so things like
	// `uwgwrapper -- mybinary` work consistently with
	// `uwgwrapper -- ./mybinary`.
	resolved := path
	if !strings.ContainsRune(path, '/') {
		if p, err := exec.LookPath(path); err == nil {
			resolved = p
		}
	}
	f, err := elf.Open(resolved)
	if err != nil {
		return false
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	return true
}

func appendEnv(env []string, kv string) []string {
	// kv = "KEY=VALUE". If KEY already in env, replace; else append.
	idx := strings.IndexByte(kv, '=')
	if idx < 0 {
		return append(env, kv)
	}
	prefix := kv[:idx+1]
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = kv
			return env
		}
	}
	return append(env, kv)
}

func fdproxySpawnArgs(listenPath, api, socketPath string, allowBind, allowLowBind bool, apiToken string, debug bool, allowedUIDs []uint32) []string {
	args := []string{
		"--mode=fdproxy",
		"--listen", listenPath,
		"--api", api,
		"--socket-path", socketPath,
		fmt.Sprintf("--allow-bind=%t", allowBind),
		fmt.Sprintf("--allow-lowbind=%t", allowLowBind),
	}
	if len(allowedUIDs) > 0 {
		parts := make([]string, 0, len(allowedUIDs))
		for _, u := range allowedUIDs {
			parts = append(parts, strconv.FormatUint(uint64(u), 10))
		}
		args = append(args, "--allow-uid", strings.Join(parts, ","))
	}
	if debug {
		args = append(args, "-v")
	}
	if apiToken != "" {
		args = append(args, "--token", apiToken)
	}
	return args
}

func runExecHelper(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("exec helper requires target program")
	}
	if os.Getenv("UWGS_TRACE_NO_NEW_PRIVS") != "0" {
		if err := uwgtrace.SetNoNewPrivileges(); err != nil {
			return err
		}
	}
	target, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	return syscall.Exec(target, args, os.Environ())
}

func runFDProxy(api, apiToken, socketPath, listenPath string, allowBind, allowLowBind, verbose bool, allowedUIDs []uint32) {
	if listenPath == "" {
		listenPath = "/tmp/uwgfdproxy.sock"
	}
	server, err := fdproxy.ListenWithOptions(fdproxy.Options{
		Path:         listenPath,
		API:          api,
		Token:        apiToken,
		SocketPath:   socketPath,
		Logger:       log.Default(),
		AllowBind:    allowBind,
		AllowLowBind: allowLowBind,
		Verbose:      verbose,
		AllowedUIDs:  allowedUIDs,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}

func stdioConnectTarget(flagValue string, args []string) (string, error) {
	if flagValue != "" {
		if len(args) != 0 {
			return "", fmt.Errorf("stdio mode accepts either --stdio-connect or one positional target, not both")
		}
		return flagValue, nil
	}
	if len(args) != 1 {
		return "", fmt.Errorf("stdio mode requires a single target like 100.64.0.2:22")
	}
	return args[0], nil
}

func parseStdioConnectTarget(raw string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(raw))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse stdio target %q: %w", raw, err)
	}
	if !ap.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("invalid stdio target %q", raw)
	}
	return ap, nil
}

func runStdioConnect(api, apiToken, socketPath, target string, stdin io.Reader, stdout io.Writer) error {
	dest, err := parseStdioConnectTarget(target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	up, err := socketproto.DialHTTP(ctx, api, apiToken, socketPath)
	if err != nil {
		return err
	}
	defer up.Close()

	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dest.Addr()),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    dest.Addr(),
		DestPort:  dest.Port(),
	})
	if err != nil {
		return err
	}
	id := socketproto.ClientIDBase + 1
	if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		return err
	}
	frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
	if err != nil {
		return err
	}
	if frame.ID != id {
		return fmt.Errorf("unexpected socket response id %d", frame.ID)
	}
	switch frame.Action {
	case socketproto.ActionAccept:
		if _, err := socketproto.DecodeAccept(frame.Payload); err != nil {
			return err
		}
	case socketproto.ActionClose:
		if len(frame.Payload) != 0 {
			return fmt.Errorf("connect rejected: %s", string(frame.Payload))
		}
		return errors.New("connect rejected")
	default:
		return fmt.Errorf("unexpected socket response action %d", frame.Action)
	}
	return proxyStdioSocket(up, id, stdin, stdout)
}

func proxyStdioSocket(up net.Conn, id uint64, stdin io.Reader, stdout io.Writer) error {
	var writeMu sync.Mutex
	writeFrame := func(frame socketproto.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return socketproto.WriteFrame(up, frame)
	}

	sendErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				payload := append([]byte(nil), buf[:n]...)
				if werr := writeFrame(socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: payload}); werr != nil {
					sendErr <- werr
					return
				}
			}
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				sendErr <- nil
				return
			}
			sendErr <- err
			return
		}
	}()

	for {
		frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
		if err != nil {
			var sendErrValue error
			select {
			case sendErrValue = <-sendErr:
			default:
			}
			if sendErrValue != nil {
				return sendErrValue
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if frame.ID != id {
			continue
		}
		switch frame.Action {
		case socketproto.ActionData:
			if _, err := stdout.Write(frame.Payload); err != nil {
				return err
			}
		case socketproto.ActionClose:
			select {
			case send := <-sendErr:
				if send != nil {
					return send
				}
			default:
			}
			return nil
		default:
			return fmt.Errorf("unexpected socket action %d", frame.Action)
		}
	}
}

func cleanupSpawnedFDProxy(cmd *exec.Cmd, listenPath string) {
	_ = os.Remove(listenPath)
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func waitUnixSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := os.Stat(path)
		if err == nil && st.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", path)
}

func waitFDProxyReady(path string, timeout time.Duration) error {
	if err := waitUnixSocket(path, timeout); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err != nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write([]byte("PING\n")); err != nil {
			_ = conn.Close()
			time.Sleep(25 * time.Millisecond)
			continue
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if err == nil && strings.TrimSpace(line) == "PONG" {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for fdproxy readiness on %s", path)
}

func ensureEmbeddedPreload() (string, error) {
	if len(embeddedPreload) == 0 {
		return "", errors.New("embedded preload payload missing")
	}
	sum := sha256.Sum256(embeddedPreload)
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("uwgwrapper-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("uwgpreload-%x.so", sum[:8]))
	if data, err := os.ReadFile(path); err == nil {
		if sha256.Sum256(data) == sum {
			return path, nil
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, embeddedPreload, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

func prepareSharedState() (*uwgshared.Table, error) {
	var secret uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &secret); err != nil {
		return nil, err
	}
	if secret == 0 {
		secret = 1
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("uwgwrapper-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(dir, "shared-state-*.bin")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	_ = file.Close()
	return uwgshared.Create(path, secret)
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func prependEnvPath(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			cur := strings.TrimPrefix(entry, prefix)
			if cur == "" {
				env[i] = prefix + value
			} else if !containsPath(cur, value) {
				env[i] = prefix + value + ":" + cur
			}
			return env
		}
	}
	return append(env, prefix+value)
}

func containsPath(list, value string) bool {
	for _, part := range strings.Split(list, ":") {
		if part == value {
			return true
		}
	}
	return false
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func boolString(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func init() {
	log.SetFlags(0)
	log.SetPrefix("uwgwrapper: ")
}
