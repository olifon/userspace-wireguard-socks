//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAllowUIDRelaxesSharedStateAndFDProxyPerms pins the apache2-class
// regression fix: when --allow-uid is set, both the per-run shared-
// state file under /tmp/uwgwrapper-$UID/ and the fdproxy AF_UNIX
// manager socket must be mode 0o666 instead of the default 0o600.
// Without that, setuid'd workers (apache www-data, postgres
// `postgres`, mariadb mysql) can't read or write the proxied-fd
// state and every wrapped syscall fails with EACCES.
//
// The test launches a wrapper subprocess that just spawns a long
// sleep — long enough for the test to inspect both filesystem
// objects before tearing the wrapper down. We do NOT need a real
// uwgsocks running for this; the fdproxy comes up against any URL
// because we never actually issue a connect.
//
// Without --allow-uid, both objects must be 0o600.
func TestAllowUIDRelaxesSharedStateAndFDProxyPerms(t *testing.T) {
	// Build the wrapper binary into a tmp path so we don't depend on
	// $PATH and don't conflict with parallel tests.
	repo := filepath.Clean(filepath.Join("..", ".."))
	wrapperBin := filepath.Join(t.TempDir(), "uwgwrapper")
	build := exec.Command("go", "build", "-o", wrapperBin, "./cmd/uwgwrapper")
	build.Dir = repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build wrapper: %v\n%s", err, out)
	}

	cases := []struct {
		name      string
		allowUID  string
		wantMode  os.FileMode
		wantSock  os.FileMode
	}{
		{name: "default_locked_to_owner", allowUID: "", wantMode: 0o600, wantSock: 0o600},
		{name: "allow_uid_relaxes_both", allowUID: "33", wantMode: 0o666, wantSock: 0o666},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sockPath := filepath.Join(t.TempDir(), "fdproxy.sock")
			args := []string{
				"-v",
				"--api=http://127.0.0.1:1", // bogus — fdproxy starts before any dial
				"--socket-path=/uwg/socket",
				"--listen=" + sockPath,
				"--no-new-privileges=false",
				"--transport=preload",
			}
			if tc.allowUID != "" {
				args = append(args, "--allow-uid="+tc.allowUID)
			}
			args = append(args, "--", "/bin/sleep", "30")
			cmd := exec.Command(wrapperBin, args...)
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				t.Fatalf("start wrapper: %v", err)
			}
			// Drain stderr in a goroutine to avoid backpressure on the
			// wrapper. We don't actually need the contents — just don't
			// want a full pipe.
			go func() {
				r := bufio.NewReader(stderr)
				for {
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
				}
			}()
			killed := false
			defer func() {
				if !killed {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					_ = cmd.Wait()
				}
			}()
			// Poll for the shared-state file + fdproxy socket. The
			// wrapper creates both very early (before exec'ing the
			// child) so polling for ~3s is generous.
			deadline := time.Now().Add(5 * time.Second)
			var sockInfo, stateInfo os.FileInfo
			var statePath string
			for time.Now().Before(deadline) {
				if info, err := os.Stat(sockPath); err == nil && info.Mode()&os.ModeSocket != 0 {
					sockInfo = info
				}
				// shared-state file lives at /tmp/uwgwrapper-$UID/shared-state-*.bin
				// The directory might also contain stale files; we want
				// the freshest one (mtime within the last few seconds).
				dir := fmt.Sprintf("/tmp/uwgwrapper-%d", os.Getuid())
				entries, _ := os.ReadDir(dir)
				var newest os.FileInfo
				var newestPath string
				for _, e := range entries {
					if !strings.HasPrefix(e.Name(), "shared-state-") {
						continue
					}
					full := filepath.Join(dir, e.Name())
					info, err := os.Stat(full)
					if err != nil {
						continue
					}
					if newest == nil || info.ModTime().After(newest.ModTime()) {
						newest = info
						newestPath = full
					}
				}
				if newest != nil && time.Since(newest.ModTime()) < 5*time.Second {
					stateInfo = newest
					statePath = newestPath
				}
				if sockInfo != nil && stateInfo != nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if sockInfo == nil {
				t.Fatalf("fdproxy socket %s never appeared", sockPath)
			}
			if stateInfo == nil {
				t.Fatalf("shared-state file in /tmp/uwgwrapper-%d/ never appeared", os.Getuid())
			}
			gotSock := sockInfo.Mode().Perm()
			gotState := stateInfo.Mode().Perm()
			if gotSock != tc.wantSock {
				t.Errorf("fdproxy socket %s mode = %#o, want %#o", sockPath, gotSock, tc.wantSock)
			}
			if gotState != tc.wantMode {
				t.Errorf("shared-state file %s mode = %#o, want %#o", statePath, gotState, tc.wantMode)
			}
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
			killed = true
		})
	}
}
