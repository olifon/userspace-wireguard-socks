// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build windows

package uwgshared

import (
	"os"
	"sync"
)

const (
	MaxTrackedFD    = 65536
	MaxTrackedSlots = 65536
	SharedMagic     = 0x55574753
	SharedVersion   = 6
	MaxGuardSlots   = 256

	KindNone         = 0
	KindTCPStream    = 1
	KindUDPConnected = 2
	KindUDPListener  = 3
	KindTCPListener  = 4
)

type TrackedFD struct {
	Active       int32
	Domain       int32
	Type         int32
	Protocol     int32
	Proxied      int32
	Kind         int32
	HotReady     int32
	Bound        int32
	ReuseAddr    int32
	ReusePort    int32
	BindFamily   int32
	BindPort     uint16
	BindIP       [46]byte
	RemoteFamily int32
	RemotePort   uint16
	RemoteIP     [46]byte
	SavedFL      int32
	SavedFDFL    int32
}

type GuardDisposition int

const (
	GuardUnlocked GuardDisposition = iota
	GuardOwnedBySelf
	GuardOwnedByOther
)

type Table struct {
	path   string
	secret uint64

	mu      sync.RWMutex
	tracked map[int]map[int]TrackedFD
}

func Create(path string, secret uint64) (*Table, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return &Table{
		path:    path,
		secret:  secret,
		tracked: make(map[int]map[int]TrackedFD),
	}, nil
}

func Open(path string) (*Table, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return &Table{
		path:    path,
		tracked: make(map[int]map[int]TrackedFD),
	}, nil
}

func (t *Table) Close(removeFile bool) error {
	if t == nil {
		return nil
	}
	if removeFile && t.path != "" {
		if err := os.Remove(t.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (t *Table) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

func (t *Table) Secret() uint64 {
	if t == nil {
		return 0
	}
	return t.secret
}

func (t *Table) GuardDisposition(tid int) GuardDisposition {
	_ = t
	_ = tid
	return GuardUnlocked
}

func (t *Table) GuardOwners() (int32, []int32) {
	_ = t
	return 0, nil
}

func (t *Table) ClearGuardReaderOwner(tid int32) bool {
	_ = t
	_ = tid
	return false
}

func (t *Table) ClearGuardWriterOwner(tid int32) bool {
	_ = t
	_ = tid
	return false
}

func (t *Table) WithReadLock(fn func()) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	fn()
}

func (t *Table) WithWriteLock(fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fn()
}

func (t *Table) Snapshot(pid, fd int) TrackedFD {
	if t == nil {
		return TrackedFD{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if fds := t.tracked[pid]; fds != nil {
		return fds[fd]
	}
	return TrackedFD{}
}

func (t *Table) Update(pid, fd int, fn func(entry *TrackedFD)) {
	if t == nil || fn == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tracked == nil {
		t.tracked = make(map[int]map[int]TrackedFD)
	}
	fds := t.tracked[pid]
	if fds == nil {
		fds = make(map[int]TrackedFD)
		t.tracked[pid] = fds
	}
	entry := fds[fd]
	fn(&entry)
	fds[fd] = entry
}

func (t *Table) Clear(pid, fd int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if fds := t.tracked[pid]; fds != nil {
		delete(fds, fd)
		if len(fds) == 0 {
			delete(t.tracked, pid)
		}
	}
}

func (t *Table) CopyProcess(srcPID, dstPID int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	src := t.tracked[srcPID]
	if src == nil {
		delete(t.tracked, dstPID)
		return
	}
	dst := make(map[int]TrackedFD, len(src))
	for fd, entry := range src {
		dst[fd] = entry
	}
	t.tracked[dstPID] = dst
}

func (t *Table) ClearProcess(pid int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tracked, pid)
}

func (t *Table) ProcessFDs(pid int) []int {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	fds := t.tracked[pid]
	if len(fds) == 0 {
		return nil
	}
	out := make([]int, 0, len(fds))
	for fd := range fds {
		out = append(out, fd)
	}
	return out
}

func BytesToString(buf []byte) string {
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

func StringToBytes(dst []byte, value string) {
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, value)
}
