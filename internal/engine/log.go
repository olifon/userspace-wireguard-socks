// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"io"
	"log"
	"strings"
)

// LeveledLogger is the logging interface accepted by the engine. Library
// embedders implement this to route engine output into their own log system
// and filter by level. Use WrapStdLogger to adapt a *log.Logger.
type LeveledLogger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Level controls the minimum verbosity emitted by WrapStdLogger.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ParseLevel converts a string level name to a Level constant. Unrecognised
// values map to LevelInfo.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// WrapStdLogger adapts a *log.Logger to LeveledLogger, filtering messages
// below level. The logger's existing prefix and flags are preserved; each
// message is prefixed with "[DEBUG] ", "[INFO] ", "[WARN] ", or "[ERROR] ".
func WrapStdLogger(l *log.Logger, level Level) LeveledLogger {
	return &stdLeveledLogger{l: l, level: level}
}

// DiscardLogger returns a LeveledLogger that silently drops all messages.
// Useful in tests and when embedding the engine without log output.
func DiscardLogger() LeveledLogger {
	return &stdLeveledLogger{l: log.New(io.Discard, "", 0), level: LevelError + 1}
}

type stdLeveledLogger struct {
	l     *log.Logger
	level Level
}

func (s *stdLeveledLogger) Debugf(format string, args ...any) {
	if s.level <= LevelDebug {
		s.l.Printf("[DEBUG] "+format, args...)
	}
}

func (s *stdLeveledLogger) Infof(format string, args ...any) {
	if s.level <= LevelInfo {
		s.l.Printf("[INFO] "+format, args...)
	}
}

func (s *stdLeveledLogger) Warnf(format string, args ...any) {
	if s.level <= LevelWarn {
		s.l.Printf("[WARN] "+format, args...)
	}
}

func (s *stdLeveledLogger) Errorf(format string, args ...any) {
	if s.level <= LevelError {
		s.l.Printf("[ERROR] "+format, args...)
	}
}
