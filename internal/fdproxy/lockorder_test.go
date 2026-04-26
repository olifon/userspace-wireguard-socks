//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package fdproxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestLockOrderInvariant statically asserts the load-bearing
// fdproxy lock-order rule: in any function that acquires both the
// server-level mutex (`s.mu` / `g.server.mu`) and a group-level mutex
// (`g.mu`), the server mutex MUST be acquired first. Acquiring the
// group mutex first creates the reverse `g.mu → s.mu` order, which
// can deadlock against `addMemberLocked` and `removeMember`.
//
// The check is intentionally simple: walk the AST of every .go file
// in this package, find all `*.Lock()` selector calls in each
// function body in source order, and if both kinds appear, fail
// when the group lock comes first. False positives are easy to
// silence (rename the variable, restructure), false negatives would
// just mean the test missed a violation — which is also what a code
// reviewer would do.
//
// This test exists in addition to the dynamic stress tests because:
//   1. The dynamic tests need contention to surface a race; a benign
//      lock-order violation that never deadlocks under low contention
//      still appears in production.
//   2. A static test catches violations the moment they're added,
//      without needing -race or stress runs.
//
// See docs/internal/lock-map-fdproxy.md for the rule's rationale.
func TestLockOrderInvariant(t *testing.T) {
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	var violations []string
	for _, path := range matches {
		// Skip test files — stress tests intentionally exercise the
		// lock-order from clean test fixtures, not production paths.
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			// Collect every Lock/Unlock selector call in body order so
			// we can simulate "what is currently held" as we walk.
			// Releasing a held lock and re-acquiring it (in either
			// order) is fine — what we forbid is *nesting* a server
			// lock acquisition inside a group lock acquisition.
			type event struct {
				kind   string // "server" or "group"
				op     string // "lock" or "unlock"
				pos    token.Position
			}
			var events []event
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				kind, op := classifyMutexCall(call)
				if kind == "" {
					return true
				}
				events = append(events, event{
					kind: kind,
					op:   op,
					pos:  fset.Position(call.Pos()),
				})
				return true
			})

			// State machine: walk events, track which locks are
			// currently held. Flag a violation only when we
			// acquire the server mutex while the group mutex is
			// currently held.
			groupHeld := false
			for _, e := range events {
				switch {
				case e.kind == "group" && e.op == "lock":
					groupHeld = true
				case e.kind == "group" && e.op == "unlock":
					groupHeld = false
				case e.kind == "server" && e.op == "lock":
					if groupHeld {
						violations = append(violations,
							formatViolation(fn.Name.Name, e.pos))
						return true // keep scanning other functions
					}
				}
			}
			return true
		})
	}

	if len(violations) > 0 {
		for _, v := range violations {
			t.Error(v)
		}
		t.Fatal("lock-order rule violated — group mutex acquired before server mutex; see docs/internal/lock-map-fdproxy.md")
	}
}

// classifyMutexCall returns ("server"|"group", "lock"|"unlock") for
// recognised mutex Lock/Unlock/RLock/RUnlock calls and ("","") for
// anything else. Pattern matched:
//
//   s.mu.Lock()           → ("server", "lock")
//   s.mu.Unlock()         → ("server", "unlock")
//   g.server.mu.Lock()    → ("server", "lock")
//   g.server.mu.Unlock()  → ("server", "unlock")
//   g.mu.Lock()           → ("group",  "lock")
//   g.mu.Unlock()         → ("group",  "unlock")
//
// RLock / RUnlock are treated as Lock / Unlock for the purposes of
// the lock-order rule (acquiring a server lock while holding a
// group read-lock is just as bad as while holding a group write-lock).
func classifyMutexCall(call *ast.CallExpr) (kind, op string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	switch sel.Sel.Name {
	case "Lock", "RLock":
		op = "lock"
	case "Unlock", "RUnlock":
		op = "unlock"
	default:
		return "", ""
	}
	muSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok || muSel.Sel.Name != "mu" {
		return "", ""
	}
	switch x := muSel.X.(type) {
	case *ast.SelectorExpr:
		if x.Sel.Name == "server" {
			return "server", op
		}
	case *ast.Ident:
		switch x.Name {
		case "s":
			return "server", op
		case "g":
			return "group", op
		}
	}
	return "", ""
}

func formatViolation(funcName string, p token.Position) string {
	return funcName + " at " + p.String() +
		": acquired server-level mutex while group-level mutex is held (lock order is s.mu → g.mu)"
}

// TestLockOrderAnalyzerCatchesViolation parses a synthetic snippet that
// deliberately violates the rule and asserts the analyzer flags it.
// Without this self-test, a future refactor could silently break the
// classification logic and leave TestLockOrderInvariant returning a
// false-negative pass forever.
func TestLockOrderAnalyzerCatchesViolation(t *testing.T) {
	src := `package fdproxy

import "sync"

type fakeServer struct{ mu sync.Mutex }
type fakeGroup struct {
	server *fakeServer
	mu     sync.Mutex
}

func (g *fakeGroup) bad() {
	g.mu.Lock()           // group acquired first
	g.server.mu.Lock()    // then server — WRONG, must be flagged
	g.server.mu.Unlock()
	g.mu.Unlock()
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		groupHeld := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			kind, op := classifyMutexCall(call)
			switch {
			case kind == "group" && op == "lock":
				groupHeld = true
			case kind == "group" && op == "unlock":
				groupHeld = false
			case kind == "server" && op == "lock" && groupHeld:
				found = true
			}
			return true
		})
		return true
	})
	if !found {
		t.Fatal("analyzer self-test: synthetic violation was NOT flagged — classifyMutexCall is broken")
	}
}

