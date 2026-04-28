// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// One-shot helper used to bootstrap docstring coverage in
// internal/config/. Reads docs/reference/config-reference.md, extracts
// (yaml-key → comment) pairs from lines like:
//
//	  private_key: ""    # Base64 WireGuard private key.
//
// Then walks Go source under internal/config/ and internal/transport/,
// finds struct fields with a matching yaml tag, and inserts the comment
// as a doc comment if the field doesn't already have one. Idempotent.
//
// After this runs, all bootstrapped fields have a docstring source-of-
// truth; tools/genconfigref/--audit will only flag truly novel fields.
//
// Usage: go run ./tools/lifteenum --apply
//
// The yaml-key matching is exact and unscoped (no struct-name
// disambiguation), so collisions across structs use the FIRST match.
// In practice every yaml tag in this repo is globally unique within the
// config surface, so this is fine.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	apply := flag.Bool("apply", false, "actually rewrite files (default: dry-run)")
	flag.Parse()

	pairs, err := readPairs("docs/reference/config-reference.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("loaded %d (yaml, comment) pairs from config-reference.md\n", len(pairs))

	dirs := []string{"internal/config", "internal/transport", "internal/acl"}
	totalFiles, totalFieldsBackfilled := 0, 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			n, err := backfillFile(path, pairs, *apply)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
				continue
			}
			if n > 0 {
				fmt.Printf("%s: backfilled %d fields\n", path, n)
				totalFiles++
				totalFieldsBackfilled += n
			}
		}
	}
	fmt.Printf("\ntotal: %d fields across %d files\n", totalFieldsBackfilled, totalFiles)
	if !*apply {
		fmt.Println("(dry-run — pass --apply to actually rewrite)")
	}
}

var commentLineRe = regexp.MustCompile(`^(\s+)([a-z_]+)\s*:\s*[^#]*#\s*(.*?)\s*$`)

func readPairs(path string) (map[string]string, error) {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := commentLineRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		key := m[2]
		comment := strings.TrimSpace(m[3])
		if comment == "" {
			continue
		}
		// Don't overwrite — keep the first occurrence in case the
		// same yaml key shows up under multiple parent paths.
		if _, ok := out[key]; !ok {
			out[key] = comment
		}
	}
	return out, sc.Err()
}

func backfillFile(path string, pairs map[string]string, apply bool) (int, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return 0, err
	}

	type backfill struct {
		offset  int    // byte offset in src where the field's line starts
		comment string // doc comment to insert (with leading "// ")
		indent  string // whitespace prefix for the field line
	}
	var bs []backfill

	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			if field.Doc != nil && strings.TrimSpace(field.Doc.Text()) != "" {
				continue
			}
			tag := ""
			if field.Tag != nil {
				tag = field.Tag.Value
			}
			yamlKey := extractYAMLKey(tag)
			if yamlKey == "" {
				continue
			}
			comment, ok := pairs[yamlKey]
			if !ok {
				continue
			}
			if len(field.Names) == 0 {
				continue
			}
			// Insertion point: start of the line containing the
			// first name of this field.
			pos := fset.Position(field.Names[0].Pos())
			lineStart := lineStartOffset(src, pos.Offset)
			indent := getIndent(src, lineStart)
			bs = append(bs, backfill{
				offset:  lineStart,
				comment: indent + "// " + comment + "\n",
				indent:  indent,
			})
		}
		return true
	})

	if len(bs) == 0 {
		return 0, nil
	}

	if !apply {
		return len(bs), nil
	}

	// Apply backwards so offsets stay valid as we splice.
	out := make([]byte, 0, len(src)+1024)
	last := len(src)
	// Sort descending by offset.
	for i := 0; i < len(bs); i++ {
		for j := i + 1; j < len(bs); j++ {
			if bs[j].offset > bs[i].offset {
				bs[i], bs[j] = bs[j], bs[i]
			}
		}
	}
	tail := append([]byte{}, src...)
	for _, b := range bs {
		// Insert b.comment at b.offset.
		tail = append(append(append([]byte{}, tail[:b.offset]...), []byte(b.comment)...), tail[b.offset:]...)
	}
	_ = last
	out = tail

	// gofmt the result.
	formatted, err := format.Source(out)
	if err != nil {
		return 0, fmt.Errorf("gofmt result: %w", err)
	}
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		return 0, err
	}
	return len(bs), nil
}

func extractYAMLKey(rawTag string) string {
	rawTag = strings.Trim(rawTag, "`")
	yamlIdx := strings.Index(rawTag, `yaml:"`)
	if yamlIdx < 0 {
		return ""
	}
	rest := rawTag[yamlIdx+len(`yaml:"`):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	v := rest[:end]
	if i := strings.Index(v, ","); i >= 0 {
		v = v[:i]
	}
	if v == "-" {
		return ""
	}
	return v
}

func lineStartOffset(src []byte, off int) int {
	if off > len(src) {
		off = len(src)
	}
	for off > 0 && src[off-1] != '\n' {
		off--
	}
	return off
}

func getIndent(src []byte, lineStart int) string {
	end := lineStart
	for end < len(src) && (src[end] == ' ' || src[end] == '\t') {
		end++
	}
	return string(src[lineStart:end])
}
