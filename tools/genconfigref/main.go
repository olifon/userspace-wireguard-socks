// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// genconfigref walks the canonical config struct, reads docstrings
// directly from the Go source via go/parser, derives defaults from
// config.Default(), and emits docs/reference/config-reference.md.
//
// Single source of truth: the Go struct + its // comments. Drift is
// caught by running this with --check (CI mode) instead of writing.
//
// Usage:
//
//	go run ./tools/genconfigref           # write the file
//	go run ./tools/genconfigref --check   # exit non-zero if file would change
//	go run ./tools/genconfigref --audit   # report fields with no docstring
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

const outputPath = "docs/reference/config-reference.md"

func main() {
	check := flag.Bool("check", false, "exit non-zero if the on-disk file would change")
	audit := flag.Bool("audit", false, "report fields missing docstrings; do not write")
	flag.Parse()

	docs, err := collectDocstrings()
	if err != nil {
		fatalf("collect docstrings: %v", err)
	}

	def := config.Default()
	out, missing := render(reflect.TypeOf(def), reflect.ValueOf(def), docs)

	if *audit {
		if len(missing) == 0 {
			fmt.Println("all fields have docstrings ✓")
			return
		}
		fmt.Printf("missing docstrings (%d):\n", len(missing))
		for _, m := range missing {
			fmt.Println("  -", m)
		}
		os.Exit(1)
	}

	if *check {
		existing, _ := os.ReadFile(outputPath)
		if string(existing) == out {
			return
		}
		fmt.Fprintf(os.Stderr, "%s out of date — run 'go run ./tools/genconfigref'\n", outputPath)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, []byte(out), 0o644); err != nil {
		fatalf("write %s: %v", outputPath, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", outputPath, len(out))
	if len(missing) > 0 {
		fmt.Printf("warning: %d fields are missing docstrings (run with --audit to list)\n", len(missing))
	}
}

// docKey identifies a struct field by its containing-type name and
// field name. e.g. "Config.WireGuard", "Peer.PublicKey".
type docKey struct {
	typeName, fieldName string
}

// collectDocstrings walks every Go source file in internal/config
// and internal/transport, parses it, and returns a map from
// (TypeName, FieldName) to the leading // comment. Picking up
// comments from reflect alone isn't possible — Go runtime drops
// comments — so we parse the source ourselves.
func collectDocstrings() (map[docKey]string, error) {
	out := map[docKey]string{}
	dirs := []string{
		"internal/config",
		"internal/transport",
		"internal/acl",
	}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					var doc string
					if field.Doc != nil {
						doc = strings.TrimSpace(field.Doc.Text())
					}
					if doc == "" {
						continue
					}
					for _, name := range field.Names {
						out[docKey{ts.Name.Name, name.Name}] = doc
					}
				}
				return true
			})
		}
	}
	return out, nil
}

// render walks t (must be a struct type) and emits a Markdown
// reference. Returns the rendered text and a list of fields with
// no docstring (in dotted-path form, e.g. "wireguard.peers[].endpoint").
func render(t reflect.Type, v reflect.Value, docs map[docKey]string) (string, []string) {
	var b bytes.Buffer
	var missing []string

	b.WriteString("<!-- Copyright (c) 2026 Reindert Pelsma -->\n")
	b.WriteString("<!-- SPDX-License-Identifier: ISC -->\n\n")
	b.WriteString("# Configuration reference\n\n")
	b.WriteString("> **Generated**. Do not edit by hand. Regenerate with:\n")
	b.WriteString("> ```\n")
	b.WriteString("> go run ./tools/genconfigref\n")
	b.WriteString("> ```\n")
	b.WriteString("> The source of truth is the struct definitions in `internal/config/` and\n")
	b.WriteString("> `internal/transport/`. Add a `// comment` above the field; it shows up here.\n\n")
	b.WriteString("Use [configuration.md](configuration.md) for behavior context behind these fields.\n\n")

	// Top-level: each Config field becomes a section.
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		yamlName := yamlTagName(f.Tag.Get("yaml"))
		if yamlName == "" || yamlName == "-" {
			continue
		}
		fmt.Fprintf(&b, "## `%s`\n\n", yamlName)
		doc := docs[docKey{t.Name(), f.Name}]
		if doc == "" {
			missing = append(missing, yamlName)
			b.WriteString("_(no doc comment in source — add one to `internal/config/`)_\n\n")
		} else {
			b.WriteString(doc)
			b.WriteString("\n\n")
		}
		var fv reflect.Value
		if v.IsValid() {
			fv = v.Field(i)
		}
		renderType(&b, f.Type, fv, yamlName, "  ", docs, &missing)
		b.WriteString("\n")
	}
	return b.String(), missing
}

// renderType emits the YAML-shape table for a type, recursing into
// nested structs. `prefix` is the indentation for nested entries.
// `path` is the dotted path used for missing-docstring reports.
func renderType(b *bytes.Buffer, t reflect.Type, v reflect.Value, path, prefix string, docs map[docKey]string, missing *[]string) {
	switch t.Kind() {
	case reflect.Ptr:
		if t.Elem().Kind() == reflect.Struct {
			renderType(b, t.Elem(), reflect.Value{}, path, prefix, docs, missing)
			return
		}
		// Pointer-to-scalar: treat as the scalar with " (optional)" hint.
		fmt.Fprintf(b, "%s_type:_ %s (optional)  ", prefix, t.Elem().String())
		writeDefault(b, v)
		return
	case reflect.Slice:
		elem := t.Elem()
		if elem.Kind() == reflect.Struct {
			fmt.Fprintf(b, "%s_type:_ list of objects, each with these keys:\n\n", prefix)
			renderStruct(b, elem, reflect.Value{}, path+"[]", prefix, docs, missing)
			return
		}
		fmt.Fprintf(b, "%s_type:_ list of %s  ", prefix, elem.String())
		writeDefault(b, v)
		return
	case reflect.Map:
		fmt.Fprintf(b, "%s_type:_ map[%s]%s\n", prefix, t.Key().String(), t.Elem().String())
		return
	case reflect.Struct:
		renderStruct(b, t, v, path, prefix, docs, missing)
		return
	default:
		fmt.Fprintf(b, "%s_type:_ %s  ", prefix, t.String())
		writeDefault(b, v)
		return
	}
}

func renderStruct(b *bytes.Buffer, t reflect.Type, v reflect.Value, path, prefix string, docs map[docKey]string, missing *[]string) {
	// Emit a YAML-shape block for this struct: each field on its
	// own line with key + brief inline description, then expanded
	// nested types follow.
	fmt.Fprintf(b, "%s```yaml\n", prefix)
	fmt.Fprintf(b, "%s%s:\n", prefix, lastSegment(path))
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		yamlName := yamlTagName(f.Tag.Get("yaml"))
		if yamlName == "" || yamlName == "-" {
			continue
		}
		typeStr := goTypeForYAML(f.Type)
		fmt.Fprintf(b, "%s  %s: %s\n", prefix, yamlName, typeStr)
	}
	fmt.Fprintf(b, "%s```\n\n", prefix)

	// Per-field doc lines.
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		yamlName := yamlTagName(f.Tag.Get("yaml"))
		if yamlName == "" || yamlName == "-" {
			continue
		}
		fullPath := path + "." + yamlName
		doc := docs[docKey{t.Name(), f.Name}]
		if doc == "" {
			*missing = append(*missing, fullPath)
		}
		fmt.Fprintf(b, "%s- **`%s`** ", prefix, yamlName)
		fmt.Fprintf(b, "(%s)", goTypeForYAML(f.Type))
		var fv reflect.Value
		if v.IsValid() {
			fv = v.Field(i)
		}
		if def := defaultLiteral(fv); def != "" {
			fmt.Fprintf(b, " — default: `%s`", def)
		}
		b.WriteString("  \n")
		if doc != "" {
			for _, line := range strings.Split(doc, "\n") {
				fmt.Fprintf(b, "%s  %s\n", prefix, line)
			}
		} else {
			fmt.Fprintf(b, "%s  _(no doc comment — add one in source)_\n", prefix)
		}
		b.WriteString("\n")
	}

	// Recurse into nested struct/slice-of-struct fields.
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		yamlName := yamlTagName(f.Tag.Get("yaml"))
		if yamlName == "" || yamlName == "-" {
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct {
			fmt.Fprintf(b, "%s### `%s.%s[]`\n\n", prefix, path, yamlName)
			var fv reflect.Value
			if v.IsValid() {
				fv = v.Field(i)
				if fv.Kind() == reflect.Slice && fv.Len() > 0 {
					fv = fv.Index(0)
				} else {
					fv = reflect.Value{}
				}
			}
			renderStruct(b, ft.Elem(), fv, path+"."+yamlName+"[]", prefix+"  ", docs, missing)
		} else if ft.Kind() == reflect.Struct {
			fmt.Fprintf(b, "%s### `%s.%s`\n\n", prefix, path, yamlName)
			var fv reflect.Value
			if v.IsValid() {
				fv = v.Field(i)
			}
			renderStruct(b, ft, fv, path+"."+yamlName, prefix+"  ", docs, missing)
		}
	}
}

// goTypeForYAML returns a short YAML-style type label for a Go type.
func goTypeForYAML(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Ptr:
		return goTypeForYAML(t.Elem()) + "?"
	case reflect.Slice:
		return "[" + goTypeForYAML(t.Elem()) + "]"
	case reflect.Map:
		return "map[" + goTypeForYAML(t.Key()) + "]" + goTypeForYAML(t.Elem())
	case reflect.Struct:
		return t.Name()
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "int"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.String:
		return "string"
	default:
		return t.String()
	}
}

// defaultLiteral formats v's value as a YAML-ish literal for the
// "default" annotation. Returns "" for zero values.
func defaultLiteral(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return ""
		}
		return defaultLiteral(v.Elem())
	case reflect.Bool:
		if !v.Bool() {
			return ""
		}
		return "true"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Int() == 0 {
			return ""
		}
		return fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.Uint() == 0 {
			return ""
		}
		return fmt.Sprintf("%d", v.Uint())
	case reflect.String:
		s := v.String()
		if s == "" {
			return ""
		}
		return fmt.Sprintf("%q", s)
	case reflect.Slice:
		if v.Len() == 0 {
			return ""
		}
		var parts []string
		for i := 0; i < v.Len(); i++ {
			if s := defaultLiteral(v.Index(i)); s != "" {
				parts = append(parts, s)
			}
		}
		sort.Strings(parts)
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return ""
}

func writeDefault(b *bytes.Buffer, v reflect.Value) {
	if def := defaultLiteral(v); def != "" {
		fmt.Fprintf(b, "_default:_ `%s`", def)
	}
	b.WriteString("\n\n")
}

func yamlTagName(tag string) string {
	if tag == "" {
		return ""
	}
	if i := strings.Index(tag, ","); i >= 0 {
		return tag[:i]
	}
	return tag
}

func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i+1:]
	}
	if i := strings.LastIndexByte(path, '['); i >= 0 {
		return path[:i]
	}
	return path
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
