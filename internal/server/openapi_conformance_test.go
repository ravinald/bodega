package server

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pins"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// specPathsNotDocumented lists routes the OpenAPI document deliberately does
// not describe. Each needs a reason, because an entry here is the difference
// between "not part of the API surface" and "nobody got round to it".
//
// The registry proxy routes speak their ecosystems' own protocols — PEP 503,
// GOPROXY, the npm registry API, the cargo sparse index, the Debian archive
// layout, the FreeBSD pkg repository layout, git smart-HTTP — and a client
// generator reading this document has no use for them. /healthz and the web UI are not part of the API either.
var specPathsNotDocumented = map[string]string{
	"/apt/":       "Debian archive layout, consumed by apt rather than by a generated client",
	"/pypi/":      "PEP 503 simple index",
	"/git/":       "git smart-HTTP and bundle downloads",
	"/binaries/":  "raw artifact downloads",
	"/go/":        "GOPROXY protocol",
	"/helm/":      "helm chart repository protocol",
	"/npm/":       "npm registry API",
	"/cargo/":     "cargo sparse index protocol",
	"/freebsd/":   "FreeBSD pkg repository layout, consumed by pkg rather than by a generated client",
	"/distfiles/": "ports DISTDIR layout, consumed by do-fetch.sh through MASTER_SITE_OVERRIDE",
	"/healthz":    "liveness probe, not part of the API surface",
	"/ui":         "web UI",
	"/static/":    "web UI assets",
}

type openAPIDoc struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Parameters map[string]struct {
			Schema struct {
				Enum []string `yaml:"enum"`
			} `yaml:"schema"`
		} `yaml:"parameters"`
		Schemas map[string]struct {
			Properties map[string]any `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) openAPIDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc openAPIDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	return doc
}

// Three type lists in the spec are hand-maintained, and cargo went missing from
// the first two until B40 corrected them by hand. This test then guarded those
// two and not the third, so PackageManifest.type kept the stale seven-type list
// and nothing reported it: a spec a client generates from is wrong in a way no
// server test can see.
func TestOpenAPITypeListsMatchAllTypes(t *testing.T) {
	doc := loadSpec(t)

	enum := doc.Components.Parameters["PackageType"].Schema.Enum
	if len(enum) == 0 {
		t.Fatal("PackageType parameter has no enum; the spec moved and this test did not")
	}
	assertSameSet(t, "PackageType enum", enum, manifest.AllTypes)

	props := doc.Components.Schemas["PackagesResponse"].Properties
	if len(props) == 0 {
		t.Fatal("PackagesResponse has no properties; the spec moved and this test did not")
	}
	got := make([]string, 0, len(props))
	for k := range props {
		got = append(got, k)
	}
	assertSameSet(t, "PackagesResponse properties", got, manifest.AllTypes)

	assertSameSet(t, "PackageManifest.type enum", manifestTypeEnum(t, doc), manifest.AllTypes)
}

// manifestTypeEnum digs the PackageManifest.type enum out of the untyped
// properties map. Properties is map[string]any rather than a struct because
// every schema in the document shares it, and only this one field carries a
// type list worth holding to AllTypes.
func manifestTypeEnum(t *testing.T, doc openAPIDoc) []string {
	t.Helper()
	props := doc.Components.Schemas["PackageManifest"].Properties
	if len(props) == 0 {
		t.Fatal("PackageManifest has no properties; the spec moved and this test did not")
	}
	field, ok := props["type"].(map[string]any)
	if !ok {
		t.Fatal("PackageManifest.type is not a mapping; the spec moved and this test did not")
	}
	raw, ok := field["enum"].([]any)
	if !ok {
		t.Fatal("PackageManifest.type has no enum; the spec moved and this test did not")
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("PackageManifest.type enum holds %T, want string", v)
		}
		out = append(out, s)
	}
	return out
}

// Every route the server registers is either in the spec or in the skip list
// with a reason. Four operations were routed and undocumented when this was
// written.
func TestOpenAPIDocumentsEveryAPIRoute(t *testing.T) {
	doc := loadSpec(t)
	if len(doc.Paths) == 0 {
		t.Fatal("spec has no paths")
	}

	srv := newServer(&config.Config{}, manifest.NewLocalStore(t.TempDir()),
		nil, ":0", nil)
	if len(srv.routePatterns) == 0 {
		t.Fatal("no routes recorded; registerRoutes no longer reports what it registered")
	}

	for _, pattern := range srv.routePatterns {
		path := patternPath(pattern)
		if skipReason(path) != "" {
			continue
		}
		if _, ok := doc.Paths[path]; !ok {
			t.Errorf("route %q is registered and undocumented: add it to api/openapi.yaml, or to specPathsNotDocumented with a reason", pattern)
		}
	}
}

// The reverse: a documented path nothing serves is a client generator writing
// calls that 404.
func TestOpenAPIDocumentsNoRouteTheServerLacks(t *testing.T) {
	doc := loadSpec(t)
	srv := newServer(&config.Config{}, manifest.NewLocalStore(t.TempDir()),
		nil, ":0", nil)

	registered := make(map[string]bool, len(srv.routePatterns))
	for _, p := range srv.routePatterns {
		registered[patternPath(p)] = true
	}
	for path := range doc.Paths {
		if !registered[path] {
			t.Errorf("spec documents %q, which the server does not route", path)
		}
	}
}

// patternPath strips the method from a ServeMux pattern, so
// "GET /api/v1/status" becomes "/api/v1/status". A wildcard keeps its braces,
// which is the spec's own spelling.
func patternPath(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = pattern[i+1:]
	}
	return strings.TrimSuffix(pattern, "...}") + map[bool]string{true: "}", false: ""}[strings.HasSuffix(pattern, "...}")]
}

func skipReason(path string) string {
	for prefix, reason := range specPathsNotDocumented {
		if path == prefix || strings.HasPrefix(path, prefix) {
			return reason
		}
	}
	return ""
}

func assertSameSet(t *testing.T, what string, got, want []string) {
	t.Helper()
	assertSameStrings(t, what, "manifest.AllTypes", got, want)
}

func assertSameStrings(t *testing.T, what, wantLabel string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("%s = [%s], %s = [%s]", what, strings.Join(g, ", "), wantLabel, strings.Join(w, ", "))
	}
}

// A response schema drifts from the struct it documents in silence: the server
// keeps answering with every field, and only a client generated from the
// document is missing them. Six of aptStatus's twelve keys went undeclared
// because nothing compared the two, and `mirrored` is the one an operator
// reads first — it is what separates a codename bodega generates from one it
// proxies.
//
// schemaStructs is the coverage, and TestOpenAPISchemaTableCoversTheDocument
// holds it to the document: a component schema with no row here and no reason
// in schemasWithoutStruct fails the gate, so a schema cannot be added without
// naming what it documents.
var schemaStructs = map[string]any{
	"StatusResponse":     statusResponse{},
	"SpoolStats":         spoolStats{},
	"BackendEntryStatus": backendEntryStatus{},
	"AptStatus":          aptStatus{},
	"AptUnservedEntry":   aptUnservedEntry{},
	"AptSources":         aptsources.Sources{},
	"FreeBSDStatus":      freebsdStatus{},
	"FreeBSDRepo":        pkgrepos.Repo{},
	"ConfigResponse":     configResponse{},
	"ImportResponse":     ImportResponse{},
	"ImportResult":       ImportResult{},
	"PackageManifest":    manifest.PackageManifest{},
	"VersionEntry":       manifest.VersionEntry{},
	"BuildEnv":           manifest.BuildEnv{},
	"Dependency":         manifest.Dependency{},
	"Checksum":           manifest.Checksum{},
	"PolicyRule":         audit.PolicyInfo{},
	"AuditEvent":         audit.StoredEvent{},
	"TokenInfo":          audit.TokenInfo{},
	"ProfilePin":         pins.Pin{},
	"ProfilePinOSV":      pins.OSVState{},
}

var schemasWithoutStruct = map[string]string{
	"Error":            "written as a map literal at each call site; no type carries it",
	"PackagesResponse": "a map keyed by package type, held to manifest.AllTypes by TestOpenAPITypeListsMatchAllTypes",
}

func TestOpenAPISchemaTableCoversTheDocument(t *testing.T) {
	doc := loadSpec(t)
	for name := range doc.Components.Schemas {
		_, row := schemaStructs[name]
		_, exempt := schemasWithoutStruct[name]
		switch {
		case row && exempt:
			t.Errorf("schema %s is in both schemaStructs and schemasWithoutStruct; keep one", name)
		case !row && !exempt:
			t.Errorf("schema %s documents no struct in schemaStructs; add the row, or a reason to schemasWithoutStruct", name)
		}
	}
	for name := range schemaStructs {
		if _, ok := doc.Components.Schemas[name]; !ok {
			t.Errorf("schemaStructs names %s, which the document does not define", name)
		}
	}
	for name := range schemasWithoutStruct {
		if _, ok := doc.Components.Schemas[name]; !ok {
			t.Errorf("schemasWithoutStruct names %s, which the document does not define", name)
		}
	}
}

// Property names alone pass a table row mapped to the wrong struct, and a
// $ref pointing at a schema documenting some other type. So each property
// that references a component is also held to the Go field carrying it: the
// field's element type must be the one schemaStructs names for that schema.
func TestOpenAPISchemasMatchResponseStructs(t *testing.T) {
	doc := loadSpec(t)

	documented := make(map[reflect.Type]string, len(schemaStructs))
	for name, v := range schemaStructs {
		documented[reflect.TypeOf(v)] = name
	}

	for schema, v := range schemaStructs {
		props := doc.Components.Schemas[schema].Properties
		if len(props) == 0 {
			t.Errorf("schema %s has no properties; the spec moved and this test did not", schema)
			continue
		}
		rt := reflect.TypeOf(v)
		fields := jsonFields(t, rt)

		declared := make([]string, 0, len(props))
		for k := range props {
			declared = append(declared, k)
		}
		wire := make([]string, 0, len(fields))
		for k := range fields {
			wire = append(wire, k)
		}
		assertSameStrings(t, schema+" properties", rt.String()+" JSON fields", declared, wire)

		for prop, ft := range fields {
			spec, ok := props[prop]
			if !ok {
				continue
			}
			elem := elemType(ft)
			ref := schemaRef(spec)
			switch want, isDoc := documented[elem]; {
			case ref != "" && reflect.TypeOf(schemaStructs[ref]) != elem:
				t.Errorf("%s.%s references %s, but %s carries %s", schema, prop, ref, rt, ft)
			case ref == "" && isDoc:
				t.Errorf("%s.%s is inline, but %s carries %s, which schema %s documents; use a $ref", schema, prop, rt, ft, want)
			}
		}
	}
}

// schemaRef names the component a property references directly, through
// items or additionalProperties, or through a one-element allOf (the form
// OpenAPI 3.0 needs to put a description beside a $ref). Empty when inline.
func schemaRef(prop any) string {
	m, _ := prop.(map[string]any)
	if m == nil {
		return ""
	}
	if ref, ok := m["$ref"].(string); ok {
		return strings.TrimPrefix(ref, "#/components/schemas/")
	}
	for _, k := range []string{"items", "additionalProperties"} {
		if ref := schemaRef(m[k]); ref != "" {
			return ref
		}
	}
	if all, ok := m["allOf"].([]any); ok && len(all) == 1 {
		return schemaRef(all[0])
	}
	return ""
}

// elemType strips the pointers, slices and maps between a field and the
// struct it carries, which is the type a $ref under items or
// additionalProperties documents.
func elemType(t reflect.Type) reflect.Type {
	for {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			t = t.Elem()
		default:
			return t
		}
	}
}

// jsonFields is the wire shape of rt: the json name of every exported field,
// minus its options, skipping `json:"-"`, with the type each carries. An
// untagged embedded struct is walked, because encoding/json promotes its
// fields to the top level. Two fields answering to one name is fatal rather
// than resolved: encoding/json settles it by depth and tag rules this does not
// model, and guessing would report a shape the server does not emit.
func jsonFields(t *testing.T, rt reflect.Type) map[string]reflect.Type {
	t.Helper()
	out := make(map[string]reflect.Type, rt.NumField())
	add := func(name string, ft reflect.Type) {
		if _, dup := out[name]; dup {
			t.Fatalf("%s emits %q twice; jsonFields does not resolve name collisions", rt, name)
		}
		out[name] = ft
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		embedded := f.Type
		if embedded.Kind() == reflect.Pointer {
			embedded = embedded.Elem()
		}
		if f.Anonymous && name == "" && embedded.Kind() == reflect.Struct {
			for k, ft := range jsonFields(t, embedded) {
				add(k, ft)
			}
			continue
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		add(name, f.Type)
	}
	return out
}
