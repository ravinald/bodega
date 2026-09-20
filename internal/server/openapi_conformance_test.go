package server

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// specPathsNotDocumented lists routes the OpenAPI document deliberately does
// not describe. Each needs a reason, because an entry here is the difference
// between "not part of the API surface" and "nobody got round to it".
//
// The registry proxy routes speak their ecosystems' own protocols — PEP 503,
// GOPROXY, the npm registry API, the cargo sparse index, the Debian archive
// layout, git smart-HTTP — and a client generator reading this document has no
// use for them. /healthz and the web UI are not part of the API either.
var specPathsNotDocumented = map[string]string{
	"/apt/":      "Debian archive layout, consumed by apt rather than by a generated client",
	"/pypi/":     "PEP 503 simple index",
	"/git/":      "git smart-HTTP and bundle downloads",
	"/binaries/": "raw artifact downloads",
	"/go/":       "GOPROXY protocol",
	"/helm/":     "helm chart repository protocol",
	"/npm/":      "npm registry API",
	"/cargo/":    "cargo sparse index protocol",
	"/healthz":   "liveness probe, not part of the API surface",
	"/ui":        "web UI",
	"/static/":   "web UI assets",
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

// Both type lists in the spec are hand-maintained, and cargo went missing from
// both until B40 corrected them by hand. Nothing held either to the server.
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
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("%s = [%s], manifest.AllTypes = [%s]", what, strings.Join(g, ", "), strings.Join(w, ", "))
	}
}
