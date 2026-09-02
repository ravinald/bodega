package hostpkg

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

func fixture(t *testing.T, name string) *bytes.Reader {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return bytes.NewReader(data)
}

func names(pms []manifest.PackageManifest) map[string]string {
	out := make(map[string]string, len(pms))
	for _, pm := range pms {
		out[pm.Name] = pm.Versions[0].Version
	}
	return out
}

// TestAptSkipsRemovedButNotPurged is the reason ParseApt reads the status
// field at all. The ns0 capture has 774 rows in the dpkg database and 635
// packages actually installed; the other 139 are mostly superseded kernel
// images that were removed with their config files kept. An importer that
// trusts the row count mirrors 139 packages the host does not have.
func TestAptSkipsRemovedButNotPurged(t *testing.T) {
	res, err := ParseApt(fixture(t, "apt-dpkg-query-ns0.txt"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	const installed = 635
	if got := len(res.Packages); got != installed {
		t.Errorf("imported %d packages, want %d: the dpkg status field was not honored", got, installed)
	}
	for _, pm := range res.Packages {
		if pm.Name == "linux-image-5.15.0-107-generic" {
			t.Error("imported a kernel image that is removed, config files retained")
		}
	}
	if len(res.Warnings) == 0 {
		t.Error("139 rows were skipped and nothing said so")
	}
}

// TestAptFormatsAgree cross-checks the two inventory formats against each
// other. Both captures come from the same host at the same moment, so a
// disagreement is a parser bug in one of them, and neither parser grades its
// own homework.
func TestAptFormatsAgree(t *testing.T) {
	for _, host := range []struct{ dpkg, list string }{
		{"apt-dpkg-query-ns0.txt", "apt-list-installed-ns0.txt"},
		{"apt-dpkg-query-ubuntu2404.txt", "apt-list-installed-ubuntu2404.txt"},
	} {
		t.Run(host.dpkg, func(t *testing.T) {
			fromDpkg, err := ParseApt(fixture(t, host.dpkg))
			if err != nil {
				t.Fatalf("dpkg-query: %v", err)
			}
			fromList, err := ParseApt(fixture(t, host.list))
			if err != nil {
				t.Fatalf("apt list: %v", err)
			}
			a, b := names(fromDpkg.Packages), names(fromList.Packages)
			if len(a) != len(b) {
				t.Fatalf("dpkg-query found %d packages, apt list found %d, from the same host", len(a), len(b))
			}
			for name, version := range a {
				got, ok := b[name]
				if !ok {
					t.Errorf("%s is in the dpkg-query import and not the apt list import", name)
					continue
				}
				if got != version {
					t.Errorf("%s: dpkg-query says %s, apt list says %s", name, version, got)
				}
			}
		})
	}
}

// TestAptEntriesFetchThroughAptGet pins the entry shape. An apt entry with no
// URL is resolved by the builder through 'apt-get download <source_name>', so
// source_name has to be set and the mode has to stay hosted.
func TestAptEntriesFetchThroughAptGet(t *testing.T) {
	res, err := ParseApt(fixture(t, "apt-dpkg-query-ubuntu2404.txt"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	for _, pm := range res.Packages {
		ve := pm.Versions[0]
		if ve.SourceName != pm.Name {
			t.Fatalf("%s: source_name = %q, want the package name; apt-get download has nothing to ask for", pm.Name, ve.SourceName)
		}
		if ve.URL != "" {
			t.Fatalf("%s: url = %q, want empty so the builder resolves it from the host's own sources", pm.Name, ve.URL)
		}
		if ve.Mode == manifest.ModeProxy {
			t.Fatalf("%s: mode = proxy; an apt entry with no url has no upstream to proxy to", pm.Name)
		}
	}
}

// TestEpochVersionsSurvive guards the one apt version shape a naive split
// would mangle. 77 packages on the ns0 host carry an epoch.
func TestEpochVersionsSurvive(t *testing.T) {
	res, err := ParseApt(fixture(t, "apt-dpkg-query-ns0.txt"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	found := 0
	for _, pm := range res.Packages {
		if v := pm.Versions[0].Version; len(v) > 1 && v[1] == ':' {
			found++
		}
	}
	if found == 0 {
		t.Error("no epoch versions survived the import; the ns0 capture has 77")
	}
}

func TestParsePip(t *testing.T) {
	res, err := ParsePip(fixture(t, "pypi-pip-list.json"))
	if err != nil {
		t.Fatalf("ParsePip: %v", err)
	}
	if len(res.Packages) == 0 {
		t.Fatal("no packages")
	}
	got := names(res.Packages)
	if got["certifi"] != "2026.7.22" {
		t.Errorf("certifi = %q, want 2026.7.22", got["certifi"])
	}
	if res.Packages[0].Versions[0].Mode != manifest.ModeProxy {
		t.Error("pypi entries resolve from pypi_upstream, so they import as proxy")
	}
}

func TestParseNpm(t *testing.T) {
	res, err := ParseNpm(fixture(t, "npm-ls-global.json"))
	if err != nil {
		t.Fatalf("ParseNpm: %v", err)
	}
	got := names(res.Packages)
	if got["npm"] != "11.19.0" {
		t.Errorf("npm = %q, want 11.19.0", got["npm"])
	}
}

// TestParseCargoSkipsGitSources covers the crate the local capture happens to
// contain: one installed straight from a git URL. crates.io has no such
// version, so importing it produces an entry the proxy can never satisfy.
func TestParseCargoSkipsGitSources(t *testing.T) {
	res, err := ParseCargo(fixture(t, "cargo-install-list.txt"))
	if err != nil {
		t.Fatalf("ParseCargo: %v", err)
	}
	if len(res.Packages) != 0 {
		t.Errorf("imported %d crate(s); the only one in the capture is git-sourced", len(res.Packages))
	}
	if len(res.Warnings) == 0 {
		t.Error("a crate was skipped and nothing said so")
	}
}

func TestParseGomodBothForms(t *testing.T) {
	fromBinary, err := ParseGomod(fixture(t, "gomod-go-version-m.txt"))
	if err != nil {
		t.Fatalf("go version -m: %v", err)
	}
	got := names(fromBinary.Packages)
	if got["github.com/ravinald/drover"] != "v0.5.0" {
		t.Errorf("main module = %q, want v0.5.0", got["github.com/ravinald/drover"])
	}
	if got["github.com/spf13/cobra"] == "" {
		t.Error("dependencies were dropped; a GOPROXY missing them cannot serve a build")
	}
	for name := range got {
		if name == "path" || name == "build" {
			t.Errorf("%q is a build-info key, not a module", name)
		}
	}

	fromTree, err := ParseGomod(fixture(t, "gomod-go-list-m-all.txt"))
	if err != nil {
		t.Fatalf("go list -m all: %v", err)
	}
	if len(fromTree.Packages) < 100 {
		t.Errorf("imported %d modules from go list -m all, want the whole tree", len(fromTree.Packages))
	}
	for _, pm := range fromTree.Packages {
		if pm.Versions[0].Version == "" {
			t.Errorf("%s has no version; the main module line should have been skipped", pm.Name)
		}
	}
}

// TestHelmChartNamesWithHyphens is the case a naive split on the last hyphen
// gets wrong: chart names contain hyphens too.
func TestHelmChartNamesWithHyphens(t *testing.T) {
	res, err := ParseHelm(fixture(t, "helm-list.json"))
	if err != nil {
		t.Fatalf("ParseHelm: %v", err)
	}
	got := names(res.Packages)
	if got["kube-prometheus-stack"] != "62.7.0" {
		t.Errorf("kube-prometheus-stack = %q, want 62.7.0; got names %v", got["kube-prometheus-stack"], got)
	}
	if got["nginx"] != "18.2.4" {
		t.Errorf("nginx = %q, want 18.2.4", got["nginx"])
	}
	if len(res.Warnings) == 0 {
		t.Error("helm entries import with no url and nothing said so")
	}
}

// TestEveryImportIsAdmissible closes the loop the whole feature exists to
// close: what convert emits, import accepts. A converter tested only against
// its own output passes while producing something the store refuses.
func TestEveryImportIsAdmissible(t *testing.T) {
	cfg := &config.Config{}
	for _, tc := range []struct{ typ, file string }{
		{manifest.TypeApt, "apt-dpkg-query-ns0.txt"},
		{manifest.TypeApt, "apt-list-installed-ns0.txt"},
		{manifest.TypePypi, "pypi-pip-list.json"},
		{manifest.TypeNpm, "npm-ls-global.json"},
		{manifest.TypeGomod, "gomod-go-list-m-all.txt"},
		{manifest.TypeGomod, "gomod-go-version-m.txt"},
		{manifest.TypeHelm, "helm-list.json"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			parse, err := For(tc.typ)
			if err != nil {
				t.Fatalf("For(%q): %v", tc.typ, err)
			}
			res, err := parse(fixture(t, tc.file))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			for i := range res.Packages {
				pm := &res.Packages[i]
				if r := admit.Admit(t.Context(), nil, nil, cfg, pm, ""); !r.OK() {
					t.Fatalf("%s/%s would be refused on import: %s", pm.Type, pm.Name, r.Reason)
				}
			}
		})
	}
}

// TestConversionIsDeterministic protects the workflow the output is for: an
// operator diffs this week's catalog against last week's. Map iteration order
// would make every line look changed.
func TestConversionIsDeterministic(t *testing.T) {
	for _, tc := range []struct{ typ, file string }{
		{manifest.TypeApt, "apt-dpkg-query-ns0.txt"},
		{manifest.TypeNpm, "npm-ls-global.json"},
		{manifest.TypeGomod, "gomod-go-list-m-all.txt"},
	} {
		parse, err := For(tc.typ)
		if err != nil {
			t.Fatal(err)
		}
		first, err := parse(fixture(t, tc.file))
		if err != nil {
			t.Fatal(err)
		}
		second, err := parse(fixture(t, tc.file))
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(first.Packages)
		b, _ := json.Marshal(second.Packages)
		if !bytes.Equal(a, b) {
			t.Errorf("%s: two parses of identical input produced different bytes", tc.file)
		}
	}
}

// TestNoImporterForGitOrBinary states the gap rather than leaving an operator
// to find it. Neither has a host manager to read.
func TestNoImporterForGitOrBinary(t *testing.T) {
	for _, typ := range []string{manifest.TypeGit, manifest.TypeBinary} {
		_, err := For(typ)
		if err == nil {
			t.Fatalf("For(%q) returned an importer; nothing on a host records these", typ)
		}
		if !bytes.Contains([]byte(err.Error()), []byte("observe")) {
			t.Errorf("the error for %q does not point at what does cover it: %v", typ, err)
		}
	}
}
