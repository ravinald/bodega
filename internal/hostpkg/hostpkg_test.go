package hostpkg

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
// field at all. The 26.04 capture has 731 rows in the dpkg database and 728
// packages actually installed; the other 3 are superseded kernel images that
// were removed with their config files kept. An importer that trusts the row
// count mirrors packages the host does not have.
func TestAptSkipsRemovedButNotPurged(t *testing.T) {
	res, err := ParseApt(fixture(t, "apt-dpkg-query-ubuntu2604.txt"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	const installed = 728
	if got := len(res.Packages); got != installed {
		t.Errorf("imported %d packages, want %d: the dpkg status field was not honored", got, installed)
	}
	for _, pm := range res.Packages {
		if pm.Name == "linux-image-unsigned-7.0.0-30-generic" {
			t.Error("imported a kernel image that is removed, config files retained")
		}
	}
	if len(res.Warnings) == 0 {
		t.Error("3 rows were skipped and nothing said so")
	}
}

// TestAptRowsCarryTheArchitecture is what ParseAptRows exists for. The
// manifest an import writes has no architecture on it, so a pin reading the
// same output would have to re-derive one and could disagree with the importer
// about which rows are installed. 209 of the 728 packages this host has are
// Architecture: all, and each one is published inside binary-<arch> rather
// than an index of its own.
func TestAptRowsCarryTheArchitecture(t *testing.T) {
	inv, err := ParseAptRows(fixture(t, "apt-dpkg-query-ubuntu2604.txt"))
	if err != nil {
		t.Fatalf("ParseAptRows: %v", err)
	}
	res, err := ParseApt(fixture(t, "apt-dpkg-query-ubuntu2604.txt"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	if len(inv.Rows) != len(res.Packages) {
		t.Fatalf("ParseAptRows found %d rows, ParseApt found %d packages, from one status rule", len(inv.Rows), len(res.Packages))
	}

	archAll := 0
	for _, row := range inv.Rows {
		if row.Arch == "" {
			t.Fatalf("%s has no architecture", row.Name)
		}
		if row.Arch == "all" {
			archAll++
		}
	}
	if archAll != 209 {
		t.Errorf("counted %d Architecture: all rows, want 209", archAll)
	}
}

// TestAptRowsReadTheInstallTime covers the sixth column, and that a capture
// whose sixth column is empty or not a number reads as no install time rather
// than failing: an install time only refines a bypass report.
func TestAptRowsReadTheInstallTime(t *testing.T) {
	inv, err := ParseAptRows(strings.NewReader("curl\t8.5.0\tamd64\tinstall ok installed\tcurl\t978307200\n" +
		"jq\t1.7.1\tamd64\tinstall ok installed\tjq\t\n" +
		"zstd\t1.5.5\tamd64\tinstall ok installed\tlibzstd\tsoon\n"))
	if err != nil {
		t.Fatalf("ParseAptRows: %v", err)
	}
	if len(inv.Rows) != 3 {
		t.Fatalf("rows = %+v, want 3", inv.Rows)
	}
	if got := inv.Rows[0].InstalledAt; got.Unix() != 978307200 || got.Location().String() != "UTC" {
		t.Errorf("curl installed at %v, want 2001-01-01T00:00:00Z", got)
	}
	for _, row := range inv.Rows[1:] {
		if !row.InstalledAt.IsZero() {
			t.Errorf("%s installed at %v, want zero", row.Name, row.InstalledAt)
		}
	}
	if inv.Rows[2].Source != "libzstd" {
		t.Errorf("zstd source = %q: the sixth column moved the fifth", inv.Rows[2].Source)
	}
	res, err := ParseApt(strings.NewReader("curl\t8.5.0\tamd64\tinstall ok installed\tcurl\t978307200\n"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	if md := res.Packages[0].Versions[0].Metadata; len(md) != 0 {
		t.Errorf("convert carried the install time onto the manifest: %v", md)
	}
}

// TestAptFormatsAgree cross-checks the two inventory formats against each
// other. Both captures come from the same host at the same moment, so a
// disagreement is a parser bug in one of them, and neither parser grades its
// own homework.
func TestAptFormatsAgree(t *testing.T) {
	for _, host := range []struct{ dpkg, list string }{
		{"apt-dpkg-query-ubuntu2604.txt", "apt-list-installed-ubuntu2604.txt"},
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
// would mangle. 88 packages in the 26.04 capture carry an epoch.
func TestEpochVersionsSurvive(t *testing.T) {
	res, err := ParseApt(fixture(t, "apt-dpkg-query-ubuntu2604.txt"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	found := 0
	for _, pm := range res.Packages {
		if v := pm.Versions[0].Version; len(v) > 1 && v[1] == ':' {
			found++
		}
	}
	if found != 88 {
		t.Errorf("%d epoch versions survived the import, want 88", found)
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

// TestParseRubygemsBothForms reads one container's gems both ways. The
// gem list capture holds the three cases a line can carry: a platform build
// (nokogiri 1.16.7 x86_64-linux), two versions of one gem (rake 13.2.1 and
// 13.1.0), and the default gems Ruby ships, which no registry download put
// there. The specifications listing names the two gems installed by hand.
func TestParseRubygemsBothForms(t *testing.T) {
	list, err := ParseRubygems(fixture(t, "rubygems-gem-list-local-ruby33.txt"))
	if err != nil {
		t.Fatalf("ParseRubygems(gem list): %v", err)
	}
	got := map[string][]string{}
	for _, pm := range list.Packages {
		if pm.Type != manifest.TypeRubygems {
			t.Errorf("%s typed %q", pm.Name, pm.Type)
		}
		for _, ve := range pm.Versions {
			got[pm.Name] = append(got[pm.Name], ve.Version)
			if ve.Mode != manifest.ModeProxy {
				t.Errorf("%s@%s mode %q, want proxy like every registry import", pm.Name, ve.Version, ve.Mode)
			}
		}
	}
	if v := got["nokogiri"]; len(v) != 1 || v[0] != "1.16.7-x86_64-linux" {
		t.Errorf("nokogiri = %v, want the platform build as its gem file names it", v)
	}
	if v := got["rake"]; len(v) != 2 || !slices.Contains(v, "13.2.1") || !slices.Contains(v, "13.1.0") {
		t.Errorf("rake = %v, want both installed versions on one package", v)
	}
	if _, ok := got["json"]; ok {
		t.Error("json is a default gem in the capture and was imported")
	}
	if len(list.Packages) != 17 {
		t.Errorf("imported %d gems, want the 17 the capture lists without a default: version", len(list.Packages))
	}
	if len(list.Warnings) != 1 || !strings.Contains(list.Warnings[0], "70 default gem") {
		t.Errorf("warnings = %v, want one naming the 70 default gems skipped", list.Warnings)
	}

	specs, err := ParseRubygems(fixture(t, "rubygems-specifications-ruby33.txt"))
	if err != nil {
		t.Fatalf("ParseRubygems(specifications): %v", err)
	}
	var fromSpecs []string
	for _, pm := range specs.Packages {
		fromSpecs = append(fromSpecs, pm.Name+"@"+pm.Versions[0].Version)
	}
	if want := []string{"nokogiri@1.16.7-x86_64-linux", "rake@13.2.1"}; !slices.Equal(fromSpecs, want) {
		t.Errorf("specifications = %v, want %v", fromSpecs, want)
	}
	if len(specs.Warnings) != 0 {
		t.Errorf("warnings on a clean listing: %v", specs.Warnings)
	}
}

func TestParseRubygemsReportsWhatItCannotRead(t *testing.T) {
	res, err := ParseRubygems(strings.NewReader("*** LOCAL GEMS ***\n\nrack (3.1.8)\nnot a gem line\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "rack" {
		t.Errorf("packages = %+v, want rack alone", res.Packages)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "not a gem line") {
		t.Errorf("warnings = %v, want the unreadable line named", res.Warnings)
	}
}

func TestParseGomodBothForms(t *testing.T) {
	fromBinary, err := ParseGomod(fixture(t, "gomod-go-version-m.txt"))
	if err != nil {
		t.Fatalf("go version -m: %v", err)
	}
	got := names(fromBinary.Packages)
	if got["github.com/golangci/golangci-lint/v2"] != "v2.13.2" {
		t.Errorf("main module = %q, want v2.13.2", got["github.com/golangci/golangci-lint/v2"])
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
		{manifest.TypeApt, "apt-dpkg-query-ubuntu2604.txt"},
		{manifest.TypeApt, "apt-list-installed-ubuntu2604.txt"},
		{manifest.TypePypi, "pypi-pip-list.json"},
		{manifest.TypeNpm, "npm-ls-global.json"},
		{manifest.TypeGomod, "gomod-go-list-m-all.txt"},
		{manifest.TypeGomod, "gomod-go-version-m.txt"},
		{manifest.TypeHelm, "helm-list.json"},
		{manifest.TypeFreeBSD, "freebsd-pkg-query.txt"},
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
		{manifest.TypeApt, "apt-dpkg-query-ubuntu2604.txt"},
		{manifest.TypeNpm, "npm-ls-global.json"},
		{manifest.TypeGomod, "gomod-go-list-m-all.txt"},
		{manifest.TypeFreeBSD, "freebsd-pkg-query.txt"},
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

// TestAptRecordsTheSourcePackage covers the fifth dpkg-query field. Ubuntu and
// Debian advisories are issued against the source package, so an import that
// drops it leaves the OSV gate querying "libssl3" against an index that only
// knows "openssl". 73 of this container's 101 packages are in that position.
func TestAptRecordsTheSourcePackage(t *testing.T) {
	res, err := ParseApt(fixture(t, "apt-dpkg-query-jammy-source.txt"))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	if got := len(res.Packages); got != 101 {
		t.Fatalf("imported %d packages, want 101", got)
	}

	differing := 0
	for _, pm := range res.Packages {
		ve := pm.Versions[0]
		if ve.SourcePackage == "" {
			t.Fatalf("%s: source_package is empty, but the capture carries one for every row", pm.Name)
		}
		if ve.SourceName != pm.Name {
			t.Fatalf("%s: source_name = %q; 'apt-get download' wants the binary name and must not be repurposed",
				pm.Name, ve.SourceName)
		}
		if ve.SourcePackage != pm.Name {
			differing++
		}
	}
	if differing != 73 {
		t.Errorf("counted %d packages whose source differs from their binary name, want 73", differing)
	}

	for name, want := range map[string]string{
		"libssl3":       "openssl",
		"bsdutils":      "util-linux",
		"libapt-pkg6.0": "apt",
		"base-files":    "base-files",
	} {
		pm := find(res.Packages, name)
		if pm == nil {
			t.Fatalf("%s is missing from the import", name)
		}
		if got := pm.Versions[0].SourcePackage; got != want {
			t.Errorf("%s: source_package = %q, want %q", name, got, want)
		}
	}
}

// TestAptSourcePackageIsAppendedNotInserted holds the field's position. dpkg's
// own ordering would put ${source:Package} second, and that capture parses
// with no error while dropping every row on the host: the fourth field is then
// the architecture, which no status test matches. Appending keeps the
// four-field capture taken before this field existed reading unchanged.
func TestAptSourcePackageIsAppendedNotInserted(t *testing.T) {
	appended, err := ParseApt(strings.NewReader(
		"libexpat1\t2.4.7-1ubuntu0.2\tamd64\tinstall ok installed\texpat\n"))
	if err != nil {
		t.Fatalf("appended: %v", err)
	}
	if len(appended.Packages) != 1 || appended.Packages[0].Versions[0].SourcePackage != "expat" {
		t.Fatalf("appended form did not parse: %+v", appended.Packages)
	}

	legacy, err := ParseApt(strings.NewReader(
		"libexpat1\t2.4.7-1ubuntu0.2\tamd64\tinstall ok installed\n"))
	if err != nil {
		t.Fatalf("four-field: %v", err)
	}
	if len(legacy.Packages) != 1 {
		t.Fatalf("the four-field capture must keep parsing, got %d packages", len(legacy.Packages))
	}
	if got := legacy.Packages[0].Versions[0].SourcePackage; got != "" {
		t.Errorf("a capture that recorded no source must record none, got %q", got)
	}
}

func find(pms []manifest.PackageManifest, name string) *manifest.PackageManifest {
	for i := range pms {
		if pms[i].Name == name {
			return &pms[i]
		}
	}
	return nil
}

// TestAptCaptureRecordsItsRelease is the other half of what an apt capture has
// to carry. dpkg reports no codename in either format, so the release comes
// from the host convert runs on, and it is the field that decides which
// advisories answer for a version: Ubuntu and Debian backport a fix without
// moving the upstream version, so a noble revision checked against jammy's
// records matches nothing and dates itself clean.
func TestAptCaptureRecordsItsRelease(t *testing.T) {
	const capture = "libexpat1\t2.6.1-2build1\tamd64\tinstall ok installed\texpat\n"

	res, err := ParseAptWithSuite(strings.NewReader(capture), "noble")
	if err != nil {
		t.Fatalf("ParseAptWithSuite: %v", err)
	}
	if got := res.Packages[0].Versions[0].CaptureSuite; got != "noble" {
		t.Errorf("capture_suite = %q, want noble", got)
	}
	// Not the publishing field. A server whose apt_codename is a house name
	// serves no suite a captured host could have named, so a release written
	// into Suites takes the entry out of every generated index.
	if got := res.Packages[0].Versions[0].Suites; len(got) != 0 {
		t.Errorf("suites = %v, want none: the release is provenance, not placement", got)
	}

	// A capture with no release recorded must record none. The OSV gate warns
	// on that entry rather than guessing, which is the honest answer; a
	// codename picked here would be one nothing chose.
	none, err := ParseApt(strings.NewReader(capture))
	if err != nil {
		t.Fatalf("ParseApt: %v", err)
	}
	if got := none.Packages[0].Versions[0].CaptureSuite; got != "" {
		t.Errorf("capture_suite = %q, want none", got)
	}
	if blank, err := ParseAptWithSuite(strings.NewReader(capture), "  "); err != nil {
		t.Fatalf("ParseAptWithSuite: %v", err)
	} else if got := blank.Packages[0].Versions[0].CaptureSuite; got != "" {
		t.Errorf("whitespace recorded capture_suite = %q, want none", got)
	}

	// Every row, not the first: a host inventory is a thousand packages and
	// one release.
	all, err := ParseAptWithSuite(fixture(t, "apt-dpkg-query-jammy-source.txt"), "jammy")
	if err != nil {
		t.Fatalf("ParseAptWithSuite: %v", err)
	}
	for _, pm := range all.Packages {
		if got := pm.Versions[0].CaptureSuite; got != "jammy" {
			t.Fatalf("%s: capture_suite = %q, want jammy", pm.Name, got)
		}
	}
}

// TestParseFreeBSDCollapsesToRepositories reads a FreeBSD 15.1 host with 34
// packages from three repositories. A freebsd entry is a repository keyed by
// ABI, so 34 rows become three entries, and the 7 noarch rows ("FreeBSD:15:*")
// add no version: no pkg client substitutes that for ${ABI}.
func TestParseFreeBSDCollapsesToRepositories(t *testing.T) {
	res, err := ParseFreeBSD(fixture(t, "freebsd-pkg-query.txt"))
	if err != nil {
		t.Fatalf("ParseFreeBSD: %v", err)
	}
	want := map[string]string{
		"FreeBSD-ports":    "FreeBSD:15:aarch64",
		"bodega-latest":    "FreeBSD:15:aarch64",
		"bodega-quarterly": "FreeBSD:15:aarch64",
	}
	if got := names(res.Packages); len(got) != len(want) {
		t.Fatalf("got entries %v, want %v", got, want)
	}
	for _, pm := range res.Packages {
		if pm.Type != manifest.TypeFreeBSD {
			t.Errorf("%s: type %q", pm.Name, pm.Type)
		}
		if len(pm.Versions) != 1 || pm.Versions[0].Version != want[pm.Name] {
			t.Errorf("%s: versions %+v, want the one ABI %s", pm.Name, pm.Versions, want[pm.Name])
			continue
		}
		ve := pm.Versions[0]
		if ve.URL != "" || ve.Generated {
			t.Errorf("%s: url %q generated %v; the query records neither", pm.Name, ve.URL, ve.Generated)
		}
		if ve.EffectiveMode() != manifest.ModeProxy {
			t.Errorf("%s: mode %q; hosted would mirror the whole repository on import", pm.Name, ve.EffectiveMode())
		}
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "pkg -vv") {
		t.Errorf("entries import with no url and no warning names where to find one: %v", res.Warnings)
	}
}

// TestParseFreeBSDReportsWhatItSkips covers the rows the fixture host lacks: a
// package built from ports, a repository holding only noarch packages, and a
// host upgraded across a major version whose packages still carry both ABIs.
func TestParseFreeBSDReportsWhatItSkips(t *testing.T) {
	res, err := ParseFreeBSD(strings.NewReader(strings.Join([]string{
		"unknown-repository\tFreeBSD:15:aarch64",
		"fonts\tFreeBSD:15:*",
		"FreeBSD-ports\tFreeBSD:14:aarch64",
		"FreeBSD-ports\tFreeBSD:15:aarch64",
		"FreeBSD-ports\tFreeBSD:15:*",
	}, "\n")))
	if err != nil {
		t.Fatalf("ParseFreeBSD: %v", err)
	}
	if len(res.Packages) != 1 || len(res.Packages[0].Versions) != 2 {
		t.Fatalf("want FreeBSD-ports with both ABIs, got %+v", res.Packages)
	}
	warned := strings.Join(res.Warnings, "\n")
	for _, want := range []string{"ports build", "fonts"} {
		if !strings.Contains(warned, want) {
			t.Errorf("no warning mentions %q: %v", want, res.Warnings)
		}
	}

	if _, err := ParseFreeBSD(strings.NewReader("FreeBSD-ports FreeBSD:15:aarch64\n")); err == nil {
		t.Error("a line with no tab parsed; a capture taken with the wrong format would import nothing and say nothing")
	}
}

// The capture is every POM a fresh Maven 3.9.9 left in its local repository
// after one dependency:list: the project's own dependencies and the plugins
// Maven itself resolved to run it, three versions of slf4j-api among them.
func TestParseMavenLocalRepository(t *testing.T) {
	res, err := ParseMaven(fixture(t, "maven-m2-poms-maven399.txt"))
	if err != nil {
		t.Fatalf("ParseMaven: %v", err)
	}
	got := map[string][]string{}
	versions := 0
	for _, pm := range res.Packages {
		if pm.Type != manifest.TypeMaven {
			t.Errorf("%s typed %q", pm.Name, pm.Type)
		}
		for _, ve := range pm.Versions {
			got[pm.Name] = append(got[pm.Name], ve.Version)
			versions++
			if ve.Mode != manifest.ModeProxy {
				t.Errorf("%s@%s mode %q, want proxy like every registry import", pm.Name, ve.Version, ve.Mode)
			}
		}
	}
	if len(res.Packages) != 163 || versions != 260 {
		t.Errorf("imported %d artifacts with %d versions, want the 163 and 260 the capture lists", len(res.Packages), versions)
	}
	if v := got["org.slf4j:slf4j-api"]; len(v) != 3 || !slices.Contains(v, "2.0.13") || !slices.Contains(v, "1.7.5") {
		t.Errorf("slf4j-api = %v, want all three versions on one package", v)
	}
	if v := got["io.netty:netty-transport-native-epoll"]; len(v) != 1 || v[0] != "4.1.110.Final" {
		t.Errorf("netty-transport-native-epoll = %v, want the one version whose classified jar the build resolved", v)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none for a clean capture", res.Warnings)
	}
}

func TestParseMavenReportsWhatItCannotRead(t *testing.T) {
	in := strings.Join([]string{
		"/home/ci/.m2/repository/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.pom",
		`C:\Users\ci\.m2\repository\com\google\guava\guava\33.2.0-jre\guava-33.2.0-jre.pom`,
		"org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom",
		"/home/ci/.m2/repository/com/example/app/1.0-SNAPSHOT/app-1.0-SNAPSHOT.pom",
		"/home/ci/.m2/repository/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar",
		"/home/ci/.m2/repository/org/slf4j/slf4j-api/maven-metadata-central.xml",
		"",
	}, "\n")
	res, err := ParseMaven(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, pm := range res.Packages {
		names = append(names, pm.Name+"@"+pm.Versions[0].Version)
	}
	want := "com.google.guava:guava@33.2.0-jre,org.apache.commons:commons-lang3@3.14.0,org.slf4j:slf4j-api@2.0.13"
	if strings.Join(names, ",") != want {
		t.Errorf("packages = %v, want %s", names, want)
	}
	if len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "1 SNAPSHOT") || !strings.Contains(res.Warnings[1], "skipped 2 line(s)") {
		t.Errorf("warnings = %v, want the SNAPSHOT and the two non-POM lines counted", res.Warnings)
	}
}
