package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// discoverEnv is a scratch install: a config file the CLI resolves through
// $BODEGA_CONFIG_FILE, a local manifest dir, and an audit DB the test seeds
// discovery rows into.
type discoverEnv struct {
	manifestDir string
	auditDB     string
}

func newDiscoverEnv(t *testing.T) *discoverEnv {
	t.Helper()
	dir := t.TempDir()
	env := &discoverEnv{
		manifestDir: filepath.Join(dir, "manifests"),
		auditDB:     filepath.Join(dir, "audit.db"),
	}
	for _, d := range []string{env.manifestDir, filepath.Join(dir, "storage")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	body := fmt.Sprintf(`{
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "audit_db": %q,
  "log_dir": %q,
  "allow_plaintext": true,
  "apt_codename": "noble"
}`, filepath.Join(dir, "storage"), env.manifestDir, env.auditDB, dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)
	return env
}

// seedDiscovery writes rows through the same upsert the server uses, so the
// test cannot pass against a row shape the server never produces.
func (e *discoverEnv) seedDiscovery(t *testing.T, rows ...audit.DiscoveryRow) {
	t.Helper()
	db, err := audit.Open(e.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	for _, row := range rows {
		if _, err := db.RecordDiscovery(context.Background(), row); err != nil {
			t.Fatalf("seed discovery row %+v: %v", row, err)
		}
	}
}

// readManifest loads the package from a store built fresh off disk. Reusing
// the command's store would assert against its in-memory cache rather than
// what it wrote.
func (e *discoverEnv) readManifest(t *testing.T, typ, name string) *manifest.PackageManifest {
	t.Helper()
	store := manifest.NewLocalStore(e.manifestDir)
	pm, err := store.GetPackage(context.Background(), typ, name)
	if err != nil {
		t.Fatalf("read manifest %s/%s: %v", typ, name, err)
	}
	return pm
}

func runDiscover(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newDiscoverCmd(&globalFlags{})
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return out.String(), err
}

func gomodMiss() audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: manifest.TypeGomod,
		Host:         "proxy.golang.org",
		PatternHint:  "example.com/example-corp/",
		PkgName:      "example.com/example-corp/widget-sdk",
		PkgVersion:   "v1.30.0",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://proxy.golang.org/example.com/example-corp/widget-sdk/@v/v1.30.0.info",
		LastClient:   "10.0.0.5",
	}
}

// The assertion is on the written manifest, not on the printed line: a promote
// that silently no-ops still prints.
func TestPromoteAsManifestWritesTheEntry(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss())

	if _, err := runDiscover(t, "promote", "gomod", "example.com/example-corp/", "--as", "manifest"); err != nil {
		t.Fatalf("promote --as manifest: %v", err)
	}

	pm := env.readManifest(t, manifest.TypeGomod, "example.com/example-corp/widget-sdk")
	if pm == nil {
		t.Fatal("no manifest written")
	}
	if pm.Name != "example.com/example-corp/widget-sdk" {
		t.Errorf("Name = %q", pm.Name)
	}
	if pm.Type != manifest.TypeGomod {
		t.Errorf("Type = %q, want %q", pm.Type, manifest.TypeGomod)
	}
	if len(pm.Versions) != 1 {
		t.Fatalf("versions = %d, want 1 (%+v)", len(pm.Versions), pm.Versions)
	}
	ve := pm.Versions[0]
	if ve.Version != "v1.30.0" {
		t.Errorf("Version = %q, want v1.30.0", ve.Version)
	}
	// The row records the artifact URL; the gomod manifest field is the GOPROXY
	// root the builder appends the module path to. Promoting the row verbatim
	// would make the next 'bodega build fetch gomod' request it twice.
	if ve.URL != "https://proxy.golang.org" {
		t.Errorf("URL = %q, want the GOPROXY root", ve.URL)
	}
	if ve.Mode != manifest.ModeProxy {
		t.Errorf("Mode = %q, want %q", ve.Mode, manifest.ModeProxy)
	}
}

// A second promote-all must add nothing. Anything that re-appends turns an
// operator's habit of re-running the command into a manifest full of
// duplicates.
func TestPromoteAllAsManifestIsIdempotent(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss(), audit.DiscoveryRow{
		RegistryType: manifest.TypeGomod,
		Host:         "proxy.golang.org",
		PatternHint:  "example.com/example-corp/",
		PkgName:      "example.com/example-corp/widget-sdk",
		PkgVersion:   "v1.31.0",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://proxy.golang.org/example.com/example-corp/widget-sdk/@v/v1.31.0.info",
	})

	if _, err := runDiscover(t, "promote-all", "gomod", "--as", "manifest"); err != nil {
		t.Fatalf("first promote-all: %v", err)
	}
	first := env.readManifest(t, manifest.TypeGomod, "example.com/example-corp/widget-sdk")
	if len(first.Versions) != 2 {
		t.Fatalf("versions after first run = %d, want 2 (%+v)", len(first.Versions), first.Versions)
	}

	if _, err := runDiscover(t, "promote-all", "gomod", "--as", "manifest"); err != nil {
		t.Fatalf("second promote-all: %v", err)
	}
	second := env.readManifest(t, manifest.TypeGomod, "example.com/example-corp/widget-sdk")
	if len(second.Versions) != 2 {
		t.Errorf("versions after second run = %d, want 2 — the run duplicated entries (%+v)",
			len(second.Versions), second.Versions)
	}
}

// An operator who set a version to hosted did so on purpose. A promote that
// rewrote it to proxy would silently start serving upstream bytes for an
// artifact bodega builds.
func TestPromoteAsManifestNeverDowngradesHosted(t *testing.T) {
	env := newDiscoverEnv(t)
	store := manifest.NewLocalStore(env.manifestDir)
	ctx := context.Background()
	if err := store.AddVersion(ctx, manifest.TypeGomod, "example.com/example-corp/widget-sdk", manifest.VersionEntry{
		Version: "v1.30.0",
		Mode:    manifest.ModeHosted,
		URL:     "https://internal.example.com/widget-sdk.zip",
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("save index: %v", err)
	}
	env.seedDiscovery(t, gomodMiss())

	if _, err := runDiscover(t, "promote-all", "gomod", "--as", "manifest"); err != nil {
		t.Fatalf("promote-all --as manifest: %v", err)
	}

	pm := env.readManifest(t, manifest.TypeGomod, "example.com/example-corp/widget-sdk")
	if len(pm.Versions) != 1 {
		t.Fatalf("versions = %d, want 1 (%+v)", len(pm.Versions), pm.Versions)
	}
	if pm.Versions[0].Mode != manifest.ModeHosted {
		t.Errorf("Mode = %q, want %q — promote downgraded an operator's entry", pm.Versions[0].Mode, manifest.ModeHosted)
	}
	if pm.Versions[0].URL != "https://internal.example.com/widget-sdk.zip" {
		t.Errorf("URL = %q — promote rewrote an existing entry", pm.Versions[0].URL)
	}
}

// git smart-HTTP names a repository and no ref, so a versionless row has to
// promote to something servable rather than being dropped.
func TestPromoteAsManifestVersionlessRowBecomesAnyConstraint(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, audit.DiscoveryRow{
		RegistryType: manifest.TypeGit,
		Host:         "github.com",
		PatternHint:  "example.com/example-corp/",
		PkgName:      "example-corp/widget-sdk",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://example.com/example-corp/widget-sdk",
	})

	if _, err := runDiscover(t, "promote-all", "git", "--as", "manifest"); err != nil {
		t.Fatalf("promote-all --as manifest: %v", err)
	}

	pm := env.readManifest(t, manifest.TypeGit, "example-corp/widget-sdk")
	if pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("manifest = %+v, want one version entry", pm)
	}
	if pm.Versions[0].VersionConstraint != manifest.ConstraintAny {
		t.Errorf("VersionConstraint = %q, want %q", pm.Versions[0].VersionConstraint, manifest.ConstraintAny)
	}
	if pm.Versions[0].URL != "https://example.com/example-corp/widget-sdk" {
		t.Errorf("URL = %q", pm.Versions[0].URL)
	}
}

// The row a git smart-HTTP miss actually writes, promoted.
//
// The name is namespace-prefixed and the version is empty, which is the shape
// TestGitSmartCatalogModeNeverClones pins on the server side. Both halves have
// to hold or promote does not unblock the 404 it came from: catalog mode looks
// the manifest up under "<namespace>/<repo>" with no ".git", and a versionless
// row that lost its "any" constraint would produce an entry no ref matches.
func TestPromoteAsManifestFromAGitSmartHTTPMiss(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, audit.DiscoveryRow{
		RegistryType: manifest.TypeGit,
		Host:         "github.com",
		PatternHint:  "github.com/octocat/",
		PkgName:      "vetted/octocat/Hello-World",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://github.com/octocat/Hello-World.git",
	})

	if _, err := runDiscover(t, "promote", "git", "github.com/octocat/", "--as", "manifest"); err != nil {
		t.Fatalf("promote --as manifest: %v", err)
	}

	pm := env.readManifest(t, manifest.TypeGit, "vetted/octocat/Hello-World")
	if pm == nil {
		t.Fatal("no manifest written under the name catalog mode looks up")
	}
	if pm.Name != "vetted/octocat/Hello-World" {
		t.Errorf("Name = %q, want the namespaced name the handler recorded", pm.Name)
	}
	if len(pm.Versions) != 1 {
		t.Fatalf("versions = %d, want 1 (%+v)", len(pm.Versions), pm.Versions)
	}
	ve := pm.Versions[0]
	if ve.VersionConstraint != manifest.ConstraintAny {
		t.Errorf("VersionConstraint = %q, want %q", ve.VersionConstraint, manifest.ConstraintAny)
	}
	if ve.Version != "" {
		t.Errorf("Version = %q, want empty — a clone names no single ref", ve.Version)
	}
	if ve.URL != "https://github.com/octocat/Hello-World.git" {
		t.Errorf("URL = %q, want the upstream the handler would have cloned", ve.URL)
	}
}

// A row with no upstream_url would build a proxy entry that 404s exactly like
// the miss it came from. It is named and skipped, never written.
func TestPromoteAsManifestSkipsRowsWithNoUpstreamURL(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, audit.DiscoveryRow{
		RegistryType: manifest.TypeHelm,
		PatternHint:  "ingress-nginx",
		PkgName:      "ingress-nginx",
		PkgVersion:   "4.0.0",
		Decision:     audit.DecisionNoManifest,
	})

	_, err := runDiscover(t, "promote-all", "helm", "--as", "manifest")
	if err == nil {
		t.Fatal("a run with nothing writable succeeded; the operator would believe entries were created")
	}
	if !strings.Contains(err.Error(), "upstream_url") {
		t.Errorf("error does not name the missing column:\n%s", err)
	}
	if pm := env.readManifest(t, manifest.TypeHelm, "ingress-nginx"); pm != nil {
		t.Errorf("a manifest was written from a row with no URL: %+v", pm)
	}
}

// Three failures, three messages. An operator who has captured nothing needs a
// different next step from one whose pattern is wrong.
func TestPromoteAsManifestFailuresDoNotShareOneMessage(t *testing.T) {
	env := newDiscoverEnv(t)

	_, emptyErr := runDiscover(t, "promote-all", "gomod", "--as", "manifest")
	if emptyErr == nil {
		t.Fatal("promote against an empty discovery log succeeded")
	}
	if !strings.Contains(emptyErr.Error(), "discover_mode") {
		t.Errorf("empty-log error does not name the setting that fills the log:\n%s", emptyErr)
	}

	env.seedDiscovery(t, audit.DiscoveryRow{
		RegistryType: manifest.TypeGomod,
		PatternHint:  "example.com/example-corp/",
		PkgName:      "example.com/example-corp/widget-sdk",
		PkgVersion:   "v1.30.0",
		Decision:     audit.DecisionAllowed,
		UpstreamURL:  "https://proxy.golang.org/x",
	})

	_, noMatchErr := runDiscover(t, "promote", "gomod", "example.com/example-vendor/", "--as", "manifest")
	if noMatchErr == nil {
		t.Fatal("promote against a pattern matching no no_manifest row succeeded")
	}
	if !strings.Contains(noMatchErr.Error(), "bodega discover show gomod example.com/example-vendor/") {
		t.Errorf("no-match error does not name the command that shows what was captured:\n%s", noMatchErr)
	}
	if emptyErr.Error() == noMatchErr.Error() {
		t.Error("an empty discovery log and a pattern that matches nothing report the same failure")
	}

	_, asErr := runDiscover(t, "promote", "gomod", "example.com/example-corp/", "--as", "policyy")
	if asErr == nil {
		t.Fatal("--as with an unknown target was accepted")
	}
	for _, want := range []string{"policy", "manifest"} {
		if !strings.Contains(asErr.Error(), want) {
			t.Errorf("--as error does not name %q:\n%s", want, asErr)
		}
	}
}

// npm records the tarball URL and the npm manifest field is the registry root,
// so the promoted entry has to be narrowed the same way gomod's is.
func TestPromoteAsManifestWritesTheNpmRegistryRoot(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, audit.DiscoveryRow{
		RegistryType: manifest.TypeNpm,
		Host:         "registry.npmjs.org",
		PatternHint:  "lodash",
		PkgName:      "lodash",
		PkgVersion:   "4.17.21",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
	})

	if _, err := runDiscover(t, "promote-all", "npm", "--as", "manifest"); err != nil {
		t.Fatalf("promote-all --as manifest: %v", err)
	}

	pm := env.readManifest(t, manifest.TypeNpm, "lodash")
	if pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("manifest = %+v, want one version entry", pm)
	}
	if pm.Versions[0].URL != "https://registry.npmjs.org" {
		t.Errorf("URL = %q, want the registry root", pm.Versions[0].URL)
	}
}

// --as policy is the default and writes what it always wrote: an allow-list
// rule, and no manifest.
func TestPromoteDefaultsToPolicy(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss())

	if _, err := runDiscover(t, "promote", "gomod", "example.com/example-corp/"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if pm := env.readManifest(t, manifest.TypeGomod, "example.com/example-corp/widget-sdk"); pm != nil {
		t.Errorf("the default promote wrote a manifest: %+v", pm)
	}

	db, err := audit.Open(env.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rules, err := db.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(rules) != 1 || rules[0].Pattern != "example.com/example-corp/" {
		t.Errorf("policy rules = %+v, want one rule for example.com/example-corp/", rules)
	}
}

// ---- generate-manifests ----------------------------------------------------

// runDiscoverSplit keeps stdout and stderr apart: the payload is only pipeable
// if the summary never lands in it, and a shared buffer cannot see that.
func runDiscoverSplit(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newDiscoverCmd(&globalFlags{})
	cmd.SetArgs(args)
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

// backdate moves a package's rows back in time. RecordDiscovery stamps
// last_seen with now(), so --since has nothing to exclude without this.
func (e *discoverEnv) backdate(t *testing.T, pkgName string, d time.Duration) {
	t.Helper()
	db, err := sql.Open("sqlite", e.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	stamp := time.Now().Add(-d).UTC().Format("2006-01-02T15:04:05.000Z")
	res, err := db.Exec(`UPDATE upstream_discovery SET last_seen = ? WHERE pkg_name = ?`, stamp, pkgName)
	if err != nil {
		t.Fatalf("backdate %s: %v", pkgName, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		t.Fatalf("backdate %s: no rows matched", pkgName)
	}
}

func (e *discoverEnv) discoveryRowCount(t *testing.T) int64 {
	t.Helper()
	db, err := audit.Open(e.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	n, err := db.DiscoveryCount(context.Background(), "")
	if err != nil {
		t.Fatalf("count discovery rows: %v", err)
	}
	return n
}

func decodeGenerated(t *testing.T, payload string) []manifest.PackageManifest {
	t.Helper()
	pms, err := decodeManifests([]byte(payload))
	if err != nil {
		t.Fatalf("decode generated payload %q: %v", payload, err)
	}
	return pms
}

func npmMiss() audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: manifest.TypeNpm,
		Host:         "registry.npmjs.org",
		PatternHint:  "lodash",
		PkgName:      "lodash",
		PkgVersion:   "4.17.21",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		LastClient:   "10.0.0.6",
	}
}

func gitMiss() audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: manifest.TypeGit,
		Host:         "github.com",
		PatternHint:  "https://example.com/example-corp/",
		PkgName:      "example-corp/widget-sdk",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://example.com/example-corp/widget-sdk",
		LastClient:   "10.0.0.7",
	}
}

func binaryMiss() audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: manifest.TypeBinary,
		Host:         "downloads.example.com",
		PatternHint:  "https://downloads.example.com/",
		PkgName:      "example-vendor/widget-tool_1.9.8_linux_amd64.zip",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://downloads.example.com/widget-tool/1.9.8/widget-tool_1.9.8_linux_amd64.zip",
		LastClient:   "10.0.0.8",
	}
}

// The assertion is on what the store holds after a real import, not on the
// payload: a generator tested only against its own output passes while
// producing something nothing can import.
func TestGenerateManifestsRoundTripsThroughImport(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss(), npmMiss(), gitMiss(), binaryMiss())

	path := filepath.Join(t.TempDir(), "catalog.json")
	if _, _, err := runDiscoverSplit(t, "generate-manifests", "-o", path); err != nil {
		t.Fatalf("generate-manifests: %v", err)
	}

	imp := newImportCmd(&globalFlags{})
	imp.SetArgs([]string{path})
	imp.SilenceUsage = true
	imp.SilenceErrors = true
	if err := imp.Execute(); err != nil {
		t.Fatalf("pkg import %s: %v", path, err)
	}

	for _, want := range []struct {
		typ, name, version, url string
	}{
		{manifest.TypeGomod, "example.com/example-corp/widget-sdk", "v1.30.0", "https://proxy.golang.org"},
		{manifest.TypeNpm, "lodash", "4.17.21", "https://registry.npmjs.org"},
		{manifest.TypeGit, "example-corp/widget-sdk", "", "https://example.com/example-corp/widget-sdk"},
		{manifest.TypeBinary, "example-vendor/widget-tool_1.9.8_linux_amd64.zip", "", "https://downloads.example.com/widget-tool/1.9.8/widget-tool_1.9.8_linux_amd64.zip"},
	} {
		pm := env.readManifest(t, want.typ, want.name)
		if pm == nil {
			t.Fatalf("%s/%s: not in the store after import", want.typ, want.name)
		}
		if len(pm.Versions) != 1 {
			t.Fatalf("%s/%s: got %d versions, want 1", want.typ, want.name, len(pm.Versions))
		}
		ve := pm.Versions[0]
		if ve.Version != want.version || ve.URL != want.url {
			t.Errorf("%s/%s: got version %q url %q, want %q / %q",
				want.typ, want.name, ve.Version, ve.URL, want.version, want.url)
		}
		if ve.Mode != manifest.ModeProxy {
			t.Errorf("%s/%s: got mode %q, want %q", want.typ, want.name, ve.Mode, manifest.ModeProxy)
		}
	}

	// Everything is now cataloged, so the idempotent re-run has nothing left.
	out, _, err := runDiscoverSplit(t, "generate-manifests", "--skip-existing")
	if err != nil {
		t.Fatalf("generate-manifests --skip-existing: %v", err)
	}
	if pms := decodeGenerated(t, out); len(pms) != 0 {
		t.Fatalf("--skip-existing emitted %d package(s) after import, want 0", len(pms))
	}
}

func TestGenerateManifestsIsByteIdentical(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t,
		gomodMiss(), npmMiss(), gitMiss(), binaryMiss(),
		withVersion(gomodMiss(), "v1.9.0"),
		withVersion(gomodMiss(), "v1.10.0"),
		withVersion(gomodMiss(), "release-candidate"),
	)

	first, _, err := runDiscoverSplit(t, "generate-manifests")
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}
	second, _, err := runDiscoverSplit(t, "generate-manifests")
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}
	if first != second {
		t.Fatalf("two runs over the same rows differ:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}

	pms := decodeGenerated(t, first)
	var gomod *manifest.PackageManifest
	for i := range pms {
		if pms[i].Type == manifest.TypeGomod {
			gomod = &pms[i]
		}
	}
	if gomod == nil {
		t.Fatal("no gomod manifest generated")
	}
	var got []string
	for _, ve := range gomod.Versions {
		got = append(got, ve.Version)
	}
	want := []string{"v1.30.0", "v1.10.0", "v1.9.0", "release-candidate"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("version order: got %v, want %v (newest first, unparseable last)", got, want)
	}
}

func withVersion(row audit.DiscoveryRow, version string) audit.DiscoveryRow {
	row.PkgVersion = version
	row.UpstreamURL = "https://proxy.golang.org/" + row.PkgName + "/@v/" + version + ".info"
	return row
}

func withRequests(t *testing.T, env *discoverEnv, row audit.DiscoveryRow, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		env.seedDiscovery(t, row)
	}
}

func TestGenerateManifestsSinceFilter(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss(), npmMiss())
	env.backdate(t, "lodash", 30*24*time.Hour)

	out, errOut, err := runDiscoverSplit(t, "generate-manifests", "--since", "7d")
	if err != nil {
		t.Fatalf("generate-manifests --since: %v", err)
	}
	pms := decodeGenerated(t, out)
	if len(pms) != 1 || pms[0].Type != manifest.TypeGomod {
		t.Fatalf("--since 7d kept %d package(s), want only the gomod one: %s", len(pms), out)
	}
	if !strings.Contains(errOut, "dropped by --since") {
		t.Errorf("summary does not report the --since drop: %s", errOut)
	}

	all, _, err := runDiscoverSplit(t, "generate-manifests", "--since", "90d")
	if err != nil {
		t.Fatalf("generate-manifests --since 90d: %v", err)
	}
	if len(decodeGenerated(t, all)) != 2 {
		t.Errorf("--since 90d should keep both packages: %s", all)
	}
}

func TestGenerateManifestsMinRequestsFilter(t *testing.T) {
	env := newDiscoverEnv(t)
	withRequests(t, env, gomodMiss(), 12)
	env.seedDiscovery(t, npmMiss())

	out, errOut, err := runDiscoverSplit(t, "generate-manifests", "--min-requests", "10")
	if err != nil {
		t.Fatalf("generate-manifests --min-requests: %v", err)
	}
	pms := decodeGenerated(t, out)
	if len(pms) != 1 || pms[0].Type != manifest.TypeGomod {
		t.Fatalf("--min-requests 10 kept %d package(s), want only the gomod one: %s", len(pms), out)
	}
	if !strings.Contains(errOut, "dropped by --min-requests") {
		t.Errorf("summary does not report the --min-requests drop: %s", errOut)
	}
}

func TestGenerateManifestsSkipExistingFilter(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss(), npmMiss())

	store := manifest.NewLocalStore(env.manifestDir)
	ctx := context.Background()
	if err := store.AddVersion(ctx, manifest.TypeNpm, "lodash", manifest.VersionEntry{
		Version: "1.0.0",
		URL:     "https://registry.npmjs.org",
		Mode:    manifest.ModeHosted,
	}); err != nil {
		t.Fatalf("seed existing manifest: %v", err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("save index: %v", err)
	}

	out, errOut, err := runDiscoverSplit(t, "generate-manifests", "--skip-existing")
	if err != nil {
		t.Fatalf("generate-manifests --skip-existing: %v", err)
	}
	pms := decodeGenerated(t, out)
	if len(pms) != 1 || pms[0].Type != manifest.TypeGomod {
		t.Fatalf("--skip-existing kept %d package(s), want only the uncataloged gomod one: %s", len(pms), out)
	}
	if !strings.Contains(errOut, "dropped by --skip-existing") {
		t.Errorf("summary does not report the --skip-existing drop: %s", errOut)
	}

	// The flag filters, it does not touch what it found.
	pm := env.readManifest(t, manifest.TypeNpm, "lodash")
	if pm == nil || len(pm.Versions) != 1 || pm.Versions[0].Mode != manifest.ModeHosted {
		t.Errorf("the existing manifest was rewritten: %+v", pm)
	}
}

// An entry the import would reject is skipped here instead, so a half-written
// store is never the operator's first sign of trouble. The row carries a type
// no build of bodega serves, which is what a database written by a newer
// version looks like to an older binary.
func TestGenerateManifestsSkipsWhatTheValidatorRefuses(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss(), audit.DiscoveryRow{
		RegistryType: "conda",
		Host:         "conda.anaconda.org",
		PatternHint:  "conda.anaconda.org",
		PkgName:      "numpy",
		PkgVersion:   "2.1.0",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://conda.anaconda.org/conda-forge/linux-64/numpy-2.1.0.conda",
		LastClient:   "10.0.0.9",
	})

	out, errOut, err := runDiscoverSplit(t, "generate-manifests")
	if err != nil {
		t.Fatalf("generate-manifests: %v", err)
	}
	for _, pm := range decodeGenerated(t, out) {
		if pm.Type == "conda" {
			t.Fatalf("a manifest of an unknown type reached the payload: %s", out)
		}
	}
	if !strings.Contains(errOut, "WARN skipped (conda, numpy)") {
		t.Errorf("the skip does not name (type, pkg_name): %s", errOut)
	}
	if !strings.Contains(errOut, "failed manifest validation") {
		t.Errorf("summary does not count the validation failure: %s", errOut)
	}
}

// Reading is all this command does. A generator that also pruned would turn a
// reviewable dump into an unrepeatable one.
func TestGenerateManifestsLeavesDiscoveryRowsAlone(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss(), npmMiss(), gitMiss())
	before := env.discoveryRowCount(t)

	if _, _, err := runDiscoverSplit(t, "generate-manifests", "--min-requests", "99"); err != nil {
		t.Fatalf("generate-manifests: %v", err)
	}
	if after := env.discoveryRowCount(t); after != before {
		t.Fatalf("discovery rows changed from %d to %d", before, after)
	}
}

// Issue #142: go resolves an unknown module through /@v/list and /@v/@latest,
// neither of which carries a version, and gomod composes the version into the
// fetch URL. The versioned rows for the same module still generate.
func TestGenerateManifestsDropsVersionlessGomodRows(t *testing.T) {
	env := newDiscoverEnv(t)
	listRow := gomodMiss()
	listRow.PkgVersion = ""
	listRow.UpstreamURL = "https://proxy.golang.org/example.com/example-corp/widget-sdk/@v/list"
	env.seedDiscovery(t, listRow, gomodMiss())

	out, errOut, err := runDiscoverSplit(t, "generate-manifests", "gomod")
	if err != nil {
		t.Fatalf("generate-manifests gomod: %v", err)
	}
	pms := decodeGenerated(t, out)
	if len(pms) != 1 {
		t.Fatalf("got %d manifest(s), want 1: %s", len(pms), out)
	}
	if len(pms[0].Versions) != 1 || pms[0].Versions[0].Version != "v1.30.0" {
		t.Fatalf("versionless row reached the payload: %+v", pms[0].Versions)
	}
	if !strings.Contains(errOut, "versionless observation") {
		t.Errorf("the dropped row is not reported: %s", errOut)
	}
}

// no_namespace rows name a namespace nothing is configured for, which is a
// config fix rather than a manifest. The operator gets told which, not an
// empty file with no explanation.
func TestGenerateManifestsReportsRowsItCannotUse(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t,
		audit.DiscoveryRow{
			RegistryType: manifest.TypeGit,
			PatternHint:  "internal",
			PkgName:      "internal",
			Decision:     audit.DecisionNoNamespace,
			LastClient:   "10.0.0.5",
		},
		audit.DiscoveryRow{
			RegistryType: manifest.TypeNpm,
			Host:         "registry.npmjs.org",
			PatternHint:  "lodash",
			PkgName:      "lodash",
			PkgVersion:   "4.17.21",
			Decision:     audit.DecisionNoPolicy,
			UpstreamURL:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			LastClient:   "10.0.0.6",
		},
	)

	out, errOut, err := runDiscoverSplit(t, "generate-manifests")
	if err != nil {
		t.Fatalf("generate-manifests: %v", err)
	}
	if pms := decodeGenerated(t, out); len(pms) != 0 {
		t.Fatalf("got %d manifest(s) from rows that are not catalog misses: %s", len(pms), out)
	}
	for _, want := range []string{audit.DecisionNoNamespace, "not catalog misses"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("summary does not mention %q: %s", want, errOut)
		}
	}
}

// seedPolicy inserts one allow-list rule directly, which is what
// 'bodega policy add' writes.
func (e *discoverEnv) seedPolicy(t *testing.T, regType, kind, pattern string) {
	t.Helper()
	db, err := audit.Open(e.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.InsertPolicy(context.Background(), audit.PolicyInfo{
		ID:           "test-" + pattern,
		RegistryType: regType,
		RuleKind:     kind,
		Pattern:      pattern,
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
}

// TestGenerateManifestsAppliesTheAllowList is issue #167. The generator called
// admit.Admit with a nil checker, which disables checkAllowList outright, so a
// package the allow-list refuses passed generation and then aborted 'bodega
// pkg import' partway through the file with the packages ahead of it already
// written.
func TestGenerateManifestsAppliesTheAllowList(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss())
	env.seedPolicy(t, manifest.TypeGomod, policy.KindPrefix, "example.com/example-vendor/")

	out, errOut, err := runDiscoverSplit(t, "generate-manifests")
	if err != nil {
		t.Fatalf("generate-manifests: %v", err)
	}
	if pms := decodeGenerated(t, out); len(pms) != 0 {
		t.Fatalf("a package the allow-list refuses reached the payload: %s", out)
	}
	if !strings.Contains(errOut, "WARN skipped (gomod, example.com/example-corp/widget-sdk)") {
		t.Errorf("the skip does not name the refused package: %s", errOut)
	}

	// Read-only is the other half of the contract: the allow-list check runs
	// with no audit database behind it, so nothing records the refusal here.
	db, err := audit.Open(env.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	n, err := db.Count(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	if n != 0 {
		t.Errorf("generate-manifests wrote %d audit event(s); the command reads", n)
	}
}

// A package the allow-list permits is unaffected, which is what keeps the
// check from reading as "generation stopped working".
func TestGenerateManifestsEmitsWhatTheAllowListPermits(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss())
	env.seedPolicy(t, manifest.TypeGomod, policy.KindPrefix, "example.com/example-corp/")

	out, _, err := runDiscoverSplit(t, "generate-manifests")
	if err != nil {
		t.Fatalf("generate-manifests: %v", err)
	}
	pms := decodeGenerated(t, out)
	if len(pms) != 1 || pms[0].Name != "example.com/example-corp/widget-sdk" {
		t.Fatalf("an allowed package did not reach the payload: %s", out)
	}
}

// gitNoNamespaceRow is what a request under /git/ naming a namespace nothing
// is configured for writes: the namespace is both the package and the pattern.
func gitNoNamespaceRow() audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: manifest.TypeGit,
		PatternHint:  "gitlab",
		PkgName:      "gitlab",
		Decision:     audit.DecisionNoNamespace,
		LastClient:   "10.0.0.5",
	}
}

// The repair for a no_namespace row is a git_upstreams key, and the row is the
// one thing that names it. --as policy used to insert a rule for the pattern
// and print "Promoted git \"gitlab\"", leaving the 404 exactly where it was.
func TestPromotePolicyRefusesANoNamespaceRow(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gitNoNamespaceRow())

	out, err := runDiscover(t, "promote", "git", "gitlab")
	if err == nil {
		t.Fatalf("promote of a no_namespace pattern succeeded: %s", out)
	}
	for _, want := range []string{audit.DecisionNoNamespace, "git_upstreams", "gitlab"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}

	db, openErr := audit.Open(env.auditDB)
	if openErr != nil {
		t.Fatalf("open audit db: %v", openErr)
	}
	defer func() { _ = db.Close() }()
	rules, listErr := db.ListPolicies(context.Background())
	if listErr != nil {
		t.Fatalf("list policies: %v", listErr)
	}
	if len(rules) != 0 {
		t.Errorf("the refused promote wrote %d rule(s): %+v", len(rules), rules)
	}
}

// A pattern that has ever been seen as anything else is a real observation and
// still promotes: the refusal is on rows that are only no_namespace.
func TestPromotePolicyAllowsAPatternSeenAsSomethingElse(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gitNoNamespaceRow(), audit.DiscoveryRow{
		RegistryType: manifest.TypeGit,
		PatternHint:  "gitlab",
		PkgName:      "gitlab/team/tool",
		Decision:     audit.DecisionNoPolicy,
		UpstreamURL:  "https://gitlab.example/team/tool.git",
		LastClient:   "10.0.0.6",
	})

	if out, err := runDiscover(t, "promote", "git", "gitlab"); err != nil {
		t.Fatalf("promote of a mixed pattern refused: %v\n%s", err, out)
	}
}

// promote-all reports the unconfigured patterns per line and promotes the rest,
// rather than aborting a bulk run over a mixed type.
func TestPromoteAllPolicySkipsNoNamespacePatterns(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gitNoNamespaceRow(), audit.DiscoveryRow{
		RegistryType: manifest.TypeGit,
		PatternHint:  "github.com/octocat/",
		PkgName:      "github/octocat/Hello-World",
		Decision:     audit.DecisionNoPolicy,
		UpstreamURL:  "https://github.com/octocat/Hello-World.git",
		LastClient:   "10.0.0.6",
	})

	// The per-pattern lines go to os.Stdout like every other promote-all
	// report, so the assertion is on the rules written rather than the print.
	out, err := runDiscover(t, "promote-all", "git")
	if err != nil {
		t.Fatalf("promote-all git: %v\n%s", err, out)
	}

	db, openErr := audit.Open(env.auditDB)
	if openErr != nil {
		t.Fatalf("open audit db: %v", openErr)
	}
	defer func() { _ = db.Close() }()
	rules, listErr := db.ListPolicies(context.Background())
	if listErr != nil {
		t.Fatalf("list policies: %v", listErr)
	}
	if len(rules) != 1 || rules[0].Pattern != "github.com/octocat/" {
		t.Errorf("promote-all wrote %+v, want only the github.com/octocat/ rule", rules)
	}
}

// writeOnlySinkEnv is newDiscoverEnv's config with the event stream pointed at
// a JSONL file. The embedded store still exists — it holds the ACLs and the
// tokens — so a command that read it anyway would find a real, empty database
// and print an empty table, which is the answer this refusal replaces.
func writeOnlySinkEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	body := fmt.Sprintf(`{
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "audit_db": %q,
  "log_dir": %q,
  "allow_plaintext": true,
  "apt_codename": "noble",
  "audit_sink": "jsonl",
  "audit_sink_dsn": %q
}`, filepath.Join(dir, "storage"), filepath.Join(dir, "manifests"),
		filepath.Join(dir, "audit.db"), dir, filepath.Join(dir, "audit.jsonl"))
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)
}

// Every discovery read refuses by name under a write-only sink. promote is
// named in docs/usage.md as unavailable, so it is in the table rather than
// left to be inferred from list: it reads the discovery rows to build the
// policy rule or the manifest entries it writes.
func TestDiscoveryReadsRefuseUnderAWriteOnlySink(t *testing.T) {
	for _, args := range [][]string{
		{"list"},
		{"show", "gomod", "example.com/example-corp/"},
		{"promote", "gomod", "example.com/example-corp/"},
		{"promote-all", "gomod"},
		{"export", "json", "gomod"},
		{"clear", "gomod"},
		{"generate-manifests", "gomod"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			writeOnlySinkEnv(t)
			out, err := runDiscover(t, args...)
			if err == nil {
				t.Fatalf("discover %v succeeded under a write-only sink; output:\n%s", args, out)
			}
			msg := err.Error()
			for _, want := range []string{"jsonl", "write-only", "postgres"} {
				if !strings.Contains(msg, want) {
					t.Errorf("refusal does not mention %q: %s", want, msg)
				}
			}
		})
	}
}

// An export of nothing is an empty collection, not null. `jq '.[]'` over null
// is an error rather than an empty iteration, so a consumer written the
// obvious way breaks on the empty table instead of doing nothing.
func TestDiscoverExportEmptyTableIsACollection(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t) // no rows: the store exists and the table is empty

	var runErr error
	out := captureStdout(t, func() {
		_, runErr = runDiscover(t, "export", "json")
	})
	if runErr != nil {
		t.Fatalf("discover export json: %v", runErr)
	}
	if got := strings.TrimSpace(out); got != "[]" {
		t.Errorf("empty export emitted %q, want []", got)
	}
	var rows []audit.DiscoveryRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("export is not JSON: %v", err)
	}
	if rows == nil {
		t.Error("empty export decodes to nil, so a consumer iterating it has nothing to iterate over")
	}

	csvOut := captureStdout(t, func() {
		_, runErr = runDiscover(t, "export", "csv")
	})
	if runErr != nil {
		t.Fatalf("discover export csv: %v", runErr)
	}
	if !strings.HasPrefix(csvOut, "registry_type,") {
		t.Errorf("empty csv export starts %q, want the header row", csvOut)
	}
}

// pypiIndexMiss is what a simple-index read for an uncataloged distribution
// records: the index URL and no version, because /pypi/simple/<dist>/ names
// none.
func pypiIndexMiss() audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: manifest.TypePypi,
		Host:         "pypi.org",
		PatternHint:  "django-cors-headers",
		PkgName:      "django-cors-headers",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://pypi.org/simple/django-cors-headers/",
		LastClient:   "10.0.0.9",
	}
}

// B75 R4: observe-then-promote has to bootstrap a catalog from an empty store,
// which is what docs/usage.md promises and what the widget install replaced with
// fifty-one rounds of a shell loop over pip's stderr. A pypi entry naming only
// the distribution is fetchable — the server resolves a wheel by reading
// /simple/<dist>/ and the builder resolves one through pip — so the row promotes
// rather than being skipped for having no version.
func TestGenerateManifestsPromotesAVersionlessPypiRow(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, pypiIndexMiss())

	path := filepath.Join(t.TempDir(), "catalog.json")
	out, errOut, err := runDiscoverSplit(t, "generate-manifests", "pypi", "-o", path)
	if err != nil {
		t.Fatalf("generate-manifests pypi: %v (out %q, err %q)", err, out, errOut)
	}
	if strings.Contains(errOut, "without a version") && strings.Contains(errOut, "django-cors-headers") {
		t.Errorf("the row was skipped for having no version, so an observe window catalogs nothing: %s", errOut)
	}

	imp := newImportCmd(&globalFlags{})
	imp.SetArgs([]string{path})
	imp.SilenceUsage = true
	imp.SilenceErrors = true
	if err := imp.Execute(); err != nil {
		t.Fatalf("pkg import %s: %v", path, err)
	}

	pm := env.readManifest(t, manifest.TypePypi, "django-cors-headers")
	if pm == nil {
		t.Fatal("pypi/django-cors-headers: not in the store after import")
	}
	if len(pm.Versions) != 1 {
		t.Fatalf("pypi/django-cors-headers: got %d versions, want 1", len(pm.Versions))
	}
	ve := pm.Versions[0]
	if ve.Mode != manifest.ModeProxy {
		t.Errorf("mode = %q, want %q", ve.Mode, manifest.ModeProxy)
	}
	// The registry root, not the index path: manifestURL trims it, and the
	// server appends /simple/<dist>/ itself.
	if ve.URL != "https://pypi.org" {
		t.Errorf("url = %q, want the registry root", ve.URL)
	}
	if ve.Version != "" || ve.VersionConstraint != manifest.ConstraintAny {
		t.Errorf("version %q constraint %q, want an open entry", ve.Version, ve.VersionConstraint)
	}
}

// B75 R7: `discover export` emits two formats of one thing, and they disagreed.
// CSV carried pkg_name, JSON carried PkgName, and docs/usage.md documents one
// set of names. The e2e harness compares the same two lists from a live run;
// this one runs in `make check`, which the harness does not.
func TestDiscoverExportCSVHeaderMatchesTheJSONKeys(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, pypiIndexMiss())

	// `discover export` writes to os.Stdout rather than to the cobra stream, so
	// the process pipe is the only place its payload appears.
	csvOut, _, err := runOSVCmd(t, newDiscoverCmd(&globalFlags{}), "export", "csv", "pypi")
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}
	header, _, ok := strings.Cut(csvOut, "\n")
	if !ok {
		t.Fatalf("export csv emitted no header: %q", csvOut)
	}

	jsonOut, _, err := runOSVCmd(t, newDiscoverCmd(&globalFlags{}), "export", "json", "pypi")
	if err != nil {
		t.Fatalf("export json: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &rows); err != nil {
		t.Fatalf("export json is not a collection: %v (%q)", err, jsonOut)
	}
	if len(rows) == 0 {
		t.Fatal("export json emitted no rows, so the key set is unmeasured")
	}

	inCSV := map[string]bool{}
	for _, col := range strings.Split(strings.TrimSpace(header), ",") {
		inCSV[col] = true
	}
	for key := range rows[0] {
		if !inCSV[key] {
			t.Errorf("json key %q is on no CSV column", key)
		}
		delete(inCSV, key)
	}
	for col := range inCSV {
		t.Errorf("CSV column %q is in no json object", col)
	}
}
