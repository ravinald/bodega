package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
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
		if err := db.RecordDiscovery(context.Background(), row); err != nil {
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
		PatternHint:  "github.com/aws/",
		PkgName:      "github.com/aws/aws-sdk-go-v2",
		PkgVersion:   "v1.30.0",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://proxy.golang.org/github.com/aws/aws-sdk-go-v2/@v/v1.30.0.info",
		LastClient:   "10.0.0.5",
	}
}

// The assertion is on the written manifest, not on the printed line: a promote
// that silently no-ops still prints.
func TestPromoteAsManifestWritesTheEntry(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, gomodMiss())

	if _, err := runDiscover(t, "promote", "gomod", "github.com/aws/", "--as", "manifest"); err != nil {
		t.Fatalf("promote --as manifest: %v", err)
	}

	pm := env.readManifest(t, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2")
	if pm == nil {
		t.Fatal("no manifest written")
	}
	if pm.Name != "github.com/aws/aws-sdk-go-v2" {
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
		PatternHint:  "github.com/aws/",
		PkgName:      "github.com/aws/aws-sdk-go-v2",
		PkgVersion:   "v1.31.0",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://proxy.golang.org/github.com/aws/aws-sdk-go-v2/@v/v1.31.0.info",
	})

	if _, err := runDiscover(t, "promote-all", "gomod", "--as", "manifest"); err != nil {
		t.Fatalf("first promote-all: %v", err)
	}
	first := env.readManifest(t, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2")
	if len(first.Versions) != 2 {
		t.Fatalf("versions after first run = %d, want 2 (%+v)", len(first.Versions), first.Versions)
	}

	if _, err := runDiscover(t, "promote-all", "gomod", "--as", "manifest"); err != nil {
		t.Fatalf("second promote-all: %v", err)
	}
	second := env.readManifest(t, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2")
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
	if err := store.AddVersion(ctx, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2", manifest.VersionEntry{
		Version: "v1.30.0",
		Mode:    manifest.ModeHosted,
		URL:     "https://internal.example.com/aws-sdk-go-v2.zip",
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

	pm := env.readManifest(t, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2")
	if len(pm.Versions) != 1 {
		t.Fatalf("versions = %d, want 1 (%+v)", len(pm.Versions), pm.Versions)
	}
	if pm.Versions[0].Mode != manifest.ModeHosted {
		t.Errorf("Mode = %q, want %q — promote downgraded an operator's entry", pm.Versions[0].Mode, manifest.ModeHosted)
	}
	if pm.Versions[0].URL != "https://internal.example.com/aws-sdk-go-v2.zip" {
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
		PatternHint:  "github.com/aws/",
		PkgName:      "aws/aws-sdk-go-v2",
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://github.com/aws/aws-sdk-go-v2",
	})

	if _, err := runDiscover(t, "promote-all", "git", "--as", "manifest"); err != nil {
		t.Fatalf("promote-all --as manifest: %v", err)
	}

	pm := env.readManifest(t, manifest.TypeGit, "aws/aws-sdk-go-v2")
	if pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("manifest = %+v, want one version entry", pm)
	}
	if pm.Versions[0].VersionConstraint != manifest.ConstraintAny {
		t.Errorf("VersionConstraint = %q, want %q", pm.Versions[0].VersionConstraint, manifest.ConstraintAny)
	}
	if pm.Versions[0].URL != "https://github.com/aws/aws-sdk-go-v2" {
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
		PatternHint:  "github.com/aws/",
		PkgName:      "github.com/aws/aws-sdk-go-v2",
		PkgVersion:   "v1.30.0",
		Decision:     audit.DecisionAllowed,
		UpstreamURL:  "https://proxy.golang.org/x",
	})

	_, noMatchErr := runDiscover(t, "promote", "gomod", "github.com/hashicorp/", "--as", "manifest")
	if noMatchErr == nil {
		t.Fatal("promote against a pattern matching no no_manifest row succeeded")
	}
	if !strings.Contains(noMatchErr.Error(), "bodega discover show gomod github.com/hashicorp/") {
		t.Errorf("no-match error does not name the command that shows what was captured:\n%s", noMatchErr)
	}
	if emptyErr.Error() == noMatchErr.Error() {
		t.Error("an empty discovery log and a pattern that matches nothing report the same failure")
	}

	_, asErr := runDiscover(t, "promote", "gomod", "github.com/aws/", "--as", "policyy")
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

	if _, err := runDiscover(t, "promote", "gomod", "github.com/aws/"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if pm := env.readManifest(t, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2"); pm != nil {
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
	if len(rules) != 1 || rules[0].Pattern != "github.com/aws/" {
		t.Errorf("policy rules = %+v, want one rule for github.com/aws/", rules)
	}
}
