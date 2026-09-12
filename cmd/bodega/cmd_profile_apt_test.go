package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// aptSeed is one cataloged binary package and the source it was built from,
// which is the pair dpkg-query's five-field format reports and the pair every
// decision about apt under a profile turns on.
type aptSeed struct {
	source   string
	versions []string
}

// seedAptCatalog writes apt packages carrying a source package, which
// seedCatalogTyped cannot: it writes pypi-shaped entries where the two names
// are one.
func seedAptCatalog(t *testing.T, env *discoverEnv, origin string, pkgs map[string]aptSeed) {
	t.Helper()
	ctx := context.Background()
	store := manifest.NewLocalStore(env.manifestDir)
	if err := store.LoadIndex(ctx); err != nil {
		t.Fatalf("load index: %v", err)
	}
	for name, seed := range pkgs {
		pm := &manifest.PackageManifest{
			ConfigVersion: manifest.CurrentConfigVersion,
			Name:          name,
			Type:          manifest.TypeApt,
		}
		for _, v := range seed.versions {
			pm.Versions = append(pm.Versions, manifest.VersionEntry{Version: v, SourcePackage: seed.source})
		}
		if err := admit.ApplyOrigin(pm, origin); err != nil {
			t.Fatalf("apply origin: %v", err)
		}
		if err := store.SavePackage(ctx, pm); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("save index: %v", err)
	}
}

// mirrorNoble adds an apt_upstreams entry so checkProfileAptBase reaches its
// membership and expansion checks instead of stopping at an unmirrored base.
func mirrorNoble(t *testing.T) {
	t.Helper()
	path := os.Getenv(config.EnvConfigFile)
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(blob, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg["apt_codename"] = "house"
	cfg["apt_upstreams"] = map[string]any{
		"noble": []any{map[string]any{"url": "https://archive.ubuntu.com/ubuntu"}},
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func readBaselineDoc(t *testing.T, path string) profileDoc {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var doc profileDoc
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	return doc
}

// A baseline read off a host lists apt packages under their source package,
// because that is the name the filtered index and the pool predicate both
// close over. Listing the binary names dpkg reports produces a profile whose
// own installed set is reported kept back, one binary at a time.
func TestAptBaselineListsSourcePackagesNotBinaries(t *testing.T) {
	env := newDiscoverEnv(t)
	seedAptCatalog(t, env, "web01", map[string]aptSeed{
		"nginx":        {source: "nginx", versions: []string{"1.24.0-2ubuntu7.1"}},
		"nginx-common": {source: "nginx", versions: []string{"1.24.0-2ubuntu7.1"}},
		"libexpat1":    {source: "expat", versions: []string{"2.6.1-2ubuntu0.2"}},
		"htop":         {source: "htop", versions: []string{"3.3.0-4build1"}},
	})

	baseline := filepath.Join(t.TempDir(), "web.json")
	out := mustRunProfile(t, "create", "web", "--from-origin", "web01", "--out", baseline)

	var got []string
	for _, e := range readBaselineDoc(t, baseline).Entries {
		got = append(got, e.Name)
	}
	want := map[string]bool{"nginx": true, "expat": true, "htop": true}
	for _, name := range got {
		if !want[name] {
			t.Errorf("the baseline lists %q, which is a binary package; the filtered index closes on the source: %v", name, got)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("the baseline lists no entry for source %q: %v", name, got)
	}
	if len(got) != 3 {
		t.Errorf("nginx and nginx-common are one source and should be one entry, got %d: %v", len(got), got)
	}
	if !strings.Contains(out, "  libexpat1 -> expat\n  nginx-common -> nginx\n") {
		t.Errorf("the baseline step does not report both renames in a fixed order, so the operator reads a name they never installed and the list reorders between runs:\n%s", out)
	}
}

// A capture predating the five-field dpkg-query format records no source. The
// binary name is the only name it has, and an entry under it beats no entry.
func TestAptBaselineFallsBackToTheBinaryWhenNoSourceWasCaptured(t *testing.T) {
	env := newDiscoverEnv(t)
	seedAptCatalog(t, env, "web01", map[string]aptSeed{
		"htop": {versions: []string{"3.3.0-4build1"}},
	})

	baseline := filepath.Join(t.TempDir(), "web.json")
	mustRunProfile(t, "create", "web", "--from-origin", "web01", "--out", baseline)

	doc := readBaselineDoc(t, baseline)
	if len(doc.Entries) != 1 || doc.Entries[0].Name != "htop" {
		t.Fatalf("a source-less capture did not fall back to the binary name: %+v", doc.Entries)
	}
}

// --pin names a package the way the host reports it, and the pin has to land
// on the entry the baseline actually wrote.
func TestAptPinOnABinaryLandsOnItsSourceEntry(t *testing.T) {
	env := newDiscoverEnv(t)
	seedAptCatalog(t, env, "web01", map[string]aptSeed{
		"libexpat1": {source: "expat", versions: []string{"2.6.1-2ubuntu0.2"}},
	})

	baseline := filepath.Join(t.TempDir(), "web.json")
	mustRunProfile(t, "create", "web", "--from-origin", "web01", "--out", baseline, "--pin", "libexpat1")

	doc := readBaselineDoc(t, baseline)
	if len(doc.Entries) != 1 {
		t.Fatalf("want one entry, got %+v", doc.Entries)
	}
	e := doc.Entries[0]
	if e.Name != "expat" || e.Constraint != manifest.ConstraintExact || e.Version != "2.6.1-2ubuntu0.2" {
		t.Errorf("--pin libexpat1 did not pin the source entry it was collapsed onto: %+v", e)
	}
}

// profile check resolves an apt entry naming a source the catalog holds only
// as binaries. Without it every baseline this item writes fails CI on its own
// correct entries.
func TestProfileCheckResolvesAnAptSourceEntry(t *testing.T) {
	env := newDiscoverEnv(t)
	mirrorNoble(t)
	seedAptCatalog(t, env, "web01", map[string]aptSeed{
		"libexpat1": {source: "expat", versions: []string{"2.6.1-2ubuntu0.2"}},
	})
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "apt", "expat")
	mustRunProfile(t, "set", "web", "apt", "--membership", "closed", "--expansion", "block", "--base", "noble")

	out := mustRunProfile(t, "check", "web")
	if !strings.Contains(out, "OK") {
		t.Errorf("an entry naming a source the catalog holds as libexpat1 was reported unresolved:\n%s", out)
	}
}

// The inverse, which is the defect: an entry naming a binary is a control that
// matches no paragraph in the index it governs, and nothing said so.
func TestProfileCheckReportsAnAptEntryNamingABinary(t *testing.T) {
	env := newDiscoverEnv(t)
	mirrorNoble(t)
	seedAptCatalog(t, env, "web01", map[string]aptSeed{
		"libexpat1": {source: "expat", versions: []string{"2.6.1-2ubuntu0.2"}},
	})
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "apt", "libexpat1")
	mustRunProfile(t, "set", "web", "apt", "--membership", "closed", "--expansion", "block", "--base", "noble")

	out, err := runProfile(t, "check", "web")
	if err == nil {
		t.Fatalf("check passed an apt entry naming a binary whose source differs:\n%s", out)
	}
	for _, want := range []string{"libexpat1", "expat", "source package"} {
		if !strings.Contains(out, want) {
			t.Errorf("the violation does not name %q, so the repair is not in it:\n%s", want, out)
		}
	}
}

// A profile with no filtered codename reads the mirrored index unchanged, so
// its apt entries are not closed over anything and the binary/source question
// does not arise. Reporting there would be a violation for a state nothing
// enforces.
func TestProfileCheckLeavesAnUnscopedAptEntryAlone(t *testing.T) {
	env := newDiscoverEnv(t)
	seedAptCatalog(t, env, "web01", map[string]aptSeed{
		"libexpat1": {source: "expat", versions: []string{"2.6.1-2ubuntu0.2"}},
	})
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "apt", "libexpat1")
	mustRunProfile(t, "set", "web", "apt", "--membership", "closed", "--expansion", "block")

	if out := mustRunProfile(t, "check", "web"); !strings.Contains(out, "OK") {
		t.Errorf("a profile serving no filtered codename was reported on its binary names:\n%s", out)
	}
}

// --base without --expansion block would serve the archive's own index under
// bodega's signature: the host stops verifying against the distro keyring, the
// pool drops from public to private, and nothing is filtered in return.
func TestAptBaseIsRefusedWithoutBlockExpansion(t *testing.T) {
	newDiscoverEnv(t)
	mirrorNoble(t)
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "apt", "nginx")

	for _, expansion := range []string{"warn", "ignore"} {
		_, err := runProfile(t, "set", "web", "apt", "--membership", "closed", "--expansion", expansion, "--base", "noble")
		if err == nil {
			t.Fatalf("--expansion %s was accepted with --base, which serves upstream verbatim under bodega's key", expansion)
		}
		for _, want := range []string{"--expansion block", "noble-web", expansion} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("--expansion %s: the refusal does not name %q:\n%s", expansion, want, err)
			}
		}
	}

	// The default is warn and is written by --membership closed alone, so the
	// operator reaches the same state without naming an expansion at all.
	if _, err := runProfile(t, "set", "web", "apt", "--membership", "closed", "--base", "noble"); err == nil {
		t.Fatal("--base was accepted at the default expansion")
	}
	if _, err := runProfile(t, "set", "web", "apt", "--membership", "closed", "--expansion", "block", "--base", "noble"); err != nil {
		t.Fatalf("block was refused: %v", err)
	}
}

// The --from-file road reaches the same state, and writeBaseline stamps warn
// into every baseline it writes, so a hand-added apt_base lands there first.
func TestAptBaseInABaselineIsRefusedWithoutBlockExpansion(t *testing.T) {
	newDiscoverEnv(t)
	mirrorNoble(t)
	doc := profileDoc{
		ConfigVersion: 1,
		Name:          "web",
		Types: []profileDocType{{
			Type:           manifest.TypeApt,
			Membership:     audit.MembershipClosed,
			VersionDefault: audit.VersionFloating,
			Expansion:      audit.ExpansionWarn,
			AptBase:        "noble",
		}},
		Entries: []profileDocEntry{{Type: manifest.TypeApt, Name: "nginx", Constraint: manifest.ConstraintAny}},
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	path := filepath.Join(t.TempDir(), "web.json")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	if _, err := runProfile(t, "create", "web", "--from-file", path); err == nil {
		t.Fatal("a baseline carrying apt_base at the default expansion was accepted")
	} else if !strings.Contains(err.Error(), "--expansion block") {
		t.Errorf("the refusal does not name the repair:\n%s", err)
	}
}
