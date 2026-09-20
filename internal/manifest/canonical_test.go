package manifest_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// The six names B75 names, with the form PEP 503 canonicalizes each to. Three
// implementations of this rule lived in the tree and two of them disagreed on
// `.`, so a rule written against one matched nothing the other spelled.
var canonicalPypiCases = map[string]string{
	"Django":              "django",
	"zope.interface":      "zope-interface",
	"ruamel.yaml":         "ruamel-yaml",
	"django_cors_headers": "django-cors-headers",
	"a__b":                "a-b",
	"A.B_c":               "a-b-c",
}

func TestCanonicalPypiName(t *testing.T) {
	for in, want := range canonicalPypiCases {
		if got := manifest.CanonicalPypiName(in); got != want {
			t.Errorf("CanonicalPypiName(%q) = %q, want %q", in, got, want)
		}
		if got := manifest.CanonicalPypiName(want); got != want {
			t.Errorf("CanonicalPypiName is not idempotent: %q -> %q", want, got)
		}
		if got := manifest.CanonicalName(manifest.TypePypi, in); got != want {
			t.Errorf("CanonicalName(pypi, %q) = %q, want %q", in, got, want)
		}
	}
}

// Canonicalization is pypi's rule and nobody else's: an npm scope is
// case-sensitive, a Go module path is not a distribution name, and a crate or
// chart name carries no separator the rule would collapse.
func TestCanonicalNameLeavesEveryOtherTypeAlone(t *testing.T) {
	cases := []struct{ typ, name string }{
		{manifest.TypeNpm, "@Babel/Core"},
		{manifest.TypeGomod, "github.com/Masterminds/semver"},
		{manifest.TypeCargo, "serde_json"},
		{manifest.TypeHelm, "cert-manager"},
		{manifest.TypeApt, "libpq-dev"},
		{manifest.TypeGit, "example-corp/widget"},
		{manifest.TypeBinary, "hello_world"},
	}
	for _, c := range cases {
		if got := manifest.CanonicalName(c.typ, c.name); got != c.name {
			t.Errorf("CanonicalName(%s, %q) = %q, want it unchanged", c.typ, c.name, got)
		}
	}
}

// B75 R3: the write path and the read path canonicalize, so `bodega pkg convert
// pypi` writing the name `pip list --format=json` reported produces a manifest
// the client that inventory came from can reach.
func TestStorePypiWriteAndReadAgreeOnEverySpelling(t *testing.T) {
	for in, want := range canonicalPypiCases {
		dir := t.TempDir()
		store := manifest.NewLocalStore(dir)
		pm := &manifest.PackageManifest{Name: in, Type: manifest.TypePypi,
			Versions: []manifest.VersionEntry{{Version: "1.0.0"}}}
		if err := store.SavePackage(t.Context(), pm); err != nil {
			t.Fatalf("save pypi/%s: %v", in, err)
		}
		if pm.Name != want {
			t.Errorf("saved pypi/%s carries Name %q, want %q", in, pm.Name, want)
		}
		path := filepath.Join(dir, manifest.TypePypi, want, "manifest.json")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("pypi/%s did not land at %s: %v", in, path, err)
		}
		for _, spelling := range []string{in, want} {
			got, err := store.GetPackage(t.Context(), manifest.TypePypi, spelling)
			if err != nil {
				t.Fatalf("get pypi/%s: %v", spelling, err)
			}
			if got == nil {
				t.Errorf("pypi/%s written as %q is unreachable", spelling, in)
			}
		}
		if names := store.ListPackages(manifest.TypePypi); len(names) != 1 || names[0] != want {
			t.Errorf("index lists %v, want [%s]", names, want)
		}
	}
}

// An install predating canonicalization holds these on disk, and every read now
// composes a path that misses them. `bodega repair check` names them; `bodega
// repair` moves them, because renaming a manifest under a running server is the
// operator's moment to pick.
func TestMisnamedPackagesAndRenameToCanonical(t *testing.T) {
	dir := t.TempDir()
	writePackageManifest(t, dir, manifest.PackageManifest{
		Name: "zope.interface", Type: manifest.TypePypi,
		Versions: []manifest.VersionEntry{{Version: "7.2"}},
	})
	writePackageManifest(t, dir, manifest.PackageManifest{
		Name: "six", Type: manifest.TypePypi,
		Versions: []manifest.VersionEntry{{Version: "1.16.0"}},
	})
	store := manifest.NewLocalStore(dir)

	misnamed, err := store.MisnamedPackages(t.Context())
	if err != nil {
		t.Fatalf("list misnamed: %v", err)
	}
	if len(misnamed) != 1 {
		t.Fatalf("misnamed = %+v, want the one non-canonical name", misnamed)
	}
	if misnamed[0].Stored != "zope.interface" || misnamed[0].Canonical != "zope-interface" {
		t.Fatalf("misnamed[0] = %+v", misnamed[0])
	}

	if err := store.RenameToCanonical(t.Context(), misnamed[0]); err != nil {
		t.Fatalf("rename: %v", err)
	}
	pm, err := store.GetPackage(t.Context(), manifest.TypePypi, "zope-interface")
	if err != nil || pm == nil {
		t.Fatalf("get renamed package: %v (pm %v)", err, pm)
	}
	if len(pm.Versions) != 1 || pm.Versions[0].Version != "7.2" {
		t.Errorf("renamed manifest lost its versions: %+v", pm.Versions)
	}
	if _, err := os.Stat(filepath.Join(dir, manifest.TypePypi, "zope.interface", "manifest.json")); !os.IsNotExist(err) {
		t.Errorf("the old path survives the rename: %v", err)
	}
	left, err := store.MisnamedPackages(t.Context())
	if err != nil {
		t.Fatalf("re-list misnamed: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("misnamed after the repair = %+v, want none", left)
	}
}

// Two manifests for one distribution is two sets of version entries, and which
// pins survive is not a sweep's decision.
func TestRenameToCanonicalRefusesACollision(t *testing.T) {
	dir := t.TempDir()
	writePackageManifest(t, dir, manifest.PackageManifest{
		Name: "zope.interface", Type: manifest.TypePypi,
		Versions: []manifest.VersionEntry{{Version: "7.2"}},
	})
	writePackageManifest(t, dir, manifest.PackageManifest{
		Name: "zope-interface", Type: manifest.TypePypi,
		Versions: []manifest.VersionEntry{{Version: "6.1"}},
	})
	store := manifest.NewLocalStore(dir)
	misnamed, err := store.MisnamedPackages(t.Context())
	if err != nil || len(misnamed) != 1 {
		t.Fatalf("misnamed = %+v, err %v", misnamed, err)
	}
	if err := store.RenameToCanonical(t.Context(), misnamed[0]); err == nil {
		t.Fatal("rename onto an occupied canonical path succeeded, losing one manifest's entries")
	}
	for _, name := range []string{"zope.interface", "zope-interface"} {
		if _, err := os.Stat(filepath.Join(dir, manifest.TypePypi, name, "manifest.json")); err != nil {
			t.Errorf("the refusal moved %s anyway: %v", name, err)
		}
	}
}

// A rename that wrote the canonical copy and died before deleting the old one
// leaves both paths populated. A second run has to finish it: the bytes at the
// canonical path are the old manifest's, so there is nothing to merge and
// nothing to lose, and refusing would strand the distribution under a name no
// read composes.
func TestRenameToCanonicalFinishesAnInterruptedRename(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zope.interface", "zope-interface"} {
		writePackageManifest(t, dir, manifest.PackageManifest{
			Name: name, Type: manifest.TypePypi,
			Versions: []manifest.VersionEntry{{Version: "7.2"}},
		})
	}
	store := manifest.NewLocalStore(dir)
	misnamed, err := store.MisnamedPackages(t.Context())
	if err != nil || len(misnamed) != 1 {
		t.Fatalf("misnamed = %+v, err %v", misnamed, err)
	}
	if err := store.RenameToCanonical(t.Context(), misnamed[0]); err != nil {
		t.Fatalf("the retry refused its own half-finished copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, manifest.TypePypi, "zope.interface", "manifest.json")); !os.IsNotExist(err) {
		t.Errorf("the old path survives the retry: %v", err)
	}
	pm, err := store.GetPackage(t.Context(), manifest.TypePypi, "zope-interface")
	if err != nil || pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("canonical manifest after the retry = %+v (err %v)", pm, err)
	}
}

// A stored segment is not a name: SafeName encodes "/" and nothing else, so
// decoding a pypi segment reads a literal "--" as a scope separator. "a--b"
// came back as "a/b", which is already canonical, and the detector reported
// nothing for a manifest every read misses.
func TestMisnamedPackagesReadsThePypiSegmentLiterally(t *testing.T) {
	dir := t.TempDir()
	names := []string{"a--b", "A.B_c", "django_cors_headers"}
	if caseSensitive(t, dir) {
		// "Django" and "django" are one directory on APFS, and no sequence of
		// writes and deletes through the backend renames an object to its own
		// name. That case is TestRenameRefusesWhenTheBackendFoldsTheTwoNames.
		names = append(names, "Django")
	}
	for _, name := range names {
		writePackageManifest(t, dir, manifest.PackageManifest{
			Name: name, Type: manifest.TypePypi,
			Versions: []manifest.VersionEntry{{Version: "1.0.0"}},
		})
	}
	// An npm scope is stored under the same "--" encoding and does mean a
	// slash, so the decode still has to happen there.
	writePackageManifest(t, dir, manifest.PackageManifest{
		Name: "@babel/core", Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{{Version: "7.0.0"}},
	})
	store := manifest.NewLocalStore(dir)

	misnamed, err := store.MisnamedPackages(t.Context())
	if err != nil {
		t.Fatalf("list misnamed: %v", err)
	}
	got := map[string]string{}
	for _, m := range misnamed {
		got[m.Type+"/"+m.Stored] = m.Canonical
	}
	want := map[string]string{
		"pypi/a--b":                "a-b",
		"pypi/A.B_c":               "a-b-c",
		"pypi/django_cors_headers": "django-cors-headers",
	}
	if slices.Contains(names, "Django") {
		want["pypi/Django"] = "django"
	}
	for stored, canonical := range want {
		if got[stored] != canonical {
			t.Errorf("misnamed = %v, want %s -> %s", got, stored, canonical)
		}
	}
	if len(got) != len(want) {
		t.Errorf("misnamed = %v, want exactly %v — an npm scope is not a misnaming", got, want)
	}

	for _, m := range misnamed {
		if err := store.RenameToCanonical(t.Context(), m); err != nil {
			t.Fatalf("rename %s/%s: %v", m.Type, m.Stored, err)
		}
		pm, err := store.GetPackage(t.Context(), m.Type, m.Canonical)
		if err != nil || pm == nil {
			t.Fatalf("get %s/%s after the rename: %v (pm %v)", m.Type, m.Canonical, err, pm)
		}
	}
	left, err := store.MisnamedPackages(t.Context())
	if err != nil {
		t.Fatalf("re-list misnamed: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("misnamed after the repair = %+v, want none", left)
	}
}

// A repair that cannot move the object has to say so. On a case-insensitive
// store the canonical path and the stored one name one file, so the rename
// writes through to the manifest it is renaming and the old spelling survives
// whatever the repair does — reporting that as repaired is how an operator ends
// up running the same sweep every week.
func TestRenameRefusesWhenTheBackendFoldsTheTwoNames(t *testing.T) {
	dir := t.TempDir()
	if caseSensitive(t, dir) {
		t.Skip("this filesystem tells pypi/Django and pypi/django apart, so the rename is an ordinary one")
	}
	writePackageManifest(t, dir, manifest.PackageManifest{
		Name: "Django", Type: manifest.TypePypi,
		Versions: []manifest.VersionEntry{{Version: "6.1.1"}},
	})
	store := manifest.NewLocalStore(dir)
	misnamed, err := store.MisnamedPackages(t.Context())
	if err != nil || len(misnamed) != 1 {
		t.Fatalf("misnamed = %+v, err %v", misnamed, err)
	}
	err = store.RenameToCanonical(t.Context(), misnamed[0])
	if err == nil {
		t.Fatal("the rename reported success on a store that cannot separate the two names")
	}
	if !strings.Contains(err.Error(), "case-sensitive") {
		t.Errorf("error %q names no repair the operator can make", err)
	}
	pm, getErr := store.GetPackage(t.Context(), manifest.TypePypi, "django")
	if getErr != nil || pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("the refusal cost the manifest: %+v (err %v)", pm, getErr)
	}
}

// caseSensitive reports whether dir distinguishes two names differing only in
// case. ext4 and S3 do; APFS does not by default.
func caseSensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatalf("write case probe: %v", err)
	}
	defer func() { _ = os.Remove(probe) }()
	_, err := os.Stat(filepath.Join(dir, "caseprobe"))
	return os.IsNotExist(err)
}
