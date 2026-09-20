package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// deadPypiURLFixture seeds what 'discover promote --as manifest' wrote while
// the wheel handler composed <index>/packages/<filename>, on pypi and on an
// operator's own index, beside an entry that already holds a registry root.
func deadPypiURLFixture(t *testing.T) *manifest.Store {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	seed := map[string][]manifest.VersionEntry{
		"six": {
			{Version: "1.16.0", URL: "https://pypi.org/packages/six-1.16.0-py2.py3-none-any.whl", Mode: manifest.ModeProxy},
			{Version: "1.17.0", URL: "https://pypi.org/packages/six-1.17.0-py2.py3-none-any.whl", Mode: manifest.ModeProxy},
		},
		// Issue #197: the same shape on a host the sweep never checked. The
		// rewrite is right for it too, so it is reported and repaired; what
		// the old message got wrong was naming pypi in the line.
		"flask": {
			{Version: "3.0.0", URL: "https://mirror.corp.example/packages/flask-3.0.0-py3-none-any.whl", Mode: manifest.ModeProxy},
		},
		"internal-tool": {
			{Version: "2.0.0", URL: "https://pypi.corp.example", Mode: manifest.ModeProxy},
		},
	}
	for name, versions := range seed {
		for _, ve := range versions {
			if err := store.AddVersion(ctx, manifest.TypePypi, name, ve); err != nil {
				t.Fatalf("AddVersion %s: %v", name, err)
			}
		}
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return store
}

func pypiEntryURL(t *testing.T, store *manifest.Store, name, version string) string {
	t.Helper()
	pm, err := store.GetPackage(t.Context(), manifest.TypePypi, name)
	if err != nil || pm == nil {
		t.Fatalf("GetPackage %s: %v", name, err)
	}
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return ve.URL
		}
	}
	t.Fatalf("pypi/%s has no version %s", name, version)
	return ""
}

// TestRepairRewritesDeadPypiURLs is the migration half of the fix. Resolving
// wheels through the simple index helps every request from here on; a manifest
// already carrying the composed URL keeps it forever, because promote never
// rewrites a version it already wrote.
func TestRepairRewritesDeadPypiURLs(t *testing.T) {
	store := deadPypiURLFixture(t)
	var out bytes.Buffer

	if issues := repairPypiWheelURLs(t.Context(), store, false, &out); issues != 3 {
		t.Errorf("issues = %d, want 3 (both six entries and the corporate one that carries the same shape)", issues)
	}
	for _, version := range []string{"1.16.0", "1.17.0"} {
		if got := pypiEntryURL(t, store, "six", version); got != "https://pypi.org" {
			t.Errorf("pypi/six@%s URL = %q, want the registry root", version, got)
		}
	}
	if got := pypiEntryURL(t, store, "flask", "3.0.0"); got != "https://mirror.corp.example" {
		t.Errorf("pypi/flask@3.0.0 URL = %q, want the corporate index root", got)
	}
	if got := pypiEntryURL(t, store, "internal-tool", "2.0.0"); got != "https://pypi.corp.example" {
		t.Errorf("repair rewrote an entry that already held a registry root to %q", got)
	}
	if !strings.Contains(out.String(), "WRONG SHAPE: pypi/six@1.16.0") {
		t.Errorf("repair did not name what it rewrote:\n%s", out.String())
	}
	// The report states what was checked. Naming pypi beside a corporate host
	// leaves the operator unable to tell whether their own mirror is broken.
	if strings.Contains(out.String(), "which pypi does not serve") {
		t.Errorf("repair still reports a fact about pypi for every host:\n%s", out.String())
	}
}

// TestRepairCheckLeavesPypiURLs is the contract of the check form: report the
// damage, write nothing, let the operator authorize the fix.
func TestRepairCheckLeavesPypiURLs(t *testing.T) {
	store := deadPypiURLFixture(t)
	var out bytes.Buffer

	if issues := repairPypiWheelURLs(t.Context(), store, true, &out); issues != 3 {
		t.Errorf("issues = %d, want 3", issues)
	}
	if got := pypiEntryURL(t, store, "six", "1.16.0"); !strings.Contains(got, "/packages/") {
		t.Errorf("check mode rewrote pypi/six@1.16.0 to %q", got)
	}
}

// TestPromotedPypiURLIsTheRegistryRoot pins the write side. The handler records
// the simple index for one distribution, which is the only fetchable URL it
// knows; VersionEntry.URL means the registry root for pypi as it does for gomod
// and npm, so promotion trims it rather than storing a per-distribution path
// the next distribution's entry would have to repeat.
func TestPromotedPypiURLIsTheRegistryRoot(t *testing.T) {
	got := manifestURL(audit.DiscoveryRow{
		RegistryType: manifest.TypePypi,
		PkgName:      "zope.interface",
		PkgVersion:   "6.1",
		UpstreamURL:  "https://pypi.org/simple/zope-interface/",
	})
	if got != "https://pypi.org" {
		t.Errorf("manifestURL = %q, want https://pypi.org — the normalized name in the path is why the trim is at /simple/", got)
	}
}

// B75 R3: a rename the repair could not make leaves the distribution
// unreachable, so the command has to fail rather than print "(repaired)" over
// the ERROR line it just wrote. The operator's next step is a merge by hand,
// and an exit code of 0 tells them there is nothing to do.
func TestRepairPypiNamesCountsAnUnresolvedCollision(t *testing.T) {
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	ctx := t.Context()
	for name, version := range map[string]string{"zope.interface": "7.2", "zope-interface": "6.1"} {
		if err := store.AddVersion(ctx, manifest.TypePypi, name, manifest.VersionEntry{
			Version: version, Mode: manifest.ModeProxy, URL: "https://pypi.org",
		}); err != nil {
			t.Fatalf("seed pypi/%s: %v", name, err)
		}
	}
	// AddVersion canonicalizes, so the legacy spelling is written the way an
	// install predating that did: straight onto disk.
	writeRawManifest(t, dir, "zope.interface", "7.2")

	var out bytes.Buffer
	found, unresolved := repairPypiNames(ctx, manifest.NewLocalStore(dir), false, &out)
	if found != 1 {
		t.Fatalf("found = %d, want the one non-canonical manifest\n%s", found, out.String())
	}
	if unresolved != 1 {
		t.Errorf("unresolved = %d, want 1 — the collision was reported as repaired\n%s", unresolved, out.String())
	}
	if !strings.Contains(out.String(), "ERROR: could not rename it") {
		t.Errorf("the collision was not named:\n%s", out.String())
	}
	for _, name := range []string{"zope.interface", "zope-interface"} {
		if _, err := os.Stat(filepath.Join(dir, manifest.TypePypi, name, "manifest.json")); err != nil {
			t.Errorf("the refusal moved %s anyway: %v", name, err)
		}
	}
}

// writeRawManifest writes a manifest straight to its literal path, which is
// what an install predating canonicalization holds.
func writeRawManifest(t *testing.T, dir, name, version string) {
	t.Helper()
	pm := manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          name,
		Type:          manifest.TypePypi,
		Versions:      []manifest.VersionEntry{{Version: version, Mode: manifest.ModeProxy, URL: "https://pypi.org"}},
	}
	blob, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	path := filepath.Join(dir, manifest.TypePypi, name, "manifest.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, append(blob, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
