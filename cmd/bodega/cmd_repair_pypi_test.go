package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// deadPypiURLFixture seeds what 'discover promote --as manifest' wrote while
// the wheel handler composed pypi.org/packages/<filename>, beside an entry
// pointing at an operator's own index.
func deadPypiURLFixture(t *testing.T) *manifest.Store {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	seed := map[string][]manifest.VersionEntry{
		"six": {
			{Version: "1.16.0", URL: "https://pypi.org/packages/six-1.16.0-py2.py3-none-any.whl", Mode: manifest.ModeProxy},
			{Version: "1.17.0", URL: "https://pypi.org/packages/six-1.17.0-py2.py3-none-any.whl", Mode: manifest.ModeProxy},
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

	if issues := repairPypiWheelURLs(t.Context(), store, false, &out); issues != 2 {
		t.Errorf("issues = %d, want 2 (both six entries; the corporate index is not this defect)", issues)
	}
	for _, version := range []string{"1.16.0", "1.17.0"} {
		if got := pypiEntryURL(t, store, "six", version); got != "https://pypi.org" {
			t.Errorf("pypi/six@%s URL = %q, want the registry root", version, got)
		}
	}
	if got := pypiEntryURL(t, store, "internal-tool", "2.0.0"); got != "https://pypi.corp.example" {
		t.Errorf("repair rewrote an operator's own index URL to %q", got)
	}
	if !strings.Contains(out.String(), "DEAD URL: pypi/six@1.16.0") {
		t.Errorf("repair did not name what it rewrote:\n%s", out.String())
	}
}

// TestRepairCheckLeavesPypiURLs is the contract of the check form: report the
// damage, write nothing, let the operator authorize the fix.
func TestRepairCheckLeavesPypiURLs(t *testing.T) {
	store := deadPypiURLFixture(t)
	var out bytes.Buffer

	if issues := repairPypiWheelURLs(t.Context(), store, true, &out); issues != 2 {
		t.Errorf("issues = %d, want 2", issues)
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
