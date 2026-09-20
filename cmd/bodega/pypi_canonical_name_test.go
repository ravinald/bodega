package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// B75 R3: `pkg convert pypi` is a write path, and its output is what an
// operator pipes into `pkg import`. `pip list --format=json` reports a
// distribution under its published capitalization, so a catalog built the
// documented way held entries no client could reach. Canonicalizing at the
// import instead would leave the printed name disagreeing with the stored one.
func TestConvertPypiWritesCanonicalNames(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "pip-list.json")
	out := filepath.Join(dir, "catalog.json")
	body := `[{"name":"zope.interface","version":"7.2"},
	          {"name":"Django","version":"6.1.1"},
	          {"name":"django_cors_headers","version":"4.9.0"}]`
	if err := os.WriteFile(in, []byte(body), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	cmd := newConvertCmd(&globalFlags{})
	cmd.SetArgs([]string{"pypi", in, "-o", out, "--origin", "host01"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pkg convert pypi: %v\n%s", err, buf.String())
	}

	var pms []manifest.PackageManifest
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(blob, &pms); err != nil {
		t.Fatalf("parse output: %v\n%s", err, blob)
	}
	got := map[string]string{}
	for _, pm := range pms {
		if len(pm.Versions) != 1 {
			t.Fatalf("%s carries %d versions, want 1", pm.Name, len(pm.Versions))
		}
		got[pm.Name] = pm.Versions[0].Version
	}
	want := map[string]string{"zope-interface": "7.2", "django": "6.1.1", "django-cors-headers": "4.9.0"}
	for name, version := range want {
		if got[name] != version {
			t.Errorf("converted catalog holds %v, want %s@%s", got, name, version)
		}
	}
}

// An inventory naming one distribution twice folds into one manifest carrying
// both versions. Two manifests under one name reach `pkg import` as two writes,
// the second overwriting the first, and the loser's versions vanish silently.
func TestConvertPypiFoldsTwoSpellingsOfOneDistribution(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "pip-list.json")
	out := filepath.Join(dir, "catalog.json")
	body := `[{"name":"zope.interface","version":"7.2"},{"name":"zope_interface","version":"6.1"}]`
	if err := os.WriteFile(in, []byte(body), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	cmd := newConvertCmd(&globalFlags{})
	cmd.SetArgs([]string{"pypi", in, "-o", out, "--origin", "host01"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pkg convert pypi: %v", err)
	}

	var pms []manifest.PackageManifest
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(blob, &pms); err != nil {
		t.Fatalf("parse output: %v\n%s", err, blob)
	}
	if len(pms) != 1 || pms[0].Name != "zope-interface" {
		t.Fatalf("converted %d manifests %+v, want one named zope-interface", len(pms), pms)
	}
	if len(pms[0].Versions) != 2 {
		t.Errorf("versions = %+v, want both 7.2 and 6.1", pms[0].Versions)
	}
}

// B75 R3 and R4: `generate-manifests` emits JSON an operator imports, so the
// name it prints is the name that reaches the store. A row written before the
// wheel route canonicalized carries pip's spelling.
func TestGenerateManifestsWritesCanonicalPypiNames(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t,
		pypiRowFor("django_cors_headers", "4.9.0"),
		pypiRowFor("django-cors-headers", "4.10.0"),
		pypiRowFor("zope.interface", "7.2"),
	)

	path := filepath.Join(t.TempDir(), "catalog.json")
	out, errOut, err := runDiscoverSplit(t, "generate-manifests", "pypi", "-o", path)
	if err != nil {
		t.Fatalf("generate-manifests pypi: %v (out %q, err %q)", err, out, errOut)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated manifests: %v", err)
	}
	var pms []manifest.PackageManifest
	if err := json.Unmarshal(blob, &pms); err != nil {
		t.Fatalf("parse generated manifests: %v\n%s", err, blob)
	}

	byName := map[string]manifest.PackageManifest{}
	for _, pm := range pms {
		byName[pm.Name] = pm
	}
	if _, ok := byName["django_cors_headers"]; ok {
		t.Errorf("generated a manifest named django_cors_headers; the store writes that to django-cors-headers")
	}
	pm, ok := byName["django-cors-headers"]
	if !ok {
		t.Fatalf("generated %v, want a django-cors-headers manifest", byName)
	}
	if len(pm.Versions) != 2 {
		t.Errorf("versions = %+v, want the rows from both spellings", pm.Versions)
	}
	if _, ok := byName["zope-interface"]; !ok {
		t.Errorf("generated %v, want zope.interface canonicalized to zope-interface", byName)
	}
}

// pypiRowFor is the row handlePypiPackage writes when an uncataloged
// distribution's simple index is read, under one spelling and one version.
func pypiRowFor(name, version string) audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: manifest.TypePypi,
		Host:         "pypi.org",
		PatternHint:  name,
		PkgName:      name,
		PkgVersion:   version,
		Decision:     audit.DecisionNoManifest,
		UpstreamURL:  "https://pypi.org/simple/" + name + "/",
		LastClient:   "10.0.0.5",
	}
}
