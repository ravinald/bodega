package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// placeholderFixture seeds one apt package carrying the pair a second 'pkg
// create apt' leaves behind: the version-less entry the CLI stages, and the
// resolved entry the upstream lookup produced beside it.
func placeholderFixture(t *testing.T) *manifest.Store {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	for _, ve := range []manifest.VersionEntry{
		{SourceName: "hello"},
		{Version: "1.0.0", SourceName: "hello", Metadata: map[string]string{"Architecture": "amd64"}},
	} {
		if err := store.AddVersion(ctx, manifest.TypeApt, "hello", ve); err != nil {
			t.Fatalf("AddVersion: %v", err)
		}
	}
	if err := store.AddVersion(ctx, manifest.TypeApt, "staged", manifest.VersionEntry{SourceName: "staged"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return store
}

func versionCount(t *testing.T, store *manifest.Store, name string) int {
	t.Helper()
	pm, err := store.GetPackage(t.Context(), manifest.TypeApt, name)
	if err != nil || pm == nil {
		t.Fatalf("GetPackage %s: %v", name, err)
	}
	return len(pm.Versions)
}

// TestRepairDropsAptPlaceholders is the repair half of the fix. Filling the
// entry in place helps packages created from here on; a manifest already
// carrying the pair has no other way out, because every verb that could
// remove the leftover addresses a version by name.
func TestRepairDropsAptPlaceholders(t *testing.T) {
	store := placeholderFixture(t)
	var out bytes.Buffer

	if issues := repairAptPlaceholders(t.Context(), store, false, &out); issues != 2 {
		t.Errorf("issues = %d, want 2 (one placeholder beside a resolved entry, one package with only placeholders)", issues)
	}
	if n := versionCount(t, store, "hello"); n != 1 {
		t.Errorf("apt/hello kept %d versions, want 1", n)
	}
	if n := versionCount(t, store, "staged"); n != 1 {
		t.Errorf("apt/staged lost its only entry; a package with nothing resolved is a staging record, not a leftover")
	}
	if !strings.Contains(out.String(), "UNRESOLVED: apt/staged") {
		t.Errorf("repair did not report the package it deliberately left alone:\n%s", out.String())
	}
}

// TestRepairCheckChangesNothing is the contract of the check form: it reports
// and writes nothing, so an operator can see the damage before authorizing it.
func TestRepairCheckChangesNothing(t *testing.T) {
	store := placeholderFixture(t)
	var out bytes.Buffer

	if issues := repairAptPlaceholders(t.Context(), store, true, &out); issues != 2 {
		t.Errorf("issues = %d, want 2", issues)
	}
	if n := versionCount(t, store, "hello"); n != 2 {
		t.Errorf("check mode dropped an entry: apt/hello has %d versions, want 2", n)
	}
	if !strings.Contains(out.String(), "PLACEHOLDER: apt/hello") {
		t.Errorf("check mode did not name the placeholder:\n%s", out.String())
	}
}

// TestValidateManifestRefusesAVersionlessAptEntry guards the import and edit
// paths against writing back what repair exists to clean up.
func TestValidateManifestRefusesAVersionlessAptEntry(t *testing.T) {
	cfg := &config.Config{}
	var warnings bytes.Buffer
	pm := &manifest.PackageManifest{
		Name:     "hello",
		Type:     manifest.TypeApt,
		Versions: []manifest.VersionEntry{{SourceName: "hello"}},
	}
	if err := validateManifest(pm, cfg, &warnings); err == nil {
		t.Fatal("validateManifest accepted an apt entry with no version")
	}

	pm.Versions[0].Version = "*"
	if err := validateManifest(pm, cfg, &warnings); err != nil {
		t.Errorf(`validateManifest rejected version "*", which resolves on the next build: %v`, err)
	}
}
