package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// Ubuntu and Debian advisories are keyed on the source package alone, so an
// apt entry with none makes the OSV gate warn rather than answer: an empty
// result under a binary name cannot be read as clean. The form had no field
// for it, and the gate's own warn is what tells the operator to set it.
func TestAptCreateFormCarriesSourcePackageAndCaptureSuite(t *testing.T) {
	var labels []string
	for _, f := range rebuildCreateFields(manifest.TypeApt, nil) {
		labels = append(labels, f.Label)
	}
	joined := strings.Join(labels, ",")
	for _, want := range []string{"Source Package", "Capture Suite"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the apt form has no %q field: %s", want, joined)
		}
	}
}

// The release goes on CaptureSuite. Suites decides which dists/<suite>/ the
// entry publishes to, so a release written there takes the entry out of every
// generated index on a server whose apt_codename is a house name.
func TestAptFormWritesTheReleaseToCaptureSuiteNotSuites(t *testing.T) {
	fields := rebuildCreateFields(manifest.TypeApt, nil)
	setFieldValue(fields, "Apt Mode", "Package Name")
	setFieldValue(fields, "Package Name", "nginx-common")
	setFieldValue(fields, "Name", "nginx-common")
	setFieldValue(fields, "Version", "1.24.0-2ubuntu7")
	setFieldValue(fields, "Source Package", "nginx")
	setFieldValue(fields, "Capture Suite", "noble")

	ve := saveAndReadBack(t, fields, manifest.TypeApt, "nginx-common")
	if ve.SourcePackage != "nginx" {
		t.Errorf("SourcePackage = %q, want nginx; the OSV gate has nothing to key on", ve.SourcePackage)
	}
	if ve.CaptureSuite != "noble" {
		t.Errorf("CaptureSuite = %q, want noble", ve.CaptureSuite)
	}
	if len(ve.Suites) != 0 {
		t.Errorf("Suites = %v; the release belongs on CaptureSuite, and writing it here drops the entry out of every generated index", ve.Suites)
	}
}

// makeJSONApplyFn populates the form from a pasted manifest and dropped both
// fields, so the one route to them short of editing the manifest as JSON was
// also blind to them.
func TestJSONApplyPopulatesTheAptProvenanceFields(t *testing.T) {
	m := &appModel{}
	m.popup.formFields = rebuildCreateFields(manifest.TypeApt, nil)
	setFieldValue(m.popup.formFields, "Type", manifest.TypeApt)

	apply := m.makeJSONApplyFn()
	if msg := apply(`{"type":"apt","name":"nginx-common",
	  "versions":[{"version":"1.24.0-2ubuntu7","source_name":"nginx-common",
	               "source_package":"nginx","capture_suite":"noble"}]}`); msg != "" {
		t.Fatalf("apply: %s", msg)
	}

	for _, tc := range []struct{ label, want string }{
		{"Source Package", "nginx"},
		{"Capture Suite", "noble"},
		{"Package Name", "nginx-common"},
	} {
		if got := fieldValueFromSlice(m.popup.formFields, tc.label); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.label, got, tc.want)
		}
	}
}

// saveAndReadBack drives saveCreateEntry and reads the entry back off the
// store, so the assertion covers what actually lands rather than an
// intermediate the save path could still drop.
func saveAndReadBack(t *testing.T, fields []formField, typ, name string) manifest.VersionEntry {
	t.Helper()
	ctx := context.Background()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.LoadIndex(ctx); err != nil {
		t.Fatalf("load index: %v", err)
	}
	if err := saveCreateEntry(store, fields); err != nil {
		t.Fatalf("saveCreateEntry: %v", err)
	}
	pm, err := store.GetPackage(ctx, typ, name)
	if err != nil || pm == nil {
		t.Fatalf("read back %s/%s: %v", typ, name, err)
	}
	if len(pm.Versions) != 1 {
		t.Fatalf("want one version, got %d", len(pm.Versions))
	}
	return pm.Versions[0]
}
