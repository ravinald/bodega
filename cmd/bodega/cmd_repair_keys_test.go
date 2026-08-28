package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

const repairModule = "github.com/aws/aws-sdk-go-v2"

// repairFixture seeds one gomod entry's four objects at the superseded key —
// the filesystem-safe module name the builder used to derive — and returns a
// repairer over the one backend that holds them.
//
// Source and destination are the same store on purpose: 'repair keys' moves an
// object between two keys, never between two backends, and nothing in the
// manifest changes.
func repairFixture(t *testing.T, del, dry bool) (*keyRepairer, *storage.Memory, *bytes.Buffer) {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeGomod, repairModule, manifest.VersionEntry{
		Version: "v1.30.0",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	objects := storage.NewMemory()
	safe := manifest.SafeName(repairModule)
	for _, ext := range []string{".zip", ".info", ".mod"} {
		objects.Seed(manifest.GomodKey(safe, "v1.30.0", ext), "bytes"+ext)
	}
	objects.Seed(manifest.GomodListKey(safe), "v1.30.0\n")

	out := &bytes.Buffer{}
	return &keyRepairer{
		stores: storage.NewSingle(objects),
		store:  store,
		spool:  t.TempDir(),
		out:    out,
		del:    del,
		dry:    dry,
	}, objects, out
}

// canonicalRepairKeys is what handleGomod asks for: the wire form, slashes
// intact.
func canonicalRepairKeys() map[string]string {
	keys := map[string]string{
		manifest.GomodListKey(repairModule): "v1.30.0\n",
	}
	for _, ext := range []string{".zip", ".info", ".mod"} {
		keys[manifest.GomodKey(repairModule, "v1.30.0", ext)] = "bytes" + ext
	}
	return keys
}

// TestRepairKeysCopiesToTheCanonicalKeyAndKeepsTheSource is the ordering
// guarantee 'pkg move' establishes, on the command that reuses it: copy,
// verify at the destination, and only then consider the source. Both keys
// answer a missing object with "not found", so a source removed before the
// copy landed would be indistinguishable from one that was never uploaded.
func TestRepairKeysCopiesToTheCanonicalKeyAndKeepsTheSource(t *testing.T) {
	r, objects, out := repairFixture(t, false, false)
	if err := r.run(t.Context(), []string{manifest.TypeGomod}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if r.copied != 4 {
		t.Fatalf("copied %d objects, want 4", r.copied)
	}
	for key, want := range canonicalRepairKeys() {
		got, err := objects.Get(t.Context(), key)
		if err != nil || string(got) != want {
			t.Errorf("canonical key %q holds %q, %v; want %q", key, got, err, want)
		}
	}
	safe := manifest.SafeName(repairModule)
	if got, _ := objects.Get(t.Context(), manifest.GomodKey(safe, "v1.30.0", ".zip")); got == nil {
		t.Error("the superseded copy was deleted without --delete-source")
	}
	if !strings.Contains(out.String(), "still there") {
		t.Errorf("the operator was not told the old copies survive:\n%s", out)
	}
}

// TestRepairKeysIsRerunnable: an interrupted run is re-run, and the second
// pass must report the objects as already canonical rather than copying them
// again or failing on a key that exists.
func TestRepairKeysIsRerunnable(t *testing.T) {
	r, objects, _ := repairFixture(t, false, false)
	if err := r.run(t.Context(), []string{manifest.TypeGomod}); err != nil {
		t.Fatalf("first run: %v", err)
	}

	again := &keyRepairer{stores: storage.NewSingle(objects), store: r.store, spool: r.spool, out: &bytes.Buffer{}}
	if err := again.run(t.Context(), []string{manifest.TypeGomod}); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if again.copied != 0 {
		t.Errorf("re-run copied %d objects, want 0", again.copied)
	}
	if again.present != 4 {
		t.Errorf("re-run found %d objects already canonical, want 4", again.present)
	}
}

// TestRepairKeysDryRunWritesNothing. --dry-run is what an operator runs first
// on a production install, so it counting the work while writing none of it is
// the whole contract.
func TestRepairKeysDryRunWritesNothing(t *testing.T) {
	r, objects, out := repairFixture(t, true, true)
	before := len(objects.Keys())
	if err := r.run(t.Context(), []string{manifest.TypeGomod}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if r.copied != 4 {
		t.Errorf("--dry-run reported %d objects, want 4", r.copied)
	}
	if got := len(objects.Keys()); got != before {
		t.Fatalf("--dry-run changed the store: %d keys, was %d (%v)", got, before, objects.Keys())
	}
	if !strings.Contains(out.String(), "Re-run without --dry-run") {
		t.Errorf("--dry-run did not say what to do next:\n%s", out)
	}
}

// TestRepairKeysDeleteSourceRunsLast: --delete-source removes the superseded
// key, and only after the canonical one has been verified holding the bytes.
func TestRepairKeysDeleteSourceRunsLast(t *testing.T) {
	r, objects, _ := repairFixture(t, true, false)
	if err := r.run(t.Context(), []string{manifest.TypeGomod}); err != nil {
		t.Fatalf("run: %v", err)
	}

	for key, want := range canonicalRepairKeys() {
		got, err := objects.Get(t.Context(), key)
		if err != nil || string(got) != want {
			t.Errorf("canonical key %q holds %q, %v; want %q", key, got, err, want)
		}
	}
	safe := manifest.SafeName(repairModule)
	for _, key := range []string{
		manifest.GomodKey(safe, "v1.30.0", ".zip"),
		manifest.GomodKey(safe, "v1.30.0", ".info"),
		manifest.GomodKey(safe, "v1.30.0", ".mod"),
		manifest.GomodListKey(safe),
	} {
		if got, _ := objects.Get(t.Context(), key); got != nil {
			t.Errorf("superseded key %q survived --delete-source", key)
		}
	}
}

// TestSupersededKeysOnlyCoversGomod. Every other type already agreed on its
// key, so returning pairs for one of them would copy an artifact onto a key no
// handler reads and then, with --delete-source, delete the one that works.
func TestSupersededKeysOnlyCoversGomod(t *testing.T) {
	ve := manifest.VersionEntry{Version: "1.0.0"}
	for _, typ := range manifest.AllTypes {
		pm := &manifest.PackageManifest{Type: typ, Name: "example.com/thing"}
		got := supersededKeys(pm, ve)
		if typ == manifest.TypeGomod {
			if len(got) != 4 {
				t.Errorf("gomod yielded %d pairs, want 4: %v", len(got), got)
			}
			continue
		}
		if got != nil {
			t.Errorf("%s yielded repair pairs %v, want none", typ, got)
		}
	}

	// A module path with no slash encodes to itself, so there is nothing to
	// repair and a re-run stays cheap.
	flat := &manifest.PackageManifest{Type: manifest.TypeGomod, Name: "gopkg.in"}
	if got := supersededKeys(flat, ve); got != nil {
		t.Errorf("a module path with no slash yielded %v, want none", got)
	}
}
