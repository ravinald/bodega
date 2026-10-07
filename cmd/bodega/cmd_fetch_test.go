package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// With no type named, the backfill covers the types a publish time exists for
// and passes over the rest. A type the operator named that has none is refused,
// since passing over it would report a clean run over something never read.
func TestPublishedTypes(t *testing.T) {
	got, err := publishedTypes(manifest.AllTypes, false)
	if err != nil {
		t.Fatalf("all types: %v", err)
	}
	want := []string{manifest.TypeCargo, manifest.TypeGomod, manifest.TypeNpm, manifest.TypePypi}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("publishedTypes(all) = %v, want %v", got, want)
	}

	if _, err := publishedTypes([]string{manifest.TypeApt}, true); err == nil || !strings.Contains(err.Error(), "apt has no upstream publish time") {
		t.Errorf("a named apt was not refused by name: %v", err)
	}
}
