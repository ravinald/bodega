package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// The create paths produce the entry this test describes. `pkg create apt` and
// the TUI form both recorded neither the source package nor the release, so
// the gate declined rather than answering: an empty advisory list under a
// binary name cannot be read as clean, and on a bodega serving two releases
// nothing on the entry says which release its version string came from.
//
// Both halves are asserted here because either one missing is enough to make
// the entry unanswerable, and fixing one of them alone is the shape this item
// is most likely to ship by accident.
func TestOSVApt_CreatedEntryIsAnswerable(t *testing.T) {
	ck := aptChecker(t)
	const version = "2.4.7-1ubuntu0.4"

	t.Run("both fields recorded: the gate answers on the source package", func(t *testing.T) {
		ve := manifest.VersionEntry{
			Version: version, SourcePackage: "expat", CaptureSuite: "jammy",
		}
		r := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}, &ve)
		if r.Action == ActionWarn {
			t.Fatalf("a fully recorded entry still warns: %s", r.Reason)
		}
		if got := ve.Metadata[OSVMetaQueried]; !strings.HasPrefix(got, "source package expat") {
			t.Errorf("queried %q, want the source package; advisories are keyed on it alone", got)
		}
	})

	// libexpat1 is built from expat and inherits its advisories. Without the
	// source package the gate can only ask about libexpat1, which no Ubuntu
	// advisory is filed under, so the same version that blocks above comes
	// back with nothing found. That empty answer is the reason the form now
	// has the field.
	t.Run("no source package: the advisory is missed entirely", func(t *testing.T) {
		vulnerable := "2.4.7-1ubuntu0.2"

		withSource := manifest.VersionEntry{
			Version: vulnerable, SourcePackage: "expat", CaptureSuite: "jammy",
		}
		got := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}, &withSource)
		if got.Action != ActionBlock {
			t.Fatalf("this fixture version is meant to be vulnerable through expat, got %q: %s", got.Action, got.Reason)
		}

		without := manifest.VersionEntry{Version: vulnerable, CaptureSuite: "jammy"}
		missed := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}, &without)
		if missed.Action == ActionBlock {
			t.Fatalf("the binary name matched an advisory; this test no longer demonstrates what the source package buys")
		}
		t.Logf("without source_package the same version answers %q: %s", missed.Action, missed.Reason)
	})

	t.Run("no release on a two-release server: declines rather than guessing", func(t *testing.T) {
		ck2 := aptChecker(t)
		ck2.ServedAptSuites = []string{"jammy", "noble"}
		ve := manifest.VersionEntry{Version: version, SourcePackage: "expat"}
		r := ck2.Check(context.Background(),
			&manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}, &ve)
		if r.Action != ActionWarn {
			t.Fatalf("an entry naming no release was answered from one of two: %s", r.Reason)
		}
	})
}
