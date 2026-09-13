package builder

import (
	"testing"

	"github.com/ravinald/bodega/internal/hostpkg"
)

// `pkg create apt` builds its entry from apt-cache on the bodega host, which
// resolved the version against that host's own sources, so the release is
// known at the moment the entry is written. Recording nothing left the entry
// unanswerable: F14 bounded the apt_codename fallback, so on a bodega serving
// two releases a suite-less entry now warns rather than being answered from a
// codename that may be the other release.
func TestAptShowEntryRecordsTheReleaseItResolved(t *testing.T) {
	const stanza = "Package: nginx-common\nVersion: 1.24.0-2ubuntu7\nSource: nginx\nArchitecture: all\n"

	t.Run("a resolved release is recorded", func(t *testing.T) {
		ve := parseAptShowOutput(stanza, "nginx-common", "noble")
		if ve == nil {
			t.Fatal("parseAptShowOutput returned nil")
		}
		if ve.CaptureSuite != "noble" {
			t.Errorf("CaptureSuite = %q, want noble", ve.CaptureSuite)
		}
		if len(ve.Suites) != 0 {
			t.Errorf("Suites = %v; a release written there drops the entry out of every generated index", ve.Suites)
		}
		if ve.SourcePackage != "nginx" {
			t.Errorf("SourcePackage = %q, want nginx", ve.SourcePackage)
		}
	})

	// Off Linux, and on a distro publishing no codename, nothing resolves. An
	// entry naming the wrong release is answered from the wrong advisory
	// export, in the direction that reports a vulnerable host clean, so empty
	// is the correct record.
	t.Run("no resolved release records none", func(t *testing.T) {
		ve := parseAptShowOutput(stanza, "nginx-common", "")
		if ve.CaptureSuite != "" {
			t.Errorf("CaptureSuite = %q where nothing resolved", ve.CaptureSuite)
		}
	})
}

// FetchAptMetadata is what wires the resolution to the parse. The parse is
// covered above with an injected value, so this is the join: it must ask the
// host rather than leaving the field to whatever a caller happened to pass.
func TestFetchAptMetadataAsksTheHostForItsRelease(t *testing.T) {
	if hostpkg.LocalAptSuite() == "" {
		t.Skip("this host names no release, so there is nothing to carry through")
	}
	ve := FetchAptMetadata("bash")
	if ve == nil {
		t.Skip("no apt-cache on this host")
	}
	if ve.CaptureSuite != hostpkg.LocalAptSuite() {
		t.Errorf("CaptureSuite = %q, want this host's release %q", ve.CaptureSuite, hostpkg.LocalAptSuite())
	}
}
