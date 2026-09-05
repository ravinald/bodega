package server

import (
	"net/http"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// immutableHeader is what a served artifact carries and what a refusal must
// not: a year, past which no caching proxy will re-ask.
const immutableHeader = "public, max-age=31536000, immutable"

// TestCacheControlFollowsTheOutcomePerHandler is issue #199, the sibling of
// #171. Five handlers set Cache-Control before they knew the outcome, and
// http.Error does not clear the header map — so a 404 for a wheel or an npm
// tarball shipped a year-long "immutable" that no operator can reach into a
// corporate caching proxy to correct.
//
// One case per handler, each pair on one server so the refusal and the 200
// travel the same wiring.
func TestCacheControlFollowsTheOutcomePerHandler(t *testing.T) {
	seed := func(t *testing.T, s *Server, typ, key string) {
		t.Helper()
		if err := s.typeStore(typ).Put(t.Context(), key, []byte("artifact")); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}

	t.Run("pypi wheel", func(t *testing.T) {
		s := newDiscoveryServer(t)
		wantOutcome(t, s, "/pypi/wheels/absent-1.0.0-py3-none-any.whl", http.StatusNotFound, "")

		seed(t, s, manifest.TypePypi, manifest.PypiWheelPrefix+"present-1.0.0-py3-none-any.whl")
		wantOutcome(t, s, "/pypi/wheels/present-1.0.0-py3-none-any.whl", http.StatusOK, immutableHeader)
	})

	t.Run("helm chart", func(t *testing.T) {
		s := newDiscoveryServer(t)
		wantOutcome(t, s, "/helm/charts/absent-1.0.0.tgz", http.StatusNotFound, "")

		seed(t, s, manifest.TypeHelm, manifest.HelmChartKey("present", "1.0.0"))
		wantOutcome(t, s, "/helm/charts/present-1.0.0.tgz", http.StatusOK, immutableHeader)
	})

	t.Run("npm tarball", func(t *testing.T) {
		s := newDiscoveryServer(t)
		wantOutcome(t, s, "/npm/absent/-/absent-1.0.0.tgz", http.StatusNotFound, "")

		seed(t, s, manifest.TypeNpm, manifest.NpmTarballKey("present", "1.0.0"))
		wantOutcome(t, s, "/npm/present/-/present-1.0.0.tgz", http.StatusOK, immutableHeader)
	})

	t.Run("git bundle", func(t *testing.T) {
		s := newDiscoveryServer(t)
		wantOutcome(t, s, "/git/absent/absent-v1.0.0.bundle", http.StatusNotFound, "")

		seed(t, s, manifest.TypeGit, manifest.GitKey("present", "v1.0.0", false))
		wantOutcome(t, s, "/git/present/present-v1.0.0.bundle", http.StatusOK, immutableHeader)
	})

	// cargo qualifies for neither answer: the download path's last segment is
	// "download", which isImmutableArtifact does not match. The case is here so
	// that adding ".crate" to that list is a change someone makes on purpose,
	// with a test naming what it turns on.
	t.Run("cargo download", func(t *testing.T) {
		s := newDiscoveryServer(t)
		wantOutcome(t, s, "/cargo/absent/1.0.0/download", http.StatusBadGateway, "")

		if err := s.store.AddVersion(t.Context(), manifest.TypeCargo, "present",
			manifest.VersionEntry{Version: "1.0.0"}); err != nil {
			t.Fatalf("AddVersion: %v", err)
		}
		seed(t, s, manifest.TypeCargo, manifest.CargoCrateKey("present", "1.0.0"))
		wantOutcome(t, s, "/cargo/present/1.0.0/download", http.StatusOK, "")
	})
}

// wantOutcome asserts the status first and the Cache-Control it shipped with
// second, which is the order the defect appears in: a plausible status
// carrying a header that outlives it.
func wantOutcome(t *testing.T, s *Server, path string, wantCode int, wantCacheControl string) {
	t.Helper()
	code, hdr := mirrorGetHeader(t, s, path)
	if code != wantCode {
		t.Fatalf("GET %s = %d, want %d", path, code, wantCode)
	}
	if got := hdr.Get("Cache-Control"); got != wantCacheControl {
		t.Errorf("GET %s (%d) Cache-Control = %q, want %q", path, code, got, wantCacheControl)
	}
}
