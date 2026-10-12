package admit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance"
)

// npmWithProvenance serves sigstore@3.0.0 with the bundle npm recorded for it
// and left-pad@1.3.0 with none, and points the provenance check at that stub
// and at the recorded Sigstore trusted root.
func npmWithProvenance(t *testing.T) string {
	t.Helper()
	td := filepath.Join("..", "provenance", "testdata")
	bundles, err := os.ReadFile(filepath.Join(td, "npm-sigstore-3.0.0.attestations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dist := map[string]any{"integrity": "sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA=="}
		switch r.URL.Path {
		case "/sigstore":
			dist["attestations"] = map[string]any{"url": srv.URL + "/att/sigstore@3.0.0",
				"provenance": map[string]any{"predicateType": provenance.SLSAProvenanceV1}}
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": map[string]any{"3.0.0": map[string]any{"dist": dist}}})
		case "/left-pad":
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": map[string]any{"1.3.0": map[string]any{"dist": dist}}})
		case "/att/sigstore@3.0.0":
			_, _ = w.Write(bundles)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	tr, err := provenance.LoadTrustedRootFile(filepath.Join(td, "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	prev := NewProvenanceVerifier
	NewProvenanceVerifier = func(cfg *config.Config) *provenance.Verifier {
		v := prev(cfg)
		v.Root = func(context.Context) (root.TrustedMaterial, error) { return tr, nil }
		return v
	}
	t.Cleanup(func() { NewProvenanceVerifier = prev })
	return srv.URL
}

// An import records the outcome and the identity verified in the row's
// upstream_provenance check, pins the package, and refuses a version with no
// provenance once the action is block.
func TestAdmitRecordsUpstreamProvenance(t *testing.T) {
	f := newAdmissionFixture(t)
	registry := npmWithProvenance(t)
	entry := func(name, version string) *manifest.PackageManifest {
		return &manifest.PackageManifest{Type: manifest.TypeNpm, Name: name,
			Versions: []manifest.VersionEntry{{Version: version, URL: registry}}}
	}

	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, entry("sigstore", "3.0.0"), "ravi")
	if res.Decision != Admitted {
		t.Fatalf("Decision = %v (%s)", res.Decision, res.Reason)
	}
	c := checkOf(t, f.rows(t, "sigstore")[0], audit.CheckUpstreamProvenance)
	if c.Status != audit.CheckPass || c.Action != policy.ActionWarn || c.Provenance == nil ||
		c.Provenance.Outcome != audit.ProvenanceVerified || c.Provenance.SourceRepositoryURI != "https://github.com/sigstore/sigstore-js" {
		t.Fatalf("upstream_provenance = %+v (%+v)", c, c.Provenance)
	}
	if pin, err := f.adb.GetProvenancePin(t.Context(), manifest.TypeNpm, "sigstore"); err != nil || pin.PinnedVersion != "3.0.0" {
		t.Errorf("pin = %+v, %v", pin, err)
	}

	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, entry("left-pad", "1.3.0"), "ravi")
	if res.Decision != Admitted || len(res.Warnings) != 0 {
		t.Fatalf("no provenance under warn: %v %v", res.Decision, res.Warnings)
	}
	if c := checkOf(t, f.rows(t, "left-pad")[0], audit.CheckUpstreamProvenance); c.Provenance.Outcome != audit.ProvenanceUnavailable || c.Status != audit.CheckPass {
		t.Errorf("left-pad under warn = %+v", c)
	}

	if err := f.adb.SetProvenancePolicy(t.Context(), audit.ProvenancePolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, entry("left-pad", "1.3.0"), "ravi")
	if res.Decision != PolicyBlocked || res.Check != audit.CheckUpstreamProvenance {
		t.Fatalf("no provenance under block: %v %q (%s)", res.Decision, res.Check, res.Reason)
	}
	if c := checkOf(t, f.rows(t, "left-pad")[0], audit.CheckUpstreamProvenance); c.Status != audit.CheckBlock || c.Action != policy.ActionBlock {
		t.Errorf("left-pad under block = %+v", c)
	}
}

// The builder's fetch and the proxy's fill admit through Fetch, which runs the
// same check and records it the same way.
func TestFetchRecordsUpstreamProvenance(t *testing.T) {
	f := newAdmissionFixture(t)
	registry := npmWithProvenance(t)
	cfg := *f.synced
	cfg.NpmUpstream = registry
	res := Fetch(t.Context(), f.adb, VersionCheckers(&cfg, f.adb), manifest.TypeNpm, "sigstore",
		manifest.VersionEntry{Version: "3.0.0", Mode: manifest.ModeProxy}, AllowListCheck(false, "sigstore", nil), Who{Identity: "host-a"}, "")
	if res.Block != nil {
		t.Fatalf("blocked: %+v", res.Block)
	}
	c := checkOf(t, res.Admission, audit.CheckUpstreamProvenance)
	if c.Provenance == nil || c.Provenance.Outcome != audit.ProvenanceVerified {
		t.Errorf("a proxy fill with no url read the configured npm upstream and got %+v", c)
	}

	res = Fetch(t.Context(), f.adb, nil, manifest.TypeNpm, "sigstore",
		manifest.VersionEntry{Version: "3.0.0"}, AllowListCheck(false, "sigstore", nil), Who{}, "not run: no version")
	if c := checkOf(t, res.Admission, audit.CheckUpstreamProvenance); c.Status != audit.CheckNotEvaluated {
		t.Errorf("a fill with no checkers recorded %+v", c)
	}
}

// A version another check refuses does not become the trust-on-first-use
// pin, through import or through a fetch, and neither does a version whose
// sibling in the same manifest is refused: nothing of a refused manifest is
// stored. The first version actually admitted takes the pin.
func TestRefusedVersionTakesNoProvenancePin(t *testing.T) {
	f := newAdmissionFixture(t)
	registry := npmWithProvenance(t)
	dir := t.TempDir()
	db := policy.NewOSVDatabase(dir)
	db.ExportBase = osvExport(t, map[string]any{
		"id": "GHSA-test-0002",
		"affected": []map[string]any{{
			"package":  map[string]string{"name": "sigstore", "ecosystem": "npm"},
			"versions": []string{"3.0.0", "2.0.0"},
		}},
	}).URL
	if _, err := db.Sync(t.Context(), "npm"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{StoragePath: t.TempDir(), OSVDBDir: dir, NpmUpstream: registry}
	noPin := func(when string) {
		t.Helper()
		if pin, err := f.adb.GetProvenancePin(t.Context(), manifest.TypeNpm, "sigstore"); !errors.Is(err, audit.ErrProvenancePinNotFound) {
			t.Fatalf("%s: pin = %+v, %v; want none", when, pin, err)
		}
	}

	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, cfg, &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore",
		Versions: []manifest.VersionEntry{{Version: "3.0.0", URL: registry}}}, "ravi")
	if res.Decision != PolicyBlocked || res.Check != audit.CheckOSV {
		t.Fatalf("Decision = %v %q (%s)", res.Decision, res.Check, res.Reason)
	}
	c := checkOf(t, f.rows(t, "sigstore")[0], audit.CheckUpstreamProvenance)
	if c.Provenance == nil || c.Provenance.Outcome != audit.ProvenanceVerified || !strings.Contains(c.Detail, "pinned once admitted") {
		t.Errorf("a refused version's row = %+v", c)
	}
	noPin("after an import OSV refused")

	fr := Fetch(t.Context(), f.adb, VersionCheckers(cfg, f.adb), manifest.TypeNpm, "sigstore",
		manifest.VersionEntry{Version: "3.0.0", Mode: manifest.ModeProxy}, AllowListCheck(false, "sigstore", nil), Who{Identity: "host-a"}, "")
	if fr.Block == nil || fr.Block.Check != audit.CheckOSV {
		t.Fatalf("fetch block = %+v", fr.Block)
	}
	noPin("after a fetch OSV refused")

	// 3.0.0 passes its own checks; its sibling 2.0.0 is refused, so the
	// manifest is refused whole.
	db.ExportBase = osvExport(t, map[string]any{
		"id": "GHSA-test-0003",
		"affected": []map[string]any{{
			"package":  map[string]string{"name": "sigstore", "ecosystem": "npm"},
			"versions": []string{"2.0.0"},
		}},
	}).URL
	if _, err := db.Sync(t.Context(), "npm"); err != nil {
		t.Fatal(err)
	}
	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, cfg, &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore",
		Versions: []manifest.VersionEntry{{Version: "3.0.0", URL: registry}, {Version: "2.0.0", URL: registry}}}, "ravi")
	if res.Decision != PolicyBlocked || res.Version != "2.0.0" {
		t.Fatalf("Decision = %v at %q (%s)", res.Decision, res.Version, res.Reason)
	}
	noPin("after a sibling was refused")

	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, cfg, &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore",
		Versions: []manifest.VersionEntry{{Version: "3.0.0", URL: registry}}}, "ravi")
	if res.Decision != Admitted {
		t.Fatalf("Decision = %v (%s)", res.Decision, res.Reason)
	}
	pin, err := f.adb.GetProvenancePin(t.Context(), manifest.TypeNpm, "sigstore")
	if err != nil || pin.PinnedVersion != "3.0.0" || pin.SourceRepositoryURI != "https://github.com/sigstore/sigstore-js" {
		t.Fatalf("pin after an admitted version = %+v, %v", pin, err)
	}
}
