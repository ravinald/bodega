package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

type fakeOSVStore struct {
	policies map[string]audit.OSVPolicy
}

func (f *fakeOSVStore) GetOSVPolicy(_ context.Context, ecosystem string) (audit.OSVPolicy, error) {
	p, ok := f.policies[ecosystem]
	if !ok {
		return audit.OSVPolicy{}, audit.ErrOSVPolicyNotFound
	}
	return p, nil
}

// stubOSV serves /v1/query responses. vulnIDs is the list of records to
// return; empty means "no vulns."
func stubOSV(t *testing.T, vulnIDs ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Package struct {
				Name, Ecosystem string
			} `json:"package"`
			Version string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("request decode: %v", err)
		}
		var vulns []map[string]any
		for _, id := range vulnIDs {
			vulns = append(vulns, map[string]any{"id": id})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": vulns})
	}))
}

func TestOSVPolicy_NoPolicy(t *testing.T) {
	ck := NewOSVChecker(&fakeOSVStore{})
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "anything", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.0.0"})
	if r.Action != ActionPass {
		t.Errorf("no policy = pass, got %+v", r)
	}
}

func TestOSVPolicy_UnsupportedEcosystem(t *testing.T) {
	// apt has no OSV mapping; short-circuit even with a policy row.
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeApt: {Ecosystem: manifest.TypeApt, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "bash", Type: manifest.TypeApt},
		&manifest.VersionEntry{Version: "5.2"})
	if r.Action != ActionPass {
		t.Errorf("apt not in osvEcosystemFor; expected pass, got %+v", r)
	}
}

func TestOSVPolicy_NoVulnsPass(t *testing.T) {
	srv := stubOSV(t) // empty
	defer srv.Close()
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.Endpoint = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "pkg", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.0.0"})
	if r.Action != ActionPass {
		t.Errorf("clean package = pass, got %+v", r)
	}
}

func TestOSVPolicy_BlockOnVulns(t *testing.T) {
	srv := stubOSV(t, "CVE-2024-XXXX", "GHSA-abcd-efgh-ijkl")
	defer srv.Close()
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.Endpoint = srv.URL

	ve := &manifest.VersionEntry{Version: "4.17.4"}
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "lodash", Type: manifest.TypeNpm},
		ve)
	if r.Action != ActionBlock {
		t.Fatalf("vulns + block action → block; got %+v", r)
	}
	if ve.Metadata["vetting.osv.vulns"] == "" {
		t.Error("vuln IDs should be stamped onto VersionEntry.Metadata")
	}
}

func TestOSVPolicy_WarnDoesNotBlock(t *testing.T) {
	srv := stubOSV(t, "CVE-2025-YYYY")
	defer srv.Close()
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionWarn},
	}}
	ck := NewOSVChecker(store)
	ck.Endpoint = srv.URL

	ve := &manifest.VersionEntry{Version: "1.0.0"}
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "pkg", Type: manifest.TypeNpm},
		ve)
	if r.Action != ActionWarn {
		t.Errorf("warn action returns warn, got %+v", r)
	}
	if ve.Metadata["vetting.osv.vulns"] == "" {
		t.Error("warn should still stamp vuln IDs")
	}
}
