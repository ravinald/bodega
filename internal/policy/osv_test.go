package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// git has no OSV mapping; short-circuit even with a policy row.
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeGit: {Ecosystem: manifest.TypeGit, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "netbox", Type: manifest.TypeGit},
		&manifest.VersionEntry{Version: "v4.5.7"})
	if r.Action != ActionPass {
		t.Errorf("git not in osvEcosystemFor; expected pass, got %+v", r)
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
	ck.AllowAPIFallback = true

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
	ck.AllowAPIFallback = true

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
	ck.AllowAPIFallback = true

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

// stubOSVRecords serves /v1/query with full records and records the ecosystem
// the checker put on the wire, which is what a live OSV query is matched on.
func stubOSVRecords(t *testing.T, gotEco *string, vulns ...map[string]any) *httptest.Server {
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
		*gotEco = body.Package.Ecosystem
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": vulns})
	}))
}

func TestOSVPolicy_CargoVulnerableVersion(t *testing.T) {
	// time 0.1.44 is the crate version RUSTSEC-2020-0071 covers. Before cargo
	// was in osvEcosystemFor this short-circuited to pass without a query.
	var gotEco string
	srv := stubOSVRecords(t, &gotEco, map[string]any{
		"id":      "RUSTSEC-2020-0071",
		"summary": "Potential segfault in the time crate",
		"severity": []map[string]string{
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"},
		},
	})
	defer srv.Close()

	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeCargo: {Ecosystem: manifest.TypeCargo, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.Endpoint = srv.URL
	ck.AllowAPIFallback = true

	ve := &manifest.VersionEntry{Version: "0.1.44"}
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "time", Type: manifest.TypeCargo}, ve)
	if r.Action != ActionBlock {
		t.Fatalf("vulnerable crate must not pass; got %+v", r)
	}
	if gotEco != "crates.io" {
		t.Errorf("cargo must query OSV as crates.io, got %q", gotEco)
	}
	if ve.Metadata["vetting.osv.vulns"] != "RUSTSEC-2020-0071" {
		t.Errorf("vuln IDs not stamped: %q", ve.Metadata["vetting.osv.vulns"])
	}
}

func TestOSVEcosystems_CoversCargo(t *testing.T) {
	want := []string{manifest.TypeApt, manifest.TypeCargo, manifest.TypeGomod, manifest.TypeNpm, manifest.TypePypi}
	got := OSVEcosystems()
	if len(got) != len(want) {
		t.Fatalf("OSVEcosystems() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OSVEcosystems() = %v, want %v", got, want)
		}
	}
}

func TestOSVPolicy_SeverityStampedPerRecord(t *testing.T) {
	var gotEco string
	srv := stubOSVRecords(t, &gotEco,
		map[string]any{
			"id": "GHSA-high",
			"severity": []map[string]string{
				{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
		},
		map[string]any{
			"id": "GHSA-low",
			"severity": []map[string]string{
				{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
				{"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"},
			},
		},
		map[string]any{"id": "GHSA-unscored"},
	)
	defer srv.Close()

	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionWarn},
	}}
	ck := NewOSVChecker(store)
	ck.Endpoint = srv.URL
	ck.AllowAPIFallback = true

	ve := &manifest.VersionEntry{Version: "1.0.0"}
	ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "pkg", Type: manifest.TypeNpm}, ve)

	raw := ve.Metadata["vetting.osv.severity"]
	if raw == "" {
		t.Fatal("severity should be stamped alongside vetting.osv.vulns")
	}
	var got map[string][]OSVSeverity
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("a later reader must parse the stamp without re-querying OSV: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 scored records, got %d: %s", len(got), raw)
	}
	if len(got["GHSA-high"]) != 1 || got["GHSA-high"][0].Score == "" {
		t.Errorf("GHSA-high severity lost: %s", raw)
	}
	if len(got["GHSA-low"]) != 2 {
		t.Errorf("GHSA-low should keep both scoring systems: %s", raw)
	}
	if _, ok := got["GHSA-unscored"]; ok {
		t.Errorf("a record OSV scored nothing for should be absent: %s", raw)
	}
	if ve.Metadata["vetting.osv.vulns"] != "GHSA-high,GHSA-low,GHSA-unscored" {
		t.Errorf("ids must still list every record: %q", ve.Metadata["vetting.osv.vulns"])
	}
}

// TestOSVQuery_DistroResponsesExceedTheLanguageCap pins the API fallback's
// body limit on both sides.
//
// The 4 MiB cap was sized for the language ecosystems. A USN enumerates every
// version it covers, so a distro query runs an order of magnitude past it:
// measured 2026-09-11, linux 5.15.0-91.101 in Ubuntu:22.04:LTS answers with
// 32.8 MB. Under the old cap the body was truncated and the operator read
// "parse osv response: unexpected end of JSON input", which names nothing they
// can act on.
func TestOSVQuery_DistroResponsesExceedTheLanguageCap(t *testing.T) {
	// Padding rides in a summary so the response stays valid JSON at any size.
	padded := func(n int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"vulns":[{"id":"USN-0000-1","summary":"`))
			chunk := bytes.Repeat([]byte("x"), 64<<10)
			for written := 0; written < n; written += len(chunk) {
				_, _ = w.Write(chunk)
			}
			_, _ = w.Write([]byte(`"}]}`))
		}
	}

	srv := httptest.NewServer(padded(6 << 20))
	defer srv.Close()
	ck := NewOSVChecker(&fakeOSVStore{})
	ck.Endpoint = srv.URL

	vulns, err := ck.query(context.Background(), "Ubuntu:22.04:LTS", "linux", "5.15.0-91.101")
	if err != nil {
		t.Fatalf("a 6 MiB distro response is inside the cap: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "USN-0000-1" {
		t.Fatalf("got %v", vulnIDs(vulns))
	}

	// Past the cap the reason names the cap. Anything else sends the operator
	// after an upstream JSON defect that is not there.
	_, err = ck.query(context.Background(), "npm", "lodash", "4.17.4")
	if err == nil {
		t.Fatal("a 6 MiB response is past the 4 MiB language cap")
	}
	if !strings.Contains(err.Error(), "larger than the 4 MiB cap") {
		t.Errorf("the error must name the cap rather than blaming the JSON: %v", err)
	}

	if got, want := osvAPIBodyLimit("Ubuntu:22.04:LTS"), int64(64<<20); got != want {
		t.Errorf("osvAPIBodyLimit(distro) = %d, want %d", got, want)
	}
}
