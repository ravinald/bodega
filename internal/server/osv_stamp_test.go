package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// TestAPIVersionCarriesOSVStamp pins the read endpoint against the keys
// `policy osv rescan` writes. The handler serializes VersionEntry whole, so a
// handler that projects a narrower shape would drop the fields with nothing
// failing.
//
// Every ecosystem the OSV gate covers is exercised, because whole-entry
// serialization is only half of reachable: cargo was absent from the handler's
// type switch and answered "unknown type", which put the stamp out of reach
// for that ecosystem alone.
func TestAPIVersionCarriesOSVStamp(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	types := []string{manifest.TypeNpm, manifest.TypePypi, manifest.TypeGomod, manifest.TypeCargo}
	for _, typ := range types {
		if err := store.AddVersion(context.Background(), typ, "sample", manifest.VersionEntry{
			Version: "1.2.5",
			Metadata: map[string]string{
				policy.OSVMetaVulns:     "GHSA-aaaa-bbbb-cccc,GHSA-dddd-eeee-ffff",
				policy.OSVMetaCheckedAt: "2026-09-08T10:00:00Z",
				policy.OSVMetaSeverity:  `{"GHSA-aaaa-bbbb-cccc":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}`,
			},
		}); err != nil {
			t.Fatalf("AddVersion %s: %v", typ, err)
		}
	}
	cfg := &config.Config{Bucket: "test-bucket", Region: "us-west-2", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, storage.NewSingle(memStore(map[string]string{})), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			resp, err := http.Get(ts.URL + "/api/v1/packages/" + typ + "/sample/1.2.5")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			var pm manifest.PackageManifest
			if err := json.NewDecoder(resp.Body).Decode(&pm); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(pm.Versions) != 1 {
				t.Fatalf("scoped payload has %d versions, want 1", len(pm.Versions))
			}
			st := policy.OSVStampOf(pm.Versions[0])
			if !st.Flagged() || len(st.Vulns) != 2 {
				t.Errorf("flagged ids did not survive the endpoint: %+v", st)
			}
			if st.Checked.IsZero() {
				t.Error("the check date did not survive the endpoint")
			}
			if pm.Versions[0].Metadata[policy.OSVMetaSeverity] == "" {
				t.Error("the severity blob did not survive the endpoint")
			}
		})
	}
}
