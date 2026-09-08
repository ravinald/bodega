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
// `policy osv rescan` writes. The handler serializes VersionEntry whole, so
// nothing here needed a change to make the stamp reachable — and that is
// exactly why it needs a test: the next handler that projects a narrower shape
// would drop the fields with nothing failing.
func TestAPIVersionCarriesOSVStamp(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(context.Background(), manifest.TypeNpm, "sample", manifest.VersionEntry{
		Version: "1.2.5",
		Metadata: map[string]string{
			policy.OSVMetaVulns:     "GHSA-aaaa-bbbb-cccc,GHSA-dddd-eeee-ffff",
			policy.OSVMetaCheckedAt: "2026-09-08T10:00:00Z",
			policy.OSVMetaSeverity:  `{"GHSA-aaaa-bbbb-cccc":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}`,
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	cfg := &config.Config{Bucket: "test-bucket", Region: "us-west-2", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, storage.NewSingle(memStore(map[string]string{})), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/packages/npm/sample/1.2.5")
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
}
