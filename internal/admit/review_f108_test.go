package admit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
)

func TestReviewInvalidNoteCannotUseActiveOverride(t *testing.T) {
	f := newAdmissionFixture(t)
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "x")
	log.AddModule(m)
	log.Wrap = func(w http.ResponseWriter, r *http.Request, db http.Handler) {
		if !strings.HasPrefix(r.URL.Path, "/lookup/") {
			db.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		db.ServeHTTP(rec, r)
		_, _ = w.Write(append(rec.Body.Bytes(), []byte("\nchecksum database read failed\n")...))
	}
	cfg := sumdbConfig(f.synced, log)
	now := time.Now()
	o := request(t, f.adb, cfg, OverrideRequest{Type: manifest.TypeGomod, Name: m.Path, Version: m.Version, Check: audit.CheckChecksumDatabase, Reason: "INC-7", Expires: "7d"}, now)
	vote(t, f.adb, o.ID, "bob", true, now)
	got := Fetch(t.Context(), f.adb, []policy.VersionChecker{ChecksumDatabaseChecker(cfg, f.adb)}, manifest.TypeGomod, m.Path, manifest.VersionEntry{Version: m.Version}, AllowListCheck(false, m.Path, nil), Who{}, "")
	c := checkOf(t, got.Admission, audit.CheckChecksumDatabase)
	if got.Block == nil || got.Admission.Decision != audit.AdmissionPolicyBlocked || c.ChecksumDatabase.Outcome != audit.ProvenanceInvalid || c.Override != "" {
		t.Fatalf("invalid note admitted through override: decision=%s status=%s outcome=%s override=%s", got.Admission.Decision, c.Status, c.ChecksumDatabase.Outcome, c.Override)
	}
}
