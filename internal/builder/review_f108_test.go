package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
)

func TestReviewReusedGomodCannotAcquireFalseVerifiedStatement(t *testing.T) {
	attestKey(t)
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	forged := sumdbtest.NewModule(t, honest.Path, honest.Version, "different bytes")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(honest)
	app := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier, GomodNoSumdb: "example.com"}
	f := fetchGomodFrom(t, app, goproxy(t, forged.Path, forged.Version, forged.Mod, forged.Zip), forged.Path, forged.Version, nil)
	if f.summary.Failures != 0 {
		t.Fatalf("excluded initial fetch: %+v", f.summary)
	}
	app.GomodNoSumdb = ""
	f.cfg.Force = false
	second := FetchGomod(f.cfg, f.store, "")
	row := newestRow(t, f.adb, honest.Path, honest.Version)
	c := admit.ChecksumDatabaseEntry(row)
	if second.Failures != 1 || row.Decision != audit.AdmissionPolicyBlocked {
		t.Errorf("re-admission of reused mismatching bytes: failures=%d decision=%s outcome=%s object=%s", second.Failures, row.Decision, c.ChecksumDatabase.Outcome, row.ObjectKey)
	}
	if fileExists(filepath.Join(f.dir, honest.Version+".zip")) {
		t.Error("mismatching zip left for upload")
	}
	paths := GomodArtifactPaths(f.cfg, f.store, "")
	AttachAttestations(f.cfg, "gomod", paths)
	for _, p := range paths {
		for _, ep := range p.Attestations {
			raw, err := os.ReadFile(ep)
			if err != nil {
				t.Fatal(err)
			}
			_, st, err := attest.ParseEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range st.Predicate.PolicyEvaluations.Evaluations {
				if e.Check == audit.CheckChecksumDatabase && e.Status == audit.CheckPass && strings.HasPrefix(e.Detail, "verified:") {
					t.Errorf("signed verified statement for forged zip: %s", e.Detail)
				}
			}
		}
	}
}

// The bytes a verified fetch compared are the ones its pin signs, so their
// statement carries the verified evaluation, on the first fetch and when the
// build root is reused.
func TestVerifiedGomodFetchSignsTheComparedZip(t *testing.T) {
	attestKey(t)
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(m)
	app := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}
	f := fetchGomodFrom(t, app, goproxy(t, m.Path, m.Version, m.Mod, m.Zip), m.Path, m.Version, nil)
	if f.summary.Failures != 0 {
		t.Fatalf("fetch: %+v", f.summary)
	}
	verified := func(when string) {
		t.Helper()
		var found bool
		paths := GomodArtifactPaths(f.cfg, f.store, "")
		AttachAttestations(f.cfg, "gomod", paths)
		for _, p := range paths {
			for _, ep := range p.Attestations {
				raw, err := os.ReadFile(ep)
				if err != nil {
					t.Fatal(err)
				}
				_, st, err := attest.ParseEnvelope(raw)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range st.Predicate.PolicyEvaluations.Evaluations {
					if e.Check == audit.CheckChecksumDatabase && e.Status == audit.CheckPass && strings.HasPrefix(e.Detail, "verified:") {
						found = true
					}
				}
			}
		}
		if !found {
			t.Errorf("%s: no statement carries the verified checksum_database evaluation", when)
		}
	}
	verified("first fetch")
	f.cfg.Force = false
	if again := FetchGomod(f.cfg, f.store, ""); again.Failures != 0 {
		t.Fatalf("reuse: %+v", again)
	}
	verified("reuse")
}
