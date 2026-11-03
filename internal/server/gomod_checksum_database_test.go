package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
)

// gomodSumdbServer is a proxying server whose gomod fills run the
// checksum_database check against log, filling from up.
func gomodSumdbServer(t *testing.T, log *sumdbtest.Log, up *recordingUpstream) *Server {
	t.Helper()
	prev := fetchCheckers
	fetchCheckers = func(cfg *config.Config, adb *audit.DB) []policy.VersionChecker {
		return []policy.VersionChecker{admit.ChecksumDatabaseChecker(cfg, adb)}
	}
	t.Cleanup(func() { fetchCheckers = prev })
	s := proxyingServer(t)
	s.cfg.GomodUpstream = up.ts.URL
	s.cfg.GomodSumdbURL = log.URL
	s.cfg.GomodSumdbKey = log.Key.Verifier
	return s
}

func newestGomodRow(t *testing.T, s *Server, module, version string) audit.Admission {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeGomod, PkgName: module, PkgVersion: version})
	if err != nil || len(rows) == 0 {
		t.Fatalf("no admission row for %s@%s: %v", module, version, err)
	}
	return rows[0]
}

// A matching zip is served, cached and pinned; one whose zip or go.mod
// disagrees with what the database signed is refused 502 with nothing cached
// and the refusal on record. The .info carries no hash in the database and
// is served unchanged.
func TestProxyFillHoldsGoModulesToTheChecksumDatabase(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "the published bytes")
	forged := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "a backdoor")
	base := "/" + honest.Path + "/@v/" + honest.Version

	t.Run("matching zip", func(t *testing.T) {
		log := sumdbtest.New(t, sumdbtest.NewKey(t))
		log.AddModule(honest)
		up := newRecordingUpstream(t)
		up.route(base+".zip", string(honest.Zip))
		s := gomodSumdbServer(t, log, up)

		rec := doRequest(s, http.MethodGet, "/go"+base+".zip", nil)
		if rec.Code != http.StatusOK || rec.Body.String() != string(honest.Zip) {
			t.Fatalf("fill = %d %q", rec.Code, rec.Body.String())
		}
		key := manifest.GomodKey(honest.Path, honest.Version, ".zip")
		if st, err := s.typeStore(manifest.TypeGomod).Head(t.Context(), key); err != nil || !st.Exists {
			t.Errorf("%s not cached: %+v %v", key, st, err)
		}
		row := newestGomodRow(t, s, honest.Path, honest.Version)
		if row.ObjectKey != key {
			t.Errorf("admission row pinned to %q, want %q", row.ObjectKey, key)
		}
		if c := admit.ChecksumDatabaseEntry(row); c == nil || c.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
			t.Errorf("checksum_database entry %+v", c)
		}
	})

	for _, tc := range []struct {
		name, ext string
		body      []byte
		signed    string
	}{
		{"disagreeing zip", ".zip", forged.Zip, honest.ZipHash},
		{"disagreeing go.mod", ".mod", []byte("module example.com/widget\n\nrequire example.com/evil v1.0.0\n"), honest.ModHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installAttestKey(t)
			log := sumdbtest.New(t, sumdbtest.NewKey(t))
			log.AddModule(honest)
			up := newRecordingUpstream(t)
			up.route(base+tc.ext, string(tc.body))
			s := gomodSumdbServer(t, log, up)
			s.loadAttestSigner()

			rec := doRequest(s, http.MethodGet, "/go"+base+tc.ext, nil)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("fill = %d %s, want 502", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			row := newestGomodRow(t, s, honest.Path, honest.Version)
			c := admit.ChecksumDatabaseEntry(row)
			if row.Decision != audit.AdmissionPolicyBlocked || c == nil || c.Status != audit.CheckBlock ||
				c.ChecksumDatabase.Outcome != audit.ProvenanceInvalid || c.ChecksumDatabase.File != honest.Version+tc.ext ||
				c.ChecksumDatabase.Computed == "" || c.ChecksumDatabase.ZipHash != honest.ZipHash || c.ChecksumDatabase.ModHash != honest.ModHash {
				t.Fatalf("refusal row %s %+v", row.Decision, c)
			}
			incident := strings.TrimSuffix(strings.Fields(c.Detail[strings.Index(c.Detail, "incident ")+len("incident "):])[0], ")")
			for _, want := range []string{"Go checksum database", "incident " + incident, "do not route around it"} {
				if !strings.Contains(body, want) {
					t.Errorf("refusal %q does not carry %q", body, want)
				}
			}
			if !strings.Contains(c.Detail, tc.signed) || !strings.Contains(c.Detail, c.ChecksumDatabase.Computed) {
				t.Errorf("row detail %q does not name both hashes", c.Detail)
			}
			key := manifest.GomodKey(honest.Path, honest.Version, tc.ext)
			if st, err := s.typeStore(manifest.TypeGomod).Head(t.Context(), key); err != nil || st.Exists {
				t.Errorf("%s cached: %+v %v", key, st, err)
			}
			if got, _ := s.auditDB.GetChecksum(t.Context(), key); got != nil && got.Value != "" {
				t.Errorf("%s pinned: %+v", key, got)
			}
			if got := envelopesFor(t, s.typeStore(manifest.TypeGomod), key); len(got) != 0 {
				t.Errorf("attestations signed for refused bytes: %v", got)
			}
		})
	}

	t.Run("info is not compared", func(t *testing.T) {
		log := sumdbtest.New(t, sumdbtest.NewKey(t))
		log.AddModule(honest)
		up := newRecordingUpstream(t)
		up.route(base+".info", `{"Version":"v1.2.3","Time":"2024-01-23T13:54:04Z"}`)
		s := gomodSumdbServer(t, log, up)
		if rec := doRequest(s, http.MethodGet, "/go"+base+".info", nil); rec.Code != http.StatusOK {
			t.Fatalf("info fill = %d %s", rec.Code, rec.Body.String())
		}
	})
}

// The statement signed for an admitted Go module carries the
// checksum_database evaluation as the row recorded it.
func TestGomodAttestationCarriesTheChecksumDatabase(t *testing.T) {
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "the published bytes")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(m)
	up := newRecordingUpstream(t)
	up.route("/"+m.Path+"/@v/"+m.Version+".zip", string(m.Zip))
	signer := installAttestKey(t)
	s := gomodSumdbServer(t, log, up)
	s.loadAttestSigner()

	if rec := doRequest(s, http.MethodGet, "/go/"+m.Path+"/@v/"+m.Version+".zip", nil); rec.Code != http.StatusOK {
		t.Fatalf("fill = %d %s", rec.Code, rec.Body.String())
	}
	key := manifest.GomodKey(m.Path, m.Version, ".zip")
	envs := envelopesFor(t, s.typeStore(manifest.TypeGomod), key)
	if len(envs) != 1 {
		t.Fatalf("envelopes beside %s = %v, want 1", key, envs)
	}
	raw, err := s.typeStore(manifest.TypeGomod).Get(t.Context(), envs[0])
	if err != nil {
		t.Fatal(err)
	}
	env, st, err := attest.ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(m.Zip)
	for _, r := range attest.Verify(env, st, attest.VerifyInput{Trusted: trustedBy(t, signer), ArtifactSHA256: hex.EncodeToString(sum[:]),
		WantPURL: attest.PURL(manifest.TypeGomod, m.Path, m.Version, key)}) {
		if !r.OK {
			t.Errorf("%s: expected %s, observed %s", r.Check, r.Expected, r.Observed)
		}
	}
	var got *attest.Evaluation
	for i, e := range st.Predicate.PolicyEvaluations.Evaluations {
		if e.Check == audit.CheckChecksumDatabase {
			got = &st.Predicate.PolicyEvaluations.Evaluations[i]
		}
	}
	if got == nil {
		t.Fatalf("no checksum_database evaluation in %+v", st.Predicate.PolicyEvaluations.Evaluations)
	}
	if got.Status != audit.CheckPass {
		t.Errorf("status %q, want pass", got.Status)
	}
	for _, want := range []string{"verified", "tree size 1", m.ZipHash, m.ModHash} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("evaluation detail %q does not carry %q", got.Detail, want)
		}
	}
}

func TestReviewConcurrentGomodFillsCannotBorrowVerifiedEvidence(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	forged := sumdbtest.NewModule(t, honest.Path, honest.Version, "different bytes")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(honest)
	var lookups atomic.Int32
	log.Wrap = func(w http.ResponseWriter, r *http.Request, db http.Handler) {
		if strings.HasPrefix(r.URL.Path, "/lookup/") && lookups.Add(1) == 1 {
			http.Error(w, "temporary outage", http.StatusServiceUnavailable)
			return
		}
		db.ServeHTTP(w, r)
	}
	signer := installAttestKey(t)
	s := gomodSumdbServer(t, log, newRecordingUpstream(t))
	s.loadAttestSigner()
	now := time.Now()
	o, err := admit.RequestOverride(t.Context(), s.auditDB, s.cfg, admit.OverrideRequest{
		Type: manifest.TypeGomod, Name: honest.Path, Version: honest.Version,
		Check: audit.CheckChecksumDatabase, Reason: "INC-17", Expires: "7d",
	}, audit.LocalOverrideCaller("alice"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admit.VoteOverride(t.Context(), s.auditDB, o.ID, audit.LocalOverrideCaller("bob"), true, "", now); err != nil {
		t.Fatal(err)
	}

	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".zip"):
			close(started)
			<-release
			_, _ = w.Write(forged.Zip)
		case strings.HasSuffix(r.URL.Path, ".mod"):
			_, _ = w.Write(honest.Mod)
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()
	defer once.Do(func() { close(release) })
	s.cfg.GomodUpstream = up.URL
	base := "/go/" + honest.Path + "/@v/" + honest.Version
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- doRequest(s, http.MethodGet, base+".zip", nil) }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("zip fill never reached the upstream")
	}
	first := newestGomodRow(t, s, honest.Path, honest.Version)
	entry := admit.ChecksumDatabaseEntry(first)
	if entry == nil || entry.ChecksumDatabase.Outcome != audit.ProvenanceUnknown || entry.Status != audit.CheckOverridden {
		t.Fatalf("first fill was not admitted under the outage override: %+v", entry)
	}
	if rec := doRequest(s, http.MethodGet, base+".mod", nil); rec.Code != http.StatusOK {
		t.Fatalf("mod fill: %d %s", rec.Code, rec.Body.String())
	}
	second := newestGomodRow(t, s, honest.Path, honest.Version)
	if entry := admit.ChecksumDatabaseEntry(second); entry == nil || entry.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
		t.Fatalf("second fill did not verify: %+v", entry)
	}
	once.Do(func() { close(release) })
	select {
	case rec := <-done:
		if rec.Code != http.StatusOK && rec.Code != http.StatusBadGateway {
			t.Fatalf("zip fill: %d %s", rec.Code, rec.Body.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("zip fill never finished")
	}
	key := manifest.GomodKey(honest.Path, honest.Version, ".zip")
	for _, path := range envelopesFor(t, s.typeStore(manifest.TypeGomod), key) {
		raw, err := s.typeStore(manifest.TypeGomod).Get(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		env, st, err := attest.ParseEnvelope(raw)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(forged.Zip)
		for _, check := range attest.Verify(env, st, attest.VerifyInput{
			Trusted: trustedBy(t, signer), ArtifactSHA256: hex.EncodeToString(sum[:]),
			WantPURL: attest.PURL(manifest.TypeGomod, honest.Path, honest.Version, key),
		}) {
			if !check.OK {
				t.Fatalf("statement does not verify for the forged zip: %+v", check)
			}
		}
		for _, e := range st.Predicate.PolicyEvaluations.Evaluations {
			if e.Check == audit.CheckChecksumDatabase && e.Status == audit.CheckPass && strings.HasPrefix(e.Detail, "verified:") {
				t.Errorf("forged zip %s acquired another fill's verified statement for %s: %s", forged.ZipHash, honest.ZipHash, e.Detail)
			}
		}
	}
}
