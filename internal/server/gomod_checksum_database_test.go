package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestReviewSameObjectFillCannotBorrowVerifiedStatement(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	forged := sumdbtest.NewModule(t, honest.Path, honest.Version, "different bytes")
	for _, tc := range []struct {
		ext            string
		honest, forged []byte
	}{
		{".zip", honest.Zip, forged.Zip},
		{".mod", honest.Mod, []byte("module example.com/widget\n\nrequire example.com/evil v1.0.0\n")},
	} {
		t.Run(tc.ext, func(t *testing.T) {
			signer := installAttestKey(t)
			log := sumdbtest.New(t, sumdbtest.NewKey(t))
			log.AddModule(honest)
			s := gomodSumdbServer(t, log, newRecordingUpstream(t))
			s.loadAttestSigner()
			ctx := t.Context()
			key := manifest.GomodKey(honest.Path, honest.Version, tc.ext)
			st := s.typeStore(manifest.TypeGomod)
			request := httptest.NewRequest(http.MethodGet, "/go/"+honest.Path+"/@v/"+honest.Version+tc.ext, nil)
			admitFill := func(exclude string) fillAdmission {
				cfg := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier, GomodNoSumdb: exclude}
				res := admit.Fetch(ctx, s.auditDB, []policy.VersionChecker{admit.ChecksumDatabaseChecker(cfg, s.auditDB)},
					manifest.TypeGomod, honest.Path, manifest.VersionEntry{Version: honest.Version},
					admit.AllowListCheck(false, honest.Path, nil), admit.Who{Actor: "alice"}, "")
				if res.Block != nil {
					t.Fatalf("admission blocked: %+v", res)
				}
				return fillAdmission{typ: manifest.TypeGomod, name: honest.Path, version: honest.Version, row: res.Admission}
			}
			digest := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
			spool := func(b []byte) string {
				p := filepath.Join(t.TempDir(), "spool"+tc.ext)
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
				return p
			}

			first := admitFill("example.com")
			firstPin, err := s.verifyProxyChecksum(ctx, key, digest(tc.forged), true)
			if err != nil || firstPin == nil {
				t.Fatalf("first digest check: %v", err)
			}
			if f := s.checksumDatabaseGate(ctx, request, first, key, spool(tc.forged)); f != nil {
				t.Fatal("excluded fill refused")
			}

			// Two cache misses can both pass the absent SHA-256 check. Suspend the
			// first before its deferred pin; suspend the second between pin and emit.
			second := admitFill("")
			secondPin, err := s.verifyProxyChecksum(ctx, key, digest(tc.honest), true)
			if err != nil || secondPin == nil {
				t.Fatalf("second digest check: %v", err)
			}
			if f := s.checksumDatabaseGate(ctx, request, second, key, spool(tc.honest)); f != nil {
				t.Fatal("honest fill refused")
			}
			secondPin()
			outcome, err := s.auditDB.PinAdmission(ctx, audit.AdmissionPin{PkgType: second.typ, PkgName: second.name,
				PkgVersion: second.version, ObjectKey: key, Admitted: &second.row})
			if err != nil {
				t.Fatal(err)
			}

			firstPin()
			s.pinFill(ctx, st, first, key, digest(tc.forged), true)
			s.emitAttestation(ctx, st, attest.Pin{Type: second.typ, Name: second.name, Version: second.version,
				ObjectKey: key, SHA256: digest(tc.honest), Outcome: outcome})

			ek, err := attest.Newest(ctx, st, []string{key})
			if err != nil {
				t.Fatal(err)
			}
			if ek == "" {
				return
			}
			raw, err := st.Get(ctx, ek)
			if err != nil {
				t.Fatal(err)
			}
			env, statement, err := attest.ParseEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			if statement.Subject[0].Digest["sha256"] != digest(tc.forged) {
				return
			}
			for _, check := range attest.Verify(env, statement, attest.VerifyInput{Trusted: trustedBy(t, signer),
				ArtifactSHA256: digest(tc.forged), WantPURL: attest.PURL(manifest.TypeGomod, honest.Path, honest.Version, key)}) {
				if !check.OK {
					t.Fatalf("invalid envelope: %+v", check)
				}
			}
			for _, evaluation := range statement.Predicate.PolicyEvaluations.Evaluations {
				if evaluation.Check == audit.CheckChecksumDatabase && evaluation.Status == audit.CheckPass && strings.HasPrefix(evaluation.Detail, "verified:") {
					t.Errorf("excluded %s fill signed differing bytes under the other fill's verified row: %s", tc.ext, evaluation.Detail)
				}
			}
		})
	}
}

func TestReviewChecksumEvidenceFilterPreservesNewerDenial(t *testing.T) {
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	for _, tc := range []struct {
		ext  string
		body []byte
	}{{".zip", m.Zip}, {".mod", m.Mod}} {
		t.Run(tc.ext, func(t *testing.T) {
			signer := installAttestKey(t)
			log := sumdbtest.New(t, sumdbtest.NewKey(t))
			log.AddModule(m)
			s := gomodSumdbServer(t, log, newRecordingUpstream(t))
			s.cfg.GomodNoSumdb = "example.com"
			s.loadAttestSigner()
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/"+m.Path+"/@v/"+m.Version+tc.ext {
					close(started)
					<-release
					_, _ = w.Write(tc.body)
					return
				}
				if r.URL.Path == "/"+m.Path+"/@v/"+m.Version+".info" {
					_, _ = w.Write([]byte(`{"Version":"v1.2.3","Time":"2026-11-03T00:00:00Z"}`))
					return
				}
				http.NotFound(w, r)
			}))
			defer up.Close()
			defer once.Do(func() { close(release) })
			s.cfg.GomodUpstream = up.URL
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- doRequest(s, http.MethodGet, "/go/"+m.Path+"/@v/"+m.Version+tc.ext, nil) }()
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("fill never reached upstream")
			}
			first := newestGomodRow(t, s, m.Path, m.Version)
			if c := admit.ChecksumDatabaseEntry(first); c == nil || c.ChecksumDatabase.Outcome != audit.ProvenanceUnavailable {
				t.Fatalf("first fill did not use its exclusion: %+v", first)
			}
			if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeGomod, MinAgeSeconds: 86400, Action: policy.ActionBlock}); err != nil {
				t.Fatal(err)
			}
			age := policy.NewAgeChecker(s.auditDB)
			age.GoProxy = up.URL
			age.Now = func() time.Time { return time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC) }
			cfg := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}
			second := admit.Fetch(t.Context(), s.auditDB, []policy.VersionChecker{age, admit.ChecksumDatabaseChecker(cfg, s.auditDB)},
				manifest.TypeGomod, m.Path, manifest.VersionEntry{Version: m.Version}, admit.AllowListCheck(false, m.Path, nil), admit.Who{Actor: "alice"}, "")
			if second.Block == nil || second.Block.Check != audit.CheckAge || second.Admission.Decision != audit.AdmissionPolicyBlocked {
				t.Fatalf("new policy did not deny the version: %+v", second)
			}
			if c := admit.ChecksumDatabaseEntry(second.Admission); c == nil || c.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
				t.Fatalf("new decision did not verify the log: %+v", second.Admission)
			}
			once.Do(func() { close(release) })
			select {
			case rec := <-done:
				if rec.Code != http.StatusOK {
					t.Fatalf("old fill: %d %s", rec.Code, rec.Body.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("fill did not finish")
			}
			if row := newestGomodRow(t, s, m.Path, m.Version); row.Decision != audit.AdmissionPolicyBlocked {
				t.Fatalf("new denial was lost from the database: %+v", row)
			}
			key := manifest.GomodKey(m.Path, m.Version, tc.ext)
			h := sha256.Sum256(tc.body)
			for _, ek := range envelopesFor(t, s.typeStore(manifest.TypeGomod), key) {
				raw, err := s.typeStore(manifest.TypeGomod).Get(t.Context(), ek)
				if err != nil {
					t.Fatal(err)
				}
				env, statement, err := attest.ParseEnvelope(raw)
				if err != nil {
					t.Fatal(err)
				}
				for _, check := range attest.Verify(env, statement, attest.VerifyInput{Trusted: trustedBy(t, signer), ArtifactSHA256: hex.EncodeToString(h[:]), WantPURL: attest.PURL(manifest.TypeGomod, m.Path, m.Version, key)}) {
					if !check.OK {
						t.Fatalf("invalid envelope: %+v", check)
					}
				}
				t.Errorf("signed decision %s after newer policy_blocked age decision; checksum evidence filtering hid the denial", statement.Predicate.PolicyEvaluations.Decision)
			}
		})
	}
}

func TestReviewChecksumEvidenceSearchLimitPreservesNewerDenial(t *testing.T) {
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	for _, tc := range []struct {
		ext  string
		body []byte
	}{{".zip", m.Zip}, {".mod", m.Mod}} {
		t.Run(tc.ext, func(t *testing.T) {
			signer := installAttestKey(t)
			log := sumdbtest.New(t, sumdbtest.NewKey(t))
			log.AddModule(m)
			s := gomodSumdbServer(t, log, newRecordingUpstream(t))
			s.cfg.GomodNoSumdb = "example.com"
			s.loadAttestSigner()
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/"+m.Path+"/@v/"+m.Version+tc.ext {
					close(started)
					<-release
					_, _ = w.Write(tc.body)
					return
				}
				if r.URL.Path == "/"+m.Path+"/@v/"+m.Version+".info" {
					_, _ = w.Write([]byte(`{"Version":"v1.2.3","Time":"2026-11-03T00:00:00Z"}`))
					return
				}
				http.NotFound(w, r)
			}))
			defer up.Close()
			defer once.Do(func() { close(release) })
			s.cfg.GomodUpstream = up.URL
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- doRequest(s, http.MethodGet, "/go/"+m.Path+"/@v/"+m.Version+tc.ext, nil) }()
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("fill never reached upstream")
			}
			first := newestGomodRow(t, s, m.Path, m.Version)
			if c := admit.ChecksumDatabaseEntry(first); c == nil || c.ChecksumDatabase.Outcome != audit.ProvenanceUnavailable {
				t.Fatalf("first fill did not use its exclusion: %+v", first)
			}
			// Enough intervening admissions push this fill's evidence out of the
			// pin candidate search; they do not grant permission after a denial.
			lookupCfg := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}
			for range 200 {
				res := admit.Fetch(t.Context(), s.auditDB, []policy.VersionChecker{admit.ChecksumDatabaseChecker(lookupCfg, s.auditDB)},
					manifest.TypeGomod, m.Path, manifest.VersionEntry{Version: m.Version}, admit.AllowListCheck(false, m.Path, nil), admit.Who{Actor: "alice"}, "")
				if res.Block != nil || res.Admission.Decision != audit.AdmissionAdmitted {
					t.Fatalf("intervening admission: %+v", res)
				}
			}
			if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeGomod, MinAgeSeconds: 86400, Action: policy.ActionBlock}); err != nil {
				t.Fatal(err)
			}
			age := policy.NewAgeChecker(s.auditDB)
			age.GoProxy = up.URL
			age.Now = func() time.Time { return time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC) }
			cfg := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}
			second := admit.Fetch(t.Context(), s.auditDB, []policy.VersionChecker{age, admit.ChecksumDatabaseChecker(cfg, s.auditDB)},
				manifest.TypeGomod, m.Path, manifest.VersionEntry{Version: m.Version}, admit.AllowListCheck(false, m.Path, nil), admit.Who{Actor: "alice"}, "")
			if second.Block == nil || second.Block.Check != audit.CheckAge || second.Admission.Decision != audit.AdmissionPolicyBlocked {
				t.Fatalf("new policy did not deny the version: %+v", second)
			}
			if c := admit.ChecksumDatabaseEntry(second.Admission); c == nil || c.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
				t.Fatalf("new decision did not verify the log: %+v", second.Admission)
			}
			once.Do(func() { close(release) })
			select {
			case rec := <-done:
				if rec.Code != http.StatusOK {
					t.Fatalf("old fill: %d %s", rec.Code, rec.Body.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("fill did not finish")
			}
			if row := newestGomodRow(t, s, m.Path, m.Version); row.Decision != audit.AdmissionPolicyBlocked {
				t.Errorf("pin synthesized a newer %s decision after policy_blocked; checksum status: %+v", row.Decision, admit.ChecksumDatabaseEntry(row))
			}
			key := manifest.GomodKey(m.Path, m.Version, tc.ext)
			h := sha256.Sum256(tc.body)
			for _, ek := range envelopesFor(t, s.typeStore(manifest.TypeGomod), key) {
				raw, err := s.typeStore(manifest.TypeGomod).Get(t.Context(), ek)
				if err != nil {
					t.Fatal(err)
				}
				env, statement, err := attest.ParseEnvelope(raw)
				if err != nil {
					t.Fatal(err)
				}
				for _, check := range attest.Verify(env, statement, attest.VerifyInput{Trusted: trustedBy(t, signer), ArtifactSHA256: hex.EncodeToString(h[:]), WantPURL: attest.PURL(manifest.TypeGomod, m.Path, m.Version, key)}) {
					if !check.OK {
						t.Fatalf("invalid envelope: %+v", check)
					}
				}
				t.Errorf("signed decision %s after newer policy_blocked age decision; the bounded pin search fabricated a newer admission", statement.Predicate.PolicyEvaluations.Decision)
			}
		})
	}
}

// The go command resolves "go install example.com/widget/cmd/widget@v1.2.3"
// by asking for the .info of every path prefix and moving on at a 404 or
// 410. The checksum database holds no record for a prefix that is not a
// module, so the fill must answer the upstream's not-found rather than the
// fail-closed refusal, which the go command treats as fatal. A version the
// upstream does publish is still refused when the database cannot confirm it.
func TestGomodPrefixProbeTheDatabaseDoesNotKnowIsNotFound(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "the published bytes")
	probe := "/example.com/widget/cmd/widget/@v/v1.2.3.info"

	for _, tc := range []struct {
		name      string
		published bool
		status    int
	}{
		{"unpublished prefix", false, http.StatusNotFound},
		{"published but unknown to the database", true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := sumdbtest.New(t, sumdbtest.NewKey(t))
			log.AddModule(honest)
			up := newRecordingUpstream(t)
			if tc.published {
				up.route(probe, `{"Version":"v1.2.3","Time":"2024-01-23T13:54:04Z"}`)
			}
			s := gomodSumdbServer(t, log, up)

			rec := doRequest(s, http.MethodGet, "/go"+probe, nil)
			if rec.Code != tc.status {
				t.Fatalf("probe = %d %s, want %d", rec.Code, rec.Body.String(), tc.status)
			}
			rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeGomod,
				PkgName: "example.com/widget/cmd/widget", PkgVersion: "v1.2.3"})
			if err != nil {
				t.Fatal(err)
			}
			if !tc.published {
				if len(rows) != 0 {
					t.Errorf("an unpublished version left admission rows: %+v", rows)
				}
				return
			}
			if len(rows) == 0 || rows[0].Decision != audit.AdmissionPolicyBlocked {
				t.Fatalf("a published version the database cannot confirm was not refused on record: %+v", rows)
			}
			if c := admit.ChecksumDatabaseEntry(rows[0]); c == nil || c.ChecksumDatabase.Outcome != audit.ProvenanceUnknown {
				t.Errorf("checksum_database entry %+v, want unknown", c)
			}
		})
	}
}
