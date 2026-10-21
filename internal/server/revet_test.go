package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

//nolint:gosec // G101: a test HMAC key, not a credential.
const revetSecret = "feed-shared-secret"

// revetServer catalogs minimist 1.2.0, admitted, under an OSV gate whose
// synced database now names it: the state a month after admission, once an
// advisory landed.
func revetServer(t *testing.T) *Server {
	t.Helper()
	s := hostedServer(t)
	s.cfg.RevetWebhookSecret = revetSecret
	gateNpmOSV(t, s, true)
	addVersion(t, s, manifest.TypeNpm, "minimist", manifest.VersionEntry{Version: "1.2.0"})
	if err := s.store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.RecordAdmission(t.Context(), audit.Admission{
		PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0",
		Decision: audit.AdmissionAdmitted, Checks: audit.NotEvaluatedChecks("seeded"),
		DecidedAt: time.Now().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func revetBody(t *testing.T, at time.Time, version string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": "npm", "name": "minimist", "version": version,
		"reason": "GHSA-test-0001", "timestamp": at.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// postRevet sends from outside admin_permit_cidr with no bearer token: the
// signature is the only credential the route may ask for.
func postRevet(s *Server, body []byte, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, RevetWebhookPath, bytes.NewReader(body))
	req.RemoteAddr = "198.51.100.7:44000"
	if sig != "" {
		req.Header.Set(RevetSignatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	return rec
}

// A signed call from outside the admin network re-vets the version at once
// and answers with the new decision; under hide the version is hidden.
func TestRevetWebhookReVetsAndAnswers(t *testing.T) {
	s := revetServer(t)
	s.revet.rv.OnBlock = config.RevetHide
	body := revetBody(t, time.Now(), "1.2.0")
	rec := postRevet(s, body, sign(revetSecret, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook = %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Results []admit.RevetOutcome `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %+v, want one", resp.Results)
	}
	o := resp.Results[0]
	if o.Previous != audit.AdmissionAdmitted || o.Decision != audit.AdmissionPolicyBlocked || o.Action != admit.RevetHidden {
		t.Errorf("outcome = %+v, want admitted -> policy_blocked, hidden", o)
	}
	pm, err := s.store.GetPackage(t.Context(), manifest.TypeNpm, "minimist")
	if err != nil || pm == nil || !pm.Versions[0].Hidden {
		t.Errorf("version not hidden in the store the server serves from")
	}
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "minimist"})
	if err != nil || len(rows) != 2 || rows[0].Identity != "webhook" || rows[0].Actor != admit.RevetActor {
		t.Errorf("rows = %+v (%v), want the webhook's row beside the admission", rows, err)
	}
}

// A threat feed naming a package the server only ever proxied gets its
// decision back rather than a 404, and under hide the refusal is reported:
// the version has no catalog entry to hide, and none is created.
func TestRevetWebhookReVetsAProxyOnlyVersion(t *testing.T) {
	s := hostedServer(t)
	s.cfg.RevetWebhookSecret = revetSecret
	gateNpmOSV(t, s, true)
	if err := s.auditDB.RecordAdmission(t.Context(), audit.Admission{
		PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0", ObjectKey: "npm/minimist/-/minimist-1.2.0.tgz",
		Decision: audit.AdmissionAdmitted, Checks: audit.NotEvaluatedChecks("seeded"),
		DecidedAt: time.Now().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	s.revet.rv.OnBlock = config.RevetHide
	body := revetBody(t, time.Now(), "")
	rec := postRevet(s, body, sign(revetSecret, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook = %d %s, want 200", rec.Code, rec.Body.String())
	}
	var resp struct {
		Results []admit.RevetOutcome `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %+v, want one", resp.Results)
	}
	if o := resp.Results[0]; o.Version != "1.2.0" || o.Decision != audit.AdmissionPolicyBlocked || o.Action != admit.RevetReported {
		t.Errorf("outcome = %+v, want 1.2.0 policy_blocked, reported", o)
	}
	if pm, err := s.store.GetPackage(t.Context(), manifest.TypeNpm, "minimist"); err != nil || pm != nil {
		t.Errorf("re-vet wrote a catalog entry: %+v (%v)", pm, err)
	}
	if rows := admissionsOf(t, s); len(rows) != 2 || rows[0].Actor != admit.RevetActor {
		t.Errorf("rows = %+v, want the webhook's row beside the fill's", rows)
	}
}

// Every authentication failure is the same bare 401, and nothing is re-vetted.
func TestRevetWebhookRefusesBadSignatures(t *testing.T) {
	s := revetServer(t)
	body := revetBody(t, time.Now(), "1.2.0")
	other := revetBody(t, time.Now(), "")
	cases := map[string]string{
		"missing":      "",
		"no prefix":    strings.TrimPrefix(sign(revetSecret, body), "sha256="),
		"not hex":      "sha256=zz",
		"wrong secret": sign("not-the-secret", body),
		"other body":   sign(revetSecret, other),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			rec := postRevet(s, body, sig)
			if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != "Unauthorized" {
				t.Errorf("= %d %q, want a bare 401", rec.Code, rec.Body.String())
			}
		})
	}
	t.Run("secret unset", func(t *testing.T) {
		s.cfg.RevetWebhookSecret = ""
		defer func() { s.cfg.RevetWebhookSecret = revetSecret }()
		if rec := postRevet(s, body, sign("", body)); rec.Code != http.StatusUnauthorized {
			t.Errorf("= %d, want 401 with no secret configured", rec.Code)
		}
	})
	if rows := admissionsOf(t, s); len(rows) != 1 {
		t.Errorf("rows = %d, want only the seeded admission", len(rows))
	}
	denied, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range denied {
		if d.Status == audit.DenialSignature {
			n++
		}
	}
	if n != len(cases)+1 {
		t.Errorf("signature denials recorded = %d, want %d", n, len(cases)+1)
	}
}

// A body signed more than five minutes ago is refused even with a good
// signature, and so is a fresh body sent a second time.
func TestRevetWebhookRefusesReplays(t *testing.T) {
	s := revetServer(t)
	stale := revetBody(t, time.Now().Add(-6*time.Minute), "1.2.0")
	if rec := postRevet(s, stale, sign(revetSecret, stale)); rec.Code != http.StatusUnauthorized {
		t.Errorf("stale body = %d, want 401", rec.Code)
	}
	future := revetBody(t, time.Now().Add(6*time.Minute), "1.2.0")
	if rec := postRevet(s, future, sign(revetSecret, future)); rec.Code != http.StatusUnauthorized {
		t.Errorf("future body = %d, want 401", rec.Code)
	}
	fresh := revetBody(t, time.Now(), "1.2.0")
	if rec := postRevet(s, fresh, sign(revetSecret, fresh)); rec.Code != http.StatusOK {
		t.Fatalf("first send = %d %s", rec.Code, rec.Body.String())
	}
	if rec := postRevet(s, fresh, sign(revetSecret, fresh)); rec.Code != http.StatusUnauthorized {
		t.Errorf("second send = %d, want 401", rec.Code)
	}
	if rows := admissionsOf(t, s); len(rows) != 2 {
		t.Errorf("rows = %d, want the seed and one re-vet", len(rows))
	}
}

// gate holds a re-vet inside its check until released.
type gate struct {
	entered chan struct{}
	release chan struct{}
}

func (g *gate) Check(context.Context, *manifest.PackageManifest, *manifest.VersionEntry) policy.Result {
	g.entered <- struct{}{}
	<-g.release
	return policy.Result{Check: audit.CheckOSV, Action: policy.ActionPass}
}

// A tick that lands while a sweep is still walking is skipped, and a webhook
// call waits for the version the sweep is on rather than deciding beside it.
func TestRevetScheduleTickSkipsWhileASweepRuns(t *testing.T) {
	s := revetServer(t)
	g := &gate{entered: make(chan struct{}, 2), release: make(chan struct{})}
	s.revet.rv.Checkers = func() []policy.VersionChecker { return []policy.VersionChecker{g} }

	first := make(chan bool)
	go func() { first <- s.revetSweep(t.Context()) }()
	<-g.entered

	if s.revetSweep(t.Context()) {
		t.Error("a second sweep ran while the first was mid-walk")
	}

	webhook := make(chan int)
	body := revetBody(t, time.Now(), "1.2.0")
	go func() { webhook <- postRevet(s, body, sign(revetSecret, body)).Code }()
	select {
	case <-g.entered:
		t.Fatal("the webhook's re-vet ran beside the sweep's")
	case <-time.After(200 * time.Millisecond):
	}

	close(g.release)
	if !<-first {
		t.Error("the first sweep reported it did not run")
	}
	if code := <-webhook; code != http.StatusOK {
		t.Errorf("webhook after the sweep = %d", code)
	}
	if rows := admissionsOf(t, s); len(rows) != 3 {
		t.Errorf("rows = %d, want the seed, the sweep's and the webhook's", len(rows))
	}
}

func admissionsOf(t *testing.T, s *Server) []audit.Admission {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "minimist"})
	if err != nil {
		t.Fatal(fmt.Errorf("admissions: %w", err))
	}
	return rows
}

// An open-mode namespaced binary names no version, so its fill records a row
// of (binary, <namespace>/<rest>, "") pinned to the object and the upstream
// that supplied it. After the allow-list is narrowed past that upstream, the
// server's own revetter finds the object as a target and refuses it, reading
// back exactly what the fill left.
func TestRevetRefusesAnUnversionedBinaryFillOutsideANarrowedList(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/dl/tool-linux.tgz", "tool bytes")
	s.cfg.BinaryUpstreams = map[string]config.BinaryUpstream{
		"acme": {URL: up.ts.URL + "/dl/", Mode: config.UpstreamModeOpen},
	}
	seedBinaryPolicy(t, s, up.ts.URL+"/dl/")

	if status, body := getStatusAndBody(t, s, "/binaries/acme/tool-linux.tgz"); status != http.StatusOK {
		t.Fatalf("fill = %d, want 200 (%s); upstream saw %v", status, body, up.paths())
	}
	if !up.sawPath("/dl/tool-linux.tgz") {
		t.Fatalf("upstream saw %v, want the fill to reach it", up.paths())
	}

	if _, err := s.auditDB.DeletePolicyByID(t.Context(), "test-"+up.ts.URL+"/dl/"); err != nil {
		t.Fatal(err)
	}
	seedBinaryPolicy(t, s, "https://good.example.com/")

	targets, err := s.revet.rv.Targets(t.Context(), admit.RevetFilter{Type: manifest.TypeBinary})
	const key = manifest.BinaryPrefix + "acme/tool-linux.tgz"
	if err != nil || len(targets) != 1 || targets[0].ObjectKey != key || targets[0].Version != "" {
		t.Fatalf("targets = %+v (%v), want the filled object by its key", targets, err)
	}
	o := s.revet.rv.One(t.Context(), targets[0], "schedule")
	if o.Error != "" || o.Decision != audit.AdmissionPolicyBlocked || o.Action != admit.RevetReported || o.ObjectKey != key {
		t.Fatalf("outcome = %+v, want policy_blocked and reported for %s", o, key)
	}
	if len(o.Failing) != 1 || o.Failing[0].Check != audit.CheckAllowList || !strings.Contains(o.Failing[0].Detail, up.ts.URL) {
		t.Errorf("failing = %+v, want the allow-list naming the recorded upstream %s", o.Failing, up.ts.URL)
	}
}
