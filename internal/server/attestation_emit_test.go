package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// installAttestKey writes a fresh attestation key where the server looks and
// returns its signer.
func installAttestKey(t *testing.T) attestsign.Signer {
	t.Helper()
	path := pinAttestKeyPath(t)
	ring, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	return ring.Signer()
}

func trustedBy(t *testing.T, s attestsign.Signer) map[string]ed25519.PublicKey {
	t.Helper()
	return map[string]ed25519.PublicKey{s.KeyID(): s.Public().(ed25519.PublicKey)}
}

func envelopesFor(t *testing.T, st storage.ObjectStore, objectKey string) []string {
	t.Helper()
	keys, err := st.List(t.Context(), manifest.AttestationDir(objectKey))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// A proxy fill signs an envelope beside the bytes it cached, the route serves
// it for a version nothing cataloged, and it verifies against the key and the
// bytes the client received.
func TestProxyFillSignsTheAttestation(t *testing.T) {
	signer := installAttestKey(t)
	s := proxyingServer(t)
	s.loadAttestSigner()
	s.cfg.PublicURL = "https://bodega.example"
	tarball := "/minimist/-/minimist-1.2.8.tgz"
	up := newRecordingUpstream(t)
	up.route(tarball, "tarball bytes")
	s.cfg.NpmUpstream = up.ts.URL

	rec := doRequest(s, http.MethodGet, "/npm"+tarball, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fill = %d %s", rec.Code, rec.Body.String())
	}
	key := manifest.NpmTarballKey("minimist", "1.2.8")
	if got := envelopesFor(t, s.typeStore(manifest.TypeNpm), key); len(got) != 1 {
		t.Fatalf("envelopes beside %s = %v, want 1", key, got)
	}

	status, body := getStatusAndBody(t, s, "/api/v1/packages/npm/minimist/1.2.8/attestation")
	if status != http.StatusOK {
		t.Fatalf("attestation route = %d %s", status, body)
	}
	env, st, err := attest.ParseEnvelope([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("tarball bytes"))
	for _, r := range attest.Verify(env, st, attest.VerifyInput{
		Trusted: trustedBy(t, signer), ArtifactSHA256: hex.EncodeToString(sum[:]), WantPURL: "pkg:npm/minimist@1.2.8",
	}) {
		if !r.OK {
			t.Errorf("%s: expected %s, observed %s", r.Check, r.Expected, r.Observed)
		}
	}
	if id := st.Predicate.IngestionPlatform.ID; id != "https://bodega.example" && !strings.HasPrefix(id, "bodega://") {
		t.Errorf("ingestionPlatform.id = %q", id)
	}
	if st.Predicate.PolicyEvaluations.PolicyDigest["sha256"] == "" {
		t.Errorf("policy digest missing: %+v", st.Predicate.PolicyEvaluations)
	}
}

// Bodega's own envelope wins over attestation_uri, and ?source=upstream goes
// straight to attestation_uri.
func TestAttestationRouteServesOwnFirst(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "sample", manifest.VersionEntry{
		Version:  "1.0.0",
		Metadata: map[string]string{MetaAttestationURI: "https://attest.example.com/sample.dsse.json"},
	})
	route := "/api/v1/packages/npm/sample/1.0.0/attestation"

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) (int, string) {
		ts := httptest.NewServer(s.Handler())
		t.Cleanup(ts.Close)
		resp, err := noFollow.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if status, _ := get(route); status != http.StatusFound {
		t.Fatalf("with no own envelope: %d, want the 302 passthrough", status)
	}

	key := manifest.NpmTarballKey("sample", "1.0.0")
	st := s.typeStore(manifest.TypeNpm)
	older := manifest.AttestationDir(key) + "20260101T000000.000000000Z" + manifest.AttestationExt
	newer := manifest.AttestationDir(key) + "20260201T000000.000000000Z" + manifest.AttestationExt
	_ = st.Put(t.Context(), older, []byte(`{"which":"older"}`))
	_ = st.Put(t.Context(), newer, []byte(`{"which":"newer"}`))

	if status, body := get(route); status != http.StatusOK || !strings.Contains(body, "newer") {
		t.Errorf("own envelope: %d %q, want 200 with the newest", status, body)
	}
	if status, _ := get(route + "?source=upstream"); status != http.StatusFound {
		t.Errorf("?source=upstream: %d, want 302", status)
	}
}

// A sink with no admissions table turns attestations off with one WARN at
// startup, and a pin under it writes nothing and logs no ERROR.
func TestAttestationsOffUnderWriteOnlySink(t *testing.T) {
	installAttestKey(t)
	dir := t.TempDir()
	var buf syncBuffer
	cfg := &config.Config{
		AptCodename: "noble", LogDir: dir, AuditDB: filepath.Join(dir, "audit.db"), StoragePath: dir,
		AuditSink: audit.SinkJSONL, AuditSinkDSN: filepath.Join(dir, "audit.jsonl"), AllowPlaintext: true,
	}
	mem := storage.NewMemory()
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(mem), "127.0.0.1:0",
		slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { _ = s.auditDB.Close() })

	key := manifest.NpmTarballKey("x", "1.0.0")
	for range 3 {
		s.pinAdmission(t.Context(), mem, manifest.TypeNpm, "x", "1.0.0", key, strings.Repeat("a", 64))
	}
	if n := strings.Count(buf.String(), "attestations are off"); n != 1 {
		t.Errorf("attestations-off WARN logged %d times, want 1:\n%s", n, buf.String())
	}
	if strings.Contains(buf.String(), "attestation not signed") {
		t.Errorf("an unverifiable pin logged a refusal:\n%s", buf.String())
	}
	if got := envelopesFor(t, mem, key); len(got) != 0 {
		t.Errorf("wrote %v under a write-only sink", got)
	}
}

// A pin whose newest decision is a block is refused at ERROR, and the
// envelope signed under the earlier admission is all that stays.
func TestProxyPinRefusalLogsError(t *testing.T) {
	installAttestKey(t)
	s := proxyingServer(t)
	s.loadAttestSigner()
	var buf syncBuffer
	s.logger = slog.New(slog.NewTextHandler(&buf, nil))
	ctx := t.Context()
	record := func(decision, status string) {
		t.Helper()
		if err := s.auditDB.RecordAdmission(ctx, audit.Admission{PkgType: manifest.TypeNpm, PkgName: "x", PkgVersion: "1.0.0",
			Decision: decision, Checks: []audit.AdmissionCheck{{Check: audit.CheckOSV, Action: "block", Status: status}}}); err != nil {
			t.Fatal(err)
		}
	}
	st := s.typeStore(manifest.TypeNpm)
	key := manifest.NpmTarballKey("x", "1.0.0")
	digest := strings.Repeat("a", 64)

	record(audit.AdmissionAdmitted, audit.CheckPass)
	s.pinAdmission(ctx, st, manifest.TypeNpm, "x", "1.0.0", key, digest)
	if got := envelopesFor(t, st, key); len(got) != 1 {
		t.Fatalf("admitted pin wrote %v, want one envelope", got)
	}
	time.Sleep(2 * time.Millisecond)
	record(audit.AdmissionPolicyBlocked, audit.CheckBlock)
	s.pinAdmission(ctx, st, manifest.TypeNpm, "x", "1.0.0", key, digest)

	if !strings.Contains(buf.String(), "level=ERROR") || !strings.Contains(buf.String(), "attestation not signed") {
		t.Errorf("refusal not logged at ERROR:\n%s", buf.String())
	}
	if got := envelopesFor(t, st, key); len(got) != 1 {
		t.Errorf("a refused pin left %v, want the one earlier envelope", got)
	}
}
