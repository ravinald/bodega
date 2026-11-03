package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
	"github.com/ravinald/bodega/internal/storage"
)

// attestInstall writes a config naming a local storage root and an audit
// database under one temp dir, installs an attestation key in the storage
// root, and returns the dir and the key ring.
func attestInstall(t *testing.T) (string, *attestsign.KeyRing) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(attestsign.CredentialsEnv, "")
	prev := attestsign.SystemKeyPath
	attestsign.SystemKeyPath = filepath.Join(dir, "absent", attestsign.KeyFileName)
	t.Cleanup(func() { attestsign.SystemKeyPath = prev })
	storageRoot := filepath.Join(dir, "storage")
	if err := os.MkdirAll(storageRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	ring, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.WritePrivate(filepath.Join(storageRoot, attestsign.KeyFileName)); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "audit_db": %q,
  "log_dir": %q,
  "public_url": "https://bodega.example",
  "allow_plaintext": true,
  "apt_codename": "noble"
}`, storageRoot, filepath.Join(dir, "manifests"), filepath.Join(dir, "audit.db"), dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigFile, path)
	return dir, ring
}

func runAttest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		cmd := newAttestCmd(&globalFlags{})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		err = cmd.Execute()
		fmt.Print(buf.String())
	})
	return out, err
}

// signedFixture signs a statement about npm lodash@<named> over artifact and
// writes the envelope, the artifact and the public key to files.
func signedFixture(t *testing.T, ring *attestsign.KeyRing, named string, artifact []byte) (envFile, artFile, pubFile string) {
	t.Helper()
	dir := t.TempDir()
	sum := sha256.Sum256(artifact)
	key := manifest.NpmTarballKey("lodash", named)
	st := attest.NewStatement(attest.Pin{Type: manifest.TypeNpm, Name: "lodash", Version: named, ObjectKey: key, SHA256: hex.EncodeToString(sum[:])},
		audit.Admission{Decision: audit.AdmissionAdmitted, DecidedAt: time.Now(), PolicyDigest: "sha256:" + strings.Repeat("ab", 32),
			Checks: []audit.AdmissionCheck{{Check: audit.CheckAllowList, Action: "block", Status: audit.CheckPass}}},
		"https://bodega.example", time.Now())
	env, err := attest.Sign(ring.Signer(), st)
	if err != nil {
		t.Fatal(err)
	}
	envFile, artFile, pubFile = filepath.Join(dir, "env.json"), filepath.Join(dir, "lodash.tgz"), filepath.Join(dir, "attest.pub")
	_ = os.WriteFile(envFile, env, 0o600)
	_ = os.WriteFile(artFile, artifact, 0o600)
	_ = os.WriteFile(pubFile, ring.Keys()[0].PublicKeyPEM, 0o600)
	return envFile, artFile, pubFile
}

// writeSignedPayload signs payload with ring and writes the envelope to a file.
func writeSignedPayload(t *testing.T, ring *attestsign.KeyRing, payload string) string {
	t.Helper()
	s := ring.Signer()
	sig, err := s.Sign(rand.Reader, attest.PAE(attest.PayloadType, []byte(payload)), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(attest.Envelope{PayloadType: attest.PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(payload)),
		Signatures: []attest.Signature{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}}})
	path := filepath.Join(t.TempDir(), "env.json")
	if err := os.WriteFile(path, env, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// An envelope signed under the pre-E27 vocabulary verifies and prints its old
// status marked as such; a fresh one prints the draft's vocabulary.
func TestAttestVerifyPreE27Envelope(t *testing.T) {
	_, ring := attestInstall(t)
	id := ring.Signer().KeyID()
	artifact := []byte("lodash tarball")
	_, art, pub := signedFixture(t, ring, "4.17.21", artifact)
	sum := sha256.Sum256(artifact)
	object := `{"status":"mismatch","sourceRepositoryUri":"https://github.com/lodash/lodash","builderId":"https://github.com/actions/runner/github-hosted"}`
	payload := `{"_type":"` + attest.StatementType + `","subject":[{"name":"pkg:npm/lodash@4.17.21","digest":{"sha256":"` + hex.EncodeToString(sum[:]) + `"}}],` +
		`"predicateType":"` + attest.PredicateType + `","predicate":{"ingestionPlatform":{"id":"https://bodega.example"},` +
		`"ingestedAt":"2026-10-10T12:00:00Z","policyEvaluations":{"policyDigest":{},"decision":"admitted","decidedAt":"2026-10-10T12:00:00Z",` +
		`"evaluations":[{"check":"allowlist","action":"none","status":"pass"}]},` +
		`"upstreamProvenance":` + object + `,"publisherSignature":` + object + `}}`
	legacy := writeSignedPayload(t, ring, payload)

	out, err := runAttest(t, "verify", legacy, "--package", "npm/lodash/4.17.21", "--artifact", art, "--public-key", pub, "--key", id)
	if err != nil {
		t.Fatalf("pre-E27 envelope: %v\n%s", err, out)
	}
	for _, c := range []string{attest.CheckSignature, attest.CheckPredicateType, attest.CheckSubjectDigest, attest.CheckSubjectName, attest.CheckPolicy} {
		if !strings.Contains(out, fmt.Sprintf("ok    %-15s", c)) {
			t.Errorf("pre-E27 envelope: no ok line for %s\n%s", c, out)
		}
	}
	if !strings.Contains(out, "info  upstream-provenance mismatch (pre-E27 vocabulary, draft of 2026-10-05)") {
		t.Errorf("pre-E27 envelope: legacy status not marked\n%s", out)
	}

	key := manifest.NpmTarballKey("lodash", "4.17.21")
	st := attest.NewStatement(attest.Pin{Type: manifest.TypeNpm, Name: "lodash", Version: "4.17.21", ObjectKey: key, SHA256: hex.EncodeToString(sum[:])},
		audit.Admission{Decision: audit.AdmissionAdmitted, DecidedAt: time.Now(), Checks: []audit.AdmissionCheck{
			{Check: audit.CheckAllowList, Action: "block", Status: audit.CheckPass},
			{Check: audit.CheckUpstreamProvenance, Action: "warn", Status: audit.CheckPass, Provenance: &audit.UpstreamProvenance{
				Outcome: audit.ProvenanceVerified, SourceRepositoryURI: "https://github.com/lodash/lodash"}},
		}}, "https://bodega.example", time.Now())
	env, err := attest.Sign(ring.Signer(), st)
	if err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(t.TempDir(), "fresh.json")
	_ = os.WriteFile(fresh, env, 0o600)
	out, err = runAttest(t, "verify", fresh, "--package", "npm/lodash/4.17.21", "--artifact", art, "--public-key", pub, "--key", id)
	if err != nil {
		t.Fatalf("fresh envelope: %v\n%s", err, out)
	}
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "info  upstream-provenance") {
			line = l
		}
	}
	if line != "info  upstream-provenance verified" || strings.Contains(out, "pre-E27") {
		t.Errorf("fresh envelope: upstream-provenance line %q\n%s", line, out)
	}
}

func TestAttestVerifyFile(t *testing.T) {
	_, ring := attestInstall(t)
	id := ring.Signer().KeyID()
	artifact := []byte("lodash tarball")
	env, art, pub := signedFixture(t, ring, "4.17.21", artifact)
	base := []string{"verify", env, "--package", "npm/lodash/4.17.21", "--public-key", pub}

	if out, err := runAttest(t, append(base, "--artifact", art, "--key", id)...); err != nil {
		t.Fatalf("good envelope: %v\n%s", err, out)
	}

	changed := filepath.Join(t.TempDir(), "changed.tgz")
	_ = os.WriteFile(changed, append([]byte("L"), artifact[1:]...), 0o600)
	out, err := runAttest(t, append(base, "--artifact", changed, "--key", id)...)
	if err == nil || !strings.Contains(out, "FAIL  subject-digest") {
		t.Errorf("changed artifact byte: %v\n%s", err, out)
	}

	otherEnv, _, _ := signedFixture(t, ring, "4.17.20", artifact)
	out, err = runAttest(t, "verify", otherEnv, "--package", "npm/lodash/4.17.21", "--public-key", pub, "--artifact", art, "--key", id)
	if err == nil || !strings.Contains(out, "FAIL  subject-name") || !strings.Contains(out, "pkg:npm/lodash@4.17.20") {
		t.Errorf("changed subject name: %v\n%s", err, out)
	}

	other, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	otherPub := filepath.Join(t.TempDir(), "other.pub")
	_ = os.WriteFile(otherPub, other.Keys()[0].PublicKeyPEM, 0o600)
	out, err = runAttest(t, "verify", env, "--package", "npm/lodash/4.17.21", "--public-key", otherPub, "--artifact", art, "--key", other.Signer().KeyID())
	if err == nil || !strings.Contains(out, "FAIL  signature") || !strings.Contains(out, "untrusted key "+id) {
		t.Errorf("wrong key: %v\n%s", err, out)
	}

	if out, err := runAttest(t, "verify", env, "--artifact", art, "--key", id); err == nil || !strings.Contains(err.Error(), "--package") {
		t.Errorf("an envelope file with no --package: %v\n%s", err, out)
	}
}

// type/name/version fetches the envelope, the keys and the bytes from the
// server, and a server handing out the key a client did not pin is caught.
func TestAttestVerifyFromServer(t *testing.T) {
	_, ring := attestInstall(t)
	artifact := []byte("lodash tarball")
	envFile, _, _ := signedFixture(t, ring, "4.17.21", artifact)
	env, _ := os.ReadFile(envFile)
	keys, _ := json.Marshal([]map[string]string{{"public_key_pem": string(ring.Keys()[0].PublicKeyPEM)}})
	served := artifact
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/packages/npm/lodash/4.17.21/attestation":
			_, _ = w.Write(env)
		case "/api/v1/attestation/keys":
			_, _ = w.Write(keys)
		case "/npm/lodash/-/lodash-4.17.21.tgz":
			_, _ = w.Write(served)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	if out, err := runAttest(t, "verify", "npm/lodash/4.17.21", "--server", ts.URL, "--key", ring.Signer().KeyID()); err != nil {
		t.Fatalf("verify from server: %v\n%s", err, out)
	}
	served = []byte("swapped tarball")
	if out, err := runAttest(t, "verify", "npm/lodash/4.17.21", "--server", ts.URL, "--key", ring.Signer().KeyID()); err == nil || !strings.Contains(out, "FAIL  subject-digest") {
		t.Errorf("server serving other bytes: %v\n%s", err, out)
	}
	if out, err := runAttest(t, "verify", "npm/lodash/4.17.21", "--server", ts.URL, "--key", strings.Repeat("0", 64)); err == nil || !strings.Contains(out, "FAIL  signature") {
		t.Errorf("unpinned key: %v\n%s", err, out)
	}
}

// backfill signs an object pinned before attestations existed, as
// not_evaluated when no admission covers it, and a second run signs nothing.
func TestAttestBackfill(t *testing.T) {
	dir, ring := attestInstall(t)
	key := manifest.NpmTarballKey("lodash", "4.17.21")
	artifact := []byte("lodash tarball")
	sum := sha256.Sum256(artifact)
	st := storage.NewLocal(filepath.Join(dir, "storage"))
	if err := st.Put(t.Context(), key, artifact); err != nil {
		t.Fatal(err)
	}
	adb, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := adb.StoreChecksum(t.Context(), key, manifest.TypeNpm, "lodash", "4.17.21", "sha256", hex.EncodeToString(sum[:]), "computed"); err != nil {
		t.Fatal(err)
	}
	_ = adb.Close()

	out, err := runAttest(t, "backfill")
	if err != nil || !strings.Contains(out, "Signed 1") || !strings.Contains(out, "not_evaluated") {
		t.Fatalf("backfill: %v\n%s", err, out)
	}
	envKey, err := attest.Newest(t.Context(), st, []string{key})
	if err != nil || envKey == "" {
		t.Fatalf("no envelope after backfill: %q %v", envKey, err)
	}
	data, _ := st.Get(t.Context(), envKey)
	env, stmt, err := attest.ParseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range stmt.Predicate.PolicyEvaluations.Evaluations {
		if e.Status != audit.CheckNotEvaluated {
			t.Errorf("backfilled evaluation %+v, want not_evaluated", e)
		}
	}
	for _, r := range attest.Verify(env, stmt, attest.VerifyInput{
		Trusted:        trustedKeys(t, ring),
		ArtifactSHA256: hex.EncodeToString(sum[:]),
		WantPURL:       "pkg:npm/lodash@4.17.21",
	}) {
		if !r.OK {
			t.Errorf("%s: expected %s, observed %s", r.Check, r.Expected, r.Observed)
		}
	}

	out, err = runAttest(t, "backfill", "--type", manifest.TypeNpm)
	if err != nil || !strings.Contains(out, "Signed 0, already attested 1") {
		t.Errorf("second backfill: %v\n%s", err, out)
	}
}

func trustedKeys(t *testing.T, ring *attestsign.KeyRing) map[string]ed25519.PublicKey {
	t.Helper()
	pub, err := attest.ParsePublicKeyPEM(ring.Keys()[0].PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]ed25519.PublicKey{ring.Signer().KeyID(): pub}
}

// The composer dist key carries no archive type, so the route is rebuilt as a
// zip; a branch version's "/" stays inside one escaped segment.
func TestServedPathComposer(t *testing.T) {
	for _, c := range []struct {
		name, version, key, want, wantErr string
	}{
		{"symfony/console", "v7.1.5", manifest.ComposerDistKey("symfony/console", "v7.1.5", "abc123"),
			"/composer/dist/symfony/console/v7.1.5/abc123.zip", ""},
		{"acme/widget", "dev-feature/x", manifest.ComposerDistKey("acme/widget", "dev-feature/x", "def456"),
			"/composer/dist/acme/widget/dev-feature%2Fx/def456.zip", ""},
		{"symfony/console", "v7.1.5", manifest.NpmTarballKey("lodash", "4.17.21"), "", "--artifact"},
		{"symfony/console", "v7.1.5", manifest.ComposerDistKey("symfony/console", "v7.1.5", ""), "", "--artifact"},
	} {
		got, err := servedPath(manifest.TypeComposer, c.name, c.version, c.key)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), c.key) ||
				!strings.Contains(err.Error(), manifest.TypeComposer) {
				t.Errorf("servedPath(%q) = %q, %v; want an error naming composer, the key and %s", c.key, got, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("servedPath(%q) = %q, %v; want %q", c.key, got, err, c.want)
		}
	}
}

// An oci manifest is fetched at the repository its key names and a blob at
// the one the statement names, each with the registry in the first segment.
func TestServedPathOCI(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	for _, c := range []struct {
		name, key, want, wantErr string
	}{
		{"docker.io/library/nginx", manifest.OCIManifestKey("docker.io", "library/nginx", d),
			"/v2/docker.io/library/nginx/manifests/" + d, ""},
		{"ghcr.io/acme/tools/app", manifest.OCIManifestKey("ghcr.io", "acme/tools/app", d),
			"/v2/ghcr.io/acme/tools/app/manifests/" + d, ""},
		{"quay.io/prometheus/node-exporter", manifest.OCIBlobKey(d),
			"/v2/quay.io/prometheus/node-exporter/blobs/" + d, ""},
		{"docker.io/library/nginx", manifest.OCIBlobKey(d),
			"/v2/docker.io/library/nginx/blobs/" + d, ""},
		{"nginx", manifest.OCIBlobKey(d), "", "--artifact"},
		{"docker.io/library/nginx", manifest.OCITagKey("docker.io", "library/nginx", "1.27"), "", "--artifact"},
		{"docker.io/library/nginx", manifest.NpmTarballKey("lodash", "4.17.21"), "", "--artifact"},
	} {
		got, err := servedPath(manifest.TypeOCI, c.name, d, c.key)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), c.key) {
				t.Errorf("servedPath(%q, %q) = %q, %v; want an error naming the key and %s", c.name, c.key, got, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("servedPath(%q, %q) = %q, %v; want %q", c.name, c.key, got, err, c.want)
		}
	}
}

// An oci statement verifies against the manifest the server serves at the
// rebuilt /v2/ route, the registry carried in its first segment.
func TestAttestVerifyOCIFromServer(t *testing.T) {
	_, ring := attestInstall(t)
	artifact := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	sum := sha256.Sum256(artifact)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	st := attest.NewStatement(attest.Pin{Type: manifest.TypeOCI, Name: "ghcr.io/acme/app", Version: digest,
		ObjectKey: manifest.OCIManifestKey("ghcr.io", "acme/app", digest), SHA256: hex.EncodeToString(sum[:])},
		audit.Admission{Decision: audit.AdmissionAdmitted, DecidedAt: time.Now(), PolicyDigest: "sha256:" + strings.Repeat("ab", 32)},
		"https://bodega.example", time.Now())
	env, err := attest.Sign(ring.Signer(), st)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal([]map[string]string{{"public_key_pem": string(ring.Keys()[0].PublicKeyPEM)}})
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/attestation"):
			_, _ = w.Write(env)
		case r.URL.Path == "/api/v1/attestation/keys":
			_, _ = w.Write(keys)
		case r.URL.Path == "/v2/ghcr.io/acme/app/manifests/"+digest:
			_, _ = w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	out, err := runAttest(t, "verify", "oci/ghcr.io/acme/app/"+digest, "--server", ts.URL, "--key", ring.Signer().KeyID())
	if err != nil {
		t.Fatalf("verify oci from server: %v\n%s\nrequested %q", err, out, paths)
	}
	if !strings.Contains(out, "ok    subject-digest") {
		t.Errorf("subject-digest did not pass:\n%s", out)
	}
}

// A composer statement verifies by name against the zip at the rebuilt route,
// and a 404 there says the dist may not be a zip and names --artifact.
func TestAttestVerifyComposerFromServer(t *testing.T) {
	_, ring := attestInstall(t)
	artifact := []byte("symfony console zip")
	sum := sha256.Sum256(artifact)
	st := attest.NewStatement(attest.Pin{Type: manifest.TypeComposer, Name: "symfony/console", Version: "v7.1.5",
		ObjectKey: manifest.ComposerDistKey("symfony/console", "v7.1.5", "abc123"), SHA256: hex.EncodeToString(sum[:])},
		audit.Admission{Decision: audit.AdmissionAdmitted, DecidedAt: time.Now(), PolicyDigest: "sha256:" + strings.Repeat("ab", 32)},
		"https://bodega.example", time.Now())
	env, err := attest.Sign(ring.Signer(), st)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal([]map[string]string{{"public_key_pem": string(ring.Keys()[0].PublicKeyPEM)}})
	serveZip := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/packages/composer/symfony/console/v7.1.5/attestation":
			_, _ = w.Write(env)
		case r.URL.Path == "/api/v1/attestation/keys":
			_, _ = w.Write(keys)
		case r.URL.Path == "/composer/dist/symfony/console/v7.1.5/abc123.zip" && serveZip:
			_, _ = w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	out, err := runAttest(t, "verify", "composer/symfony/console/v7.1.5", "--server", ts.URL, "--key", ring.Signer().KeyID())
	if err != nil {
		t.Fatalf("verify composer from server: %v\n%s", err, out)
	}
	for _, check := range []string{"signature", "predicate-type", "subject-digest", "subject-name", "policy"} {
		if !strings.Contains(out, "ok    "+check) {
			t.Errorf("check %s did not pass:\n%s", check, out)
		}
	}

	serveZip = false
	out, err = runAttest(t, "verify", "composer/symfony/console/v7.1.5", "--server", ts.URL, "--key", ring.Signer().KeyID())
	if err == nil {
		t.Fatalf("verify with no zip served passed:\n%s", out)
	}
	for _, want := range []string{"symfony/console", "v7.1.5", "/composer/dist/symfony/console/v7.1.5/abc123.zip", "may not be a zip", "--artifact"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("404 error %q does not name %q", err, want)
		}
	}
}

func TestE27UsageSampleMatchesPrinter(t *testing.T) {
	body, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(body), "After the checks, verify prints")
	if !ok {
		t.Fatal("attestation output documentation missing")
	}
	_, sample, ok := strings.Cut(section, "```text\n")
	if !ok {
		t.Fatal("attestation output sample missing")
	}
	sample, _, ok = strings.Cut(sample, "```")
	if !ok {
		t.Fatal("attestation output sample not closed")
	}
	verdict := attest.Availability{
		Result:              attest.ResultVerified,
		SourceRepositoryURI: "https://github.com/sigstore/sigstore-js",
		WorkflowRef:         "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
		BuilderID:           "https://github.com/actions/runner/github-hosted",
		BundleDigest:        map[string]string{"sha256": "5b0c..."},
	}
	var actual bytes.Buffer
	printAvailability(&actual, "upstream-provenance", verdict)
	printAvailability(&actual, "publisher-signature", verdict)
	if sample != actual.String() {
		t.Errorf("usage sample does not match verified output\nwant:\n%s\ngot:\n%s", actual.String(), sample)
	}
}

func TestE27VerifyHelpNamesTheDraftVocabulary(t *testing.T) {
	t.Setenv(config.EnvConfigFile, filepath.Join(t.TempDir(), "config.json"))
	help := strings.Join(strings.Fields(newAttestVerifyCmd(&globalFlags{}).Long), " ")
	for _, want := range []string{
		"(verified, failed, unverified or not-attempted, or unavailable when the publisher published none)",
		"An envelope signed before E27 prints its old status",
		"marked as the earlier draft's vocabulary",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("verify help does not say %q", want)
		}
	}
}

func TestE27UsageNamesTheDraftVocabulary(t *testing.T) {
	body, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(body), "After the checks, verify prints")
	if !ok {
		t.Fatal("attestation output documentation missing")
	}
	section, _, _ = strings.Cut(section, "\n")
	for _, want := range []string{
		"`verified`, `failed`, `not-attempted` (`unverified` on the `publisher-signature` line), or `unavailable` when the publisher published nothing",
		"An envelope signed before E27",
		"`info  upstream-provenance mismatch (pre-E27 vocabulary, draft of 2026-10-05)`",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("usage.md attestation output does not say %q", want)
		}
	}
}

func TestReviewGomodBackfillCannotUpgradeUncomparedBytes(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	forged := sumdbtest.NewModule(t, honest.Path, honest.Version, "different bytes")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(honest)
	for _, tc := range []struct {
		ext  string
		body []byte
	}{
		{".zip", forged.Zip},
		{".mod", []byte("module example.com/widget\n\nrequire example.com/evil v1.0.0\n")},
	} {
		t.Run(tc.ext, func(t *testing.T) {
			dir, ring := attestInstall(t)
			adb, err := audit.Open(filepath.Join(dir, "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer adb.Close()
			pm := &manifest.PackageManifest{Type: manifest.TypeGomod, Name: honest.Path,
				Versions: []manifest.VersionEntry{{Version: honest.Version}}}
			cfg := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier, GomodNoSumdb: "example.com"}
			first := admit.AdmitAs(t.Context(), nil, adb, cfg, pm, admit.Who{Actor: "alice"})
			if !first.OK() || len(first.Admissions) != 1 {
				t.Fatalf("excluded admission: %+v", first)
			}
			entry := admit.ChecksumDatabaseEntry(first.Admissions[0])
			if entry == nil || entry.ChecksumDatabase.Outcome != audit.ProvenanceUnavailable {
				t.Fatalf("excluded evidence: %+v", entry)
			}
			key := manifest.GomodKey(honest.Path, honest.Version, tc.ext)
			st := storage.NewLocal(filepath.Join(dir, "storage"))
			if err := st.Put(t.Context(), key, tc.body); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(tc.body)
			digest := hex.EncodeToString(sum[:])
			if err := adb.StoreChecksum(t.Context(), key, manifest.TypeGomod, honest.Path, honest.Version, "sha256", digest, "computed"); err != nil {
				t.Fatal(err)
			}
			if _, err := adb.PinAdmission(t.Context(), audit.AdmissionPin{PkgType: manifest.TypeGomod, PkgName: honest.Path, PkgVersion: honest.Version, ObjectKey: key, Admitted: &first.Admissions[0]}); err != nil {
				t.Fatal(err)
			}

			// An import after removing the exclusion verifies the log, but
			// does not fetch or compare the already cached artifact.
			cfg.GomodNoSumdb = ""
			second := admit.AdmitAs(t.Context(), nil, adb, cfg, pm, admit.Who{Actor: "alice"})
			if !second.OK() || len(second.Admissions) != 1 {
				t.Fatalf("verified admission: %+v", second)
			}
			entry = admit.ChecksumDatabaseEntry(second.Admissions[0])
			if entry == nil || entry.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
				t.Fatalf("verified evidence: %+v", entry)
			}

			out, runErr := runAttest(t, "backfill", "--type", manifest.TypeGomod)
			t.Logf("backfill: %v\n%s", runErr, out)
			ek, err := attest.Newest(t.Context(), st, []string{key})
			if err != nil {
				t.Fatal(err)
			}
			if ek == "" {
				return
			}
			raw, err := st.Get(t.Context(), ek)
			if err != nil {
				t.Fatal(err)
			}
			env, statement, err := attest.ParseEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range attest.Verify(env, statement, attest.VerifyInput{
				Trusted: trustedKeys(t, ring), ArtifactSHA256: digest,
				WantPURL: attest.PURL(manifest.TypeGomod, honest.Path, honest.Version, key),
			}) {
				if !check.OK {
					t.Fatalf("invalid envelope for cached bytes: %+v", check)
				}
			}
			for _, evaluation := range statement.Predicate.PolicyEvaluations.Evaluations {
				if evaluation.Check == audit.CheckChecksumDatabase && evaluation.Status == audit.CheckPass && strings.HasPrefix(evaluation.Detail, "verified:") {
					t.Errorf("backfill signed uncompared %s as verified against the honest log: %s", tc.ext, evaluation.Detail)
				}
			}
		})
	}
}

// Backfill signs a cached Go file under a verified admission no fetch bound it
// to only after comparing the stored bytes with the log's hash: bytes that
// match are signed verified, and bytes that do not are refused with both
// hashes named and no envelope written.
func TestGomodBackfillComparesStoredBytesBeforeVerified(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	forged := sumdbtest.NewModule(t, honest.Path, honest.Version, "different bytes")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(honest)
	for _, tc := range []struct {
		name       string
		ext        string
		body       []byte
		want, have string
	}{
		{"zip matches", ".zip", honest.Zip, honest.ZipHash, ""},
		{"mod matches", ".mod", honest.Mod, honest.ModHash, ""},
		{"zip differs", ".zip", forged.Zip, honest.ZipHash, forged.ZipHash},
		{"mod differs", ".mod", []byte("module example.com/widget\n\nrequire example.com/evil v1.0.0\n"), honest.ModHash, "hashes to h1:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := attestInstall(t)
			adb, err := audit.Open(filepath.Join(dir, "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer adb.Close()
			pm := &manifest.PackageManifest{Type: manifest.TypeGomod, Name: honest.Path,
				Versions: []manifest.VersionEntry{{Version: honest.Version}}}
			cfg := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}
			if res := admit.AdmitAs(t.Context(), nil, adb, cfg, pm, admit.Who{Actor: "alice"}); !res.OK() {
				t.Fatalf("admission: %+v", res)
			}
			key := manifest.GomodKey(honest.Path, honest.Version, tc.ext)
			st := storage.NewLocal(filepath.Join(dir, "storage"))
			if err := st.Put(t.Context(), key, tc.body); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(tc.body)
			if err := adb.StoreChecksum(t.Context(), key, manifest.TypeGomod, honest.Path, honest.Version, "sha256", hex.EncodeToString(sum[:]), "computed"); err != nil {
				t.Fatal(err)
			}
			out, runErr := runAttest(t, "backfill", "--type", manifest.TypeGomod)
			ek, err := attest.Newest(t.Context(), st, []string{key})
			if err != nil {
				t.Fatal(err)
			}
			if tc.have != "" {
				if runErr == nil || ek != "" {
					t.Fatalf("differing bytes were signed: err %v, envelope %q\n%s", runErr, ek, out)
				}
				for _, s := range []string{"CHECKSUM DATABASE MISMATCH", tc.want, tc.have} {
					if !strings.Contains(out, s) {
						t.Errorf("refusal does not name %q:\n%s", s, out)
					}
				}
				return
			}
			if runErr != nil || ek == "" {
				t.Fatalf("matching bytes not signed: err %v, envelope %q\n%s", runErr, ek, out)
			}
			raw, err := st.Get(t.Context(), ek)
			if err != nil {
				t.Fatal(err)
			}
			_, statement, err := attest.ParseEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			var detail string
			for _, ev := range statement.Predicate.PolicyEvaluations.Evaluations {
				if ev.Check == audit.CheckChecksumDatabase && ev.Status == audit.CheckPass {
					detail = ev.Detail
				}
			}
			if !strings.HasPrefix(detail, "verified:") || !strings.Contains(detail, tc.want) {
				t.Fatalf("matching bytes signed without the verified evaluation: %q", detail)
			}
		})
	}
}

// A verified row that already names the object proves nothing about the bytes
// stored under it: a second fill of the same key may have cached other bytes
// after the first fill pinned. Backfill compares them anyway.
func TestGomodBackfillComparesBytesUnderARowAlreadyNamingThem(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	forged := sumdbtest.NewModule(t, honest.Path, honest.Version, "different bytes")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(honest)
	for _, tc := range []struct {
		ext  string
		body []byte
	}{
		{".zip", forged.Zip},
		{".mod", []byte("module example.com/widget\n\nrequire example.com/evil v1.0.0\n")},
	} {
		t.Run(tc.ext, func(t *testing.T) {
			dir, _ := attestInstall(t)
			adb, err := audit.Open(filepath.Join(dir, "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer adb.Close()
			pm := &manifest.PackageManifest{Type: manifest.TypeGomod, Name: honest.Path,
				Versions: []manifest.VersionEntry{{Version: honest.Version}}}
			cfg := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}
			if res := admit.AdmitAs(t.Context(), nil, adb, cfg, pm, admit.Who{Actor: "alice"}); !res.OK() {
				t.Fatalf("admission: %+v", res)
			}
			rows, err := adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeGomod, PkgName: honest.Path, PkgVersion: honest.Version})
			if err != nil || len(rows) == 0 {
				t.Fatalf("admissions: %v, %d rows", err, len(rows))
			}
			key := manifest.GomodKey(honest.Path, honest.Version, tc.ext)
			if _, err := adb.PinAdmission(t.Context(), audit.AdmissionPin{PkgType: manifest.TypeGomod, PkgName: honest.Path,
				PkgVersion: honest.Version, ObjectKey: key, Admitted: &rows[0]}); err != nil {
				t.Fatal(err)
			}
			st := storage.NewLocal(filepath.Join(dir, "storage"))
			if err := st.Put(t.Context(), key, tc.body); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(tc.body)
			if err := adb.StoreChecksum(t.Context(), key, manifest.TypeGomod, honest.Path, honest.Version, "sha256", hex.EncodeToString(sum[:]), "computed"); err != nil {
				t.Fatal(err)
			}
			out, runErr := runAttest(t, "backfill", "--type", manifest.TypeGomod)
			ek, err := attest.Newest(t.Context(), st, []string{key})
			if err != nil {
				t.Fatal(err)
			}
			if runErr == nil || ek != "" || !strings.Contains(out, "CHECKSUM DATABASE MISMATCH") {
				t.Fatalf("differing bytes under an already-named verified row were signed: err %v, envelope %q\n%s", runErr, ek, out)
			}
		})
	}
}
