package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
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

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
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
