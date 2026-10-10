package builder

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/manifest"
)

// attestKey installs a fresh attestation key where a builder Config built
// over an empty storage_path looks, and returns its signer.
func attestKey(t *testing.T) attestsign.Signer {
	t.Helper()
	t.Setenv(attestsign.CredentialsEnv, "")
	path := filepath.Join(t.TempDir(), attestsign.KeyFileName)
	prev := attestsign.SystemKeyPath
	attestsign.SystemKeyPath = path
	t.Cleanup(func() { attestsign.SystemKeyPath = prev })
	ring, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	return ring.Signer()
}

// The hosted leg: a fetch admitted and pinned leaves a signed envelope in the
// build tree under the key it uploads to, and the upload's path list picks it
// up for the artifact it belongs to.
func TestHostedPinSignsTheAttestation(t *testing.T) {
	signer := attestKey(t)
	c, out := admissionConfig(t, true)
	c.BuildRoot = t.TempDir()
	if err := c.EnforcePolicy(t.Context(), manifest.TypeNpm, "minimist", manifest.VersionEntry{Version: "1.2.8"}); err != nil {
		t.Fatal(err)
	}
	key := manifest.NpmTarballKey("minimist", "1.2.8")
	digest := strings.Repeat("c", 64)
	cs := &manifest.Checksum{Algorithm: "sha256", Value: digest}
	if err := c.pinArtifactDigest(t.Context(), key, manifest.TypeNpm, "minimist", "1.2.8", cs, []string{"widget"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "ERROR") {
		t.Fatalf("pin output: %s", out.String())
	}

	paths := []ArtifactPath{{Local: "/dev/null", ObjectKey: key, Package: "minimist", Version: "1.2.8"}}
	AttachAttestations(c, manifest.TypeNpm, paths)
	if len(paths[0].Attestations) != 1 {
		t.Fatalf("attestations beside %s = %v, want 1", key, paths[0].Attestations)
	}
	local := paths[0].Attestations[0]
	if !strings.HasPrefix(local, filepath.Join(c.BuildRoot, "attestations", "npm")) {
		t.Errorf("envelope at %s, not under the build root's attestation tree", local)
	}
	data, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	env, st, err := attest.ParseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range attest.Verify(env, st, attest.VerifyInput{
		Trusted:        map[string]ed25519.PublicKey{signer.KeyID(): signer.Public().(ed25519.PublicKey)},
		ArtifactSHA256: digest,
		WantPURL:       "pkg:npm/minimist@1.2.8",
	}) {
		if !r.OK {
			t.Errorf("%s: expected %s, observed %s", r.Check, r.Expected, r.Observed)
		}
	}
	if rf := st.Predicate.ResolvedFrom; len(rf) != 1 || rf[0].Name != "widget" {
		t.Errorf("resolvedFrom = %+v, want widget", rf)
	}
	if root := attestationTree(c.BuildRoot); filepath.Base(root)+"/" != manifest.AttestationPrefix {
		t.Errorf("local tree %s does not mirror the key prefix %s", root, manifest.AttestationPrefix)
	}
}

// A builder with no key installed pins as before and signs nothing.
func TestHostedPinWithoutAKeySignsNothing(t *testing.T) {
	t.Setenv(attestsign.CredentialsEnv, "")
	prev := attestsign.SystemKeyPath
	attestsign.SystemKeyPath = filepath.Join(t.TempDir(), "absent.key")
	t.Cleanup(func() { attestsign.SystemKeyPath = prev })
	c, out := admissionConfig(t, true)
	c.BuildRoot = t.TempDir()
	key := manifest.NpmTarballKey("minimist", "1.2.8")
	cs := &manifest.Checksum{Algorithm: "sha256", Value: strings.Repeat("c", 64)}
	if err := c.pinArtifactDigest(t.Context(), key, manifest.TypeNpm, "minimist", "1.2.8", cs, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(attestationTree(c.BuildRoot)); !os.IsNotExist(err) {
		t.Errorf("an attestation tree exists with no key installed: %v", err)
	}
	if strings.Contains(out.String(), "ERROR") || strings.Contains(out.String(), "attest") {
		t.Errorf("no-key pin said something about attestations: %s", out.String())
	}
}
