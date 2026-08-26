package server_test

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/aptsign"
)

// signedTestServer installs a throwaway signing key where the server searches
// first, then builds the standard test server around it. The key is generated
// per run: a checked-in private key is a private key, whatever the README next
// to it says.
func signedTestServer(t *testing.T, keys int) (*httptest.Server, *aptsign.KeyRing) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)

	kr, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for i := 1; i < keys; i++ {
		extra, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		kr.Add(extra)
	}
	if err := kr.WritePrivate(filepath.Join(dir, aptsign.KeyFileName)); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}

	ts, _ := newTestServer(t)
	return ts, kr
}

// TestInReleaseWrapsReleaseUnchanged is the property apt depends on: the
// clearsigned document and the unsigned one are the same bytes, so a client
// that verifies and a client that does not read the same index.
func TestInReleaseWrapsReleaseUnchanged(t *testing.T) {
	ts, kr := signedTestServer(t, 1)

	status, release := aptGet(t, ts, "/apt/dists/noble/Release")
	if status != http.StatusOK {
		t.Fatalf("GET Release status = %d, want 200", status)
	}
	status, inRelease := aptGet(t, ts, "/apt/dists/noble/InRelease")
	if status != http.StatusOK {
		t.Fatalf("GET InRelease status = %d, want 200 with a key installed", status)
	}
	if !strings.HasPrefix(inRelease, "-----BEGIN PGP SIGNED MESSAGE-----") {
		t.Fatalf("InRelease does not open with the clearsign header:\n%s", inRelease)
	}

	block, _ := clearsign.Decode([]byte(inRelease))
	if block == nil {
		t.Fatal("InRelease does not decode as a clearsigned document")
	}
	if string(block.Plaintext) != release {
		t.Errorf("InRelease body != Release\n got: %q\nwant: %q", block.Plaintext, release)
	}
	if _, err := openpgp.CheckDetachedSignature(publicKeyRing(t, kr), bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		t.Errorf("InRelease signature does not verify: %v", err)
	}
}

func TestReleaseGPGVerifiesAgainstServedKey(t *testing.T) {
	ts, _ := signedTestServer(t, 1)

	_, release := aptGet(t, ts, "/apt/dists/noble/Release")
	status, sig := aptGet(t, ts, "/apt/dists/noble/Release.gpg")
	if status != http.StatusOK {
		t.Fatalf("GET Release.gpg status = %d, want 200 with a key installed", status)
	}

	// Verify against the key the *server* publishes, not the one the test
	// generated: a signature that only verifies against the test's own copy
	// proves nothing about what a client can fetch.
	status, armored := aptGet(t, ts, "/apt/bodega-archive-keyring.asc")
	if status != http.StatusOK {
		t.Fatalf("GET bodega-archive-keyring.asc status = %d, want 200", status)
	}
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		t.Fatalf("served armored key does not parse: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(el, strings.NewReader(release), strings.NewReader(sig), nil); err != nil {
		t.Errorf("Release.gpg does not verify against the served public key: %v", err)
	}
}

// TestKeyringRouteIsDearmored covers the reason the .gpg route exists: a client
// pointing signed-by= at it needs no gpg binary to dearmor anything.
func TestKeyringRouteIsDearmored(t *testing.T) {
	ts, kr := signedTestServer(t, 1)

	status, body := aptGet(t, ts, "/apt/bodega-archive-keyring.gpg")
	if status != http.StatusOK {
		t.Fatalf("GET bodega-archive-keyring.gpg status = %d, want 200", status)
	}
	if strings.Contains(body, "-----BEGIN") {
		t.Fatal("keyring route served armored bytes; signed-by= would reject them")
	}
	el, err := openpgp.ReadKeyRing(strings.NewReader(body))
	if err != nil {
		t.Fatalf("served keyring does not parse: %v", err)
	}
	if len(el) != 1 {
		t.Fatalf("keyring holds %d keys, want 1", len(el))
	}
	if got := fingerprintOf(el[0]); got != kr.Fingerprints()[0] {
		t.Errorf("served fingerprint = %s, want %s", got, kr.Fingerprints()[0])
	}
}

// TestRotationWindowVerifiesUnderEitherKey is the whole point of dual-signing:
// a client that has only the outgoing keyring and a client that has only the
// incoming one both pass, so the switch never breaks an un-updated client.
func TestRotationWindowVerifiesUnderEitherKey(t *testing.T) {
	ts, kr := signedTestServer(t, 2)
	if kr.Len() != 2 {
		t.Fatalf("test key ring holds %d keys, want 2", kr.Len())
	}

	_, release := aptGet(t, ts, "/apt/dists/noble/Release")
	_, sig := aptGet(t, ts, "/apt/dists/noble/Release.gpg")

	status, served := aptGet(t, ts, "/apt/bodega-archive-keyring.gpg")
	if status != http.StatusOK {
		t.Fatalf("GET bodega-archive-keyring.gpg status = %d, want 200", status)
	}
	all, err := openpgp.ReadKeyRing(strings.NewReader(served))
	if err != nil {
		t.Fatalf("served keyring does not parse: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("served keyring holds %d keys, want both", len(all))
	}

	for i, e := range all {
		alone := openpgp.EntityList{e}
		if _, err := openpgp.CheckArmoredDetachedSignature(alone, strings.NewReader(release), strings.NewReader(sig), nil); err != nil {
			t.Errorf("key %d (%s) alone does not verify Release.gpg: %v", i, fingerprintOf(e), err)
		}
	}
}

// TestSignedRoutesAbsentWithoutKey pins the non-breaking rule: with no key the
// signature-bearing routes 404 and the unsigned Release still serves, which is
// the ordinary fallback path apt has always taken.
func TestSignedRoutesAbsentWithoutKey(t *testing.T) {
	t.Setenv(aptsign.CredentialsEnv, t.TempDir())
	ts, _ := newTestServer(t)

	for _, path := range []string{
		"/apt/dists/noble/InRelease",
		"/apt/dists/noble/Release.gpg",
		"/apt/bodega-archive-keyring.asc",
		"/apt/bodega-archive-keyring.gpg",
		"/apt/gpg-key.asc",
	} {
		if status, _ := aptGet(t, ts, path); status != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 with no key installed", path, status)
		}
	}
	if status, _ := aptGet(t, ts, "/apt/dists/noble/Release"); status != http.StatusOK {
		t.Errorf("GET Release status = %d, want 200 — signing must not remove the unsigned document", status)
	}
}

// TestUnusableKeyLeavesRepositoryServing covers the operator who installs a key
// with the wrong permissions. Serving the repository unsigned beats refusing to
// serve it: the fault is in the journal, and clients that were working keep
// working.
func TestUnusableKeyLeavesRepositoryServing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)
	if err := os.WriteFile(filepath.Join(dir, aptsign.KeyFileName), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ts, _ := newTestServer(t)
	if status, _ := aptGet(t, ts, "/apt/dists/noble/Release"); status != http.StatusOK {
		t.Errorf("GET Release status = %d, want 200 despite the broken key", status)
	}
	if status, _ := aptGet(t, ts, "/apt/dists/noble/InRelease"); status != http.StatusNotFound {
		t.Errorf("GET InRelease status = %d, want 404 — a broken key is not a signature", status)
	}
}

func publicKeyRing(t *testing.T, kr *aptsign.KeyRing) openpgp.EntityList {
	t.Helper()
	pub, err := kr.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	return el
}

func fingerprintOf(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}
