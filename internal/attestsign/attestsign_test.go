package attestsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRing(t *testing.T, kr *KeyRing) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), KeyFileName)
	if err := kr.WritePrivate(path); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	return path
}

func mustGenerate(t *testing.T) *KeyRing {
	t.Helper()
	kr, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kr
}

func TestGenerateWritesALoadableKey(t *testing.T) {
	kr := mustGenerate(t)
	path := writeRing(t, kr)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("generated key is mode %#o, want 0600", mode)
	}
	got, err := LoadPath(path)
	if err != nil {
		t.Fatalf("LoadPath: %v", err)
	}
	if got.Signer().KeyID() != kr.Signer().KeyID() {
		t.Errorf("loaded key ID %s, generated %s", got.Signer().KeyID(), kr.Signer().KeyID())
	}
	if keys := got.Keys(); len(keys) != 1 || keys[0].Created.IsZero() || !keys[0].Retired.IsZero() {
		t.Errorf("Keys() = %+v, want one active key with a creation time", keys)
	}
}

// The key ID is what a verifier pins, so it has to be computable from the
// public key alone with nothing bodega-specific: SHA-256 over the DER SPKI.
func TestKeyIDIsSHA256OfSPKI(t *testing.T) {
	kr := mustGenerate(t)
	s := kr.Signer()
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if want := hex.EncodeToString(sum[:]); s.KeyID() != want {
		t.Errorf("KeyID = %s, want %s", s.KeyID(), want)
	}
	block, _ := pem.Decode(kr.Keys()[0].PublicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("published key is not a PUBLIC KEY PEM block: %q", kr.Keys()[0].PublicKeyPEM)
	}
	if sum2 := sha256.Sum256(block.Bytes); hex.EncodeToString(sum2[:]) != s.KeyID() {
		t.Error("hashing the published PEM body does not reproduce the key ID")
	}
}

// Sign covers the message bytes as given: a plain ed25519.Verify over the
// same bytes accepts it, and a request for a pre-hash is refused.
func TestSignIsRawEd25519(t *testing.T) {
	s := mustGenerate(t).Signer()
	msg := []byte("DSSEv1 28 application/vnd.in-toto+json 2 {}")
	sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(s.Public().(ed25519.PublicKey), msg, sig) {
		t.Error("signature does not verify over the raw message")
	}
	if _, err := s.Sign(rand.Reader, msg, crypto.SHA256); err == nil {
		t.Error("Sign accepted crypto.SHA256; it must refuse any digest framing")
	}
	if _, err := s.Sign(rand.Reader, msg, &ed25519.Options{Context: "x"}); err == nil {
		t.Error("Sign accepted an Ed25519ctx context string")
	}
}

// An openssl-generated key carries no Created: line, and the file still loads.
func TestLoadsBarePKCS8(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), KeyFileName)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := LoadPath(path)
	if err != nil {
		t.Fatalf("LoadPath: %v", err)
	}
	if !kr.Keys()[0].Created.IsZero() {
		t.Error("a key with no Created: line reported a creation time")
	}
}

func TestLoadRefusals(t *testing.T) {
	ecKey := ecdsaPEM(t)
	cases := map[string]struct {
		body string
		want string
	}{
		"not PEM":   {"hello", "not PEM"},
		"encrypted": {string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})), "passphrase-protected"},
		"ecdsa":     {ecKey, "Ed25519"},
		"rsa label": {string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}})), "RSA PRIVATE KEY"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), KeyFileName)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadPath(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), path) {
				t.Errorf("LoadPath error = %v, want one naming %s and %q", err, path, tc.want)
			}
		})
	}
}

func ecdsaPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// The permission rules are pkgsign's: anything beyond owner is refused, the
// group bit alone is forgiven inside $CREDENTIALS_DIRECTORY, world-readable is
// refused there too, and the message names the chmod.
func TestLoadPermissionRefusals(t *testing.T) {
	creds := t.TempDir()
	t.Setenv(CredentialsEnv, creds)
	elsewhere := t.TempDir()

	cases := []struct {
		name   string
		dir    string
		mode   os.FileMode
		refuse bool
	}{
		{"owner only", elsewhere, 0o600, false},
		{"group readable", elsewhere, 0o640, true},
		{"world readable", elsewhere, 0o604, true},
		{"credential 0440", creds, 0o440, false},
		{"credential world readable", creds, 0o444, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kr := mustGenerate(t)
			path := filepath.Join(tc.dir, KeyFileName)
			if err := kr.WritePrivate(path); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(path) })
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, err := LoadPath(path)
			if !tc.refuse {
				if err != nil {
					t.Fatalf("LoadPath refused mode %#o: %v", tc.mode, err)
				}
				return
			}
			want := "attestation signing key " + path + " is mode "
			if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "chmod 600 "+path) {
				t.Errorf("LoadPath(mode %#o) error = %v, want the pkgsign refusal form", tc.mode, err)
			}
		})
	}
}

func TestLoadSearchOrder(t *testing.T) {
	creds := t.TempDir()
	t.Setenv(CredentialsEnv, creds)
	prev := SystemKeyPath
	SystemKeyPath = filepath.Join(t.TempDir(), KeyFileName)
	t.Cleanup(func() { SystemKeyPath = prev })
	storage := t.TempDir()

	paths := DefaultKeyPaths(storage)
	want := []string{filepath.Join(creds, KeyFileName), SystemKeyPath, filepath.Join(storage, KeyFileName)}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("DefaultKeyPaths = %v, want %v", paths, want)
	}
	if _, err := Load(paths); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Load with no file = %v, want ErrNoKey", err)
	}

	inStorage := mustGenerate(t)
	if err := inStorage.WritePrivate(want[2]); err != nil {
		t.Fatal(err)
	}
	inSystem := mustGenerate(t)
	if err := inSystem.WritePrivate(want[1]); err != nil {
		t.Fatal(err)
	}
	kr, err := Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	if kr.Path() != want[1] || kr.Signer().KeyID() != inSystem.Signer().KeyID() {
		t.Errorf("Load picked %s, want the system path ahead of storage_path", kr.Path())
	}

	// A broken file earlier in the order is an error, not a skip.
	if err := os.Chmod(want[1], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(paths); err == nil || errors.Is(err, ErrNoKey) {
		t.Errorf("Load fell past an unusable key: %v", err)
	}
}

// Rotation: two keys loaded, the newest signs, both are published, and
// retiring the old one keeps its public half published.
func TestRotation(t *testing.T) {
	ring := mustGenerate(t)
	oldID := ring.Signer().KeyID()
	ring.Add(mustGenerate(t))
	newID := ring.Keys()[1].KeyID
	path := writeRing(t, ring)

	kr, err := LoadPath(path)
	if err != nil {
		t.Fatalf("LoadPath with two keys: %v", err)
	}
	if kr.Signer().KeyID() != newID {
		t.Errorf("signer = %s, want the newest key %s", kr.Signer().KeyID(), newID)
	}
	keys := kr.Keys()
	if len(keys) != 2 || keys[0].KeyID != oldID || keys[1].KeyID != newID {
		t.Fatalf("published %+v, want both keys in file order", keys)
	}

	if _, err := kr.Retire(oldID[:MinRetirePrefix-1]); err == nil {
		t.Error("Retire accepted a prefix shorter than MinRetirePrefix")
	}
	got, err := kr.Retire(strings.ToUpper(oldID[:MinRetirePrefix]))
	if err != nil || got != oldID {
		t.Fatalf("Retire = %q, %v; want %s", got, err, oldID)
	}
	if err := kr.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "BEGIN PRIVATE KEY"); n != 1 {
		t.Errorf("file holds %d private keys after retiring one of two, want 1", n)
	}

	kr, err = LoadPath(path)
	if err != nil {
		t.Fatalf("LoadPath after retire: %v", err)
	}
	keys = kr.Keys()
	if len(keys) != 2 || keys[0].Retired.IsZero() || !keys[1].Retired.IsZero() {
		t.Errorf("after retire, published %+v; want the old key retired and still published", keys)
	}
	if keys[0].Created.IsZero() {
		t.Error("retiring a key dropped its creation time")
	}
	if kr.Signer().KeyID() != newID {
		t.Errorf("signer after retire = %s, want %s", kr.Signer().KeyID(), newID)
	}

	if _, err := kr.Retire(oldID); err == nil || !strings.Contains(err.Error(), "already retired") {
		t.Errorf("retiring a retired key = %v, want a refusal", err)
	}
	if _, err := kr.Retire(newID); err == nil || !strings.Contains(err.Error(), "only signing key") {
		t.Errorf("retiring the last signing key = %v, want a refusal", err)
	}
}

// A file whose every key is retired has nothing to sign with; it is a broken
// key, not an absent one.
func TestLoadRefusesAllRetired(t *testing.T) {
	ring := mustGenerate(t)
	ring.Add(mustGenerate(t))
	if _, err := ring.Retire(ring.Keys()[0].KeyID); err != nil {
		t.Fatal(err)
	}
	ring.keys[1].priv = nil
	path := writeRing(t, ring)
	if _, err := LoadPath(path); err == nil || !strings.Contains(err.Error(), "only retired keys") {
		t.Errorf("LoadPath = %v, want a refusal naming retired keys", err)
	}
}
