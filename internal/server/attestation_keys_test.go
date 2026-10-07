package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/attestsign"
)

// pinAttestKeyPath points the whole search order at one temp file: no
// credential directory, the system path in a temp dir, and the test server's
// storage_path holding nothing.
func pinAttestKeyPath(t *testing.T) string {
	t.Helper()
	t.Setenv(attestsign.CredentialsEnv, "")
	path := filepath.Join(t.TempDir(), attestsign.KeyFileName)
	prev := attestsign.SystemKeyPath
	attestsign.SystemKeyPath = path
	t.Cleanup(func() { attestsign.SystemKeyPath = prev })
	return path
}

func getAttestationKeys(t *testing.T, s *Server) []attestationKey {
	t.Helper()
	status, body := getStatusAndBody(t, s, "/api/v1/attestation/keys")
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/attestation/keys = %d: %s", status, body)
	}
	var keys []attestationKey
	if err := json.Unmarshal([]byte(body), &keys); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return keys
}

func TestAttestationKeysEmptyAndWarnedOnce(t *testing.T) {
	pinAttestKeyPath(t)
	s := hostedServer(t)
	var buf syncBuffer
	s.logger = slog.New(slog.NewTextHandler(&buf, nil))
	s.attestNoKeyWarned.Store(false)

	s.loadAttestSigner()
	s.loadAttestSigner()
	if n := strings.Count(buf.String(), "no attestation signing key installed"); n != 1 {
		t.Errorf("no-key WARN logged %d times across two loads, want 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("no-key message is not at WARN:\n%s", buf.String())
	}
	if keys := getAttestationKeys(t, s); len(keys) != 0 {
		t.Errorf("with no key the route lists %+v, want []", keys)
	}
}

// Two keys loaded: the newest signs and both are published, and the route
// reports the retired one as retired once it is.
func TestAttestationKeysRotationPublishesBoth(t *testing.T) {
	path := pinAttestKeyPath(t)
	ring, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldID, newID := ring.Signer().KeyID(), incoming.Signer().KeyID()
	ring.Add(incoming)
	if err := ring.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	s := hostedServer(t)

	if got := s.attestSign.Load().signer.KeyID(); got != newID {
		t.Errorf("server signs with %s, want the newest key %s", got, newID)
	}
	keys := getAttestationKeys(t, s)
	if len(keys) != 2 || keys[0].KeyID != oldID || keys[1].KeyID != newID {
		t.Fatalf("route lists %+v, want both keys", keys)
	}
	for _, k := range keys {
		if k.Alg != "ed25519" || !strings.HasPrefix(k.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") || k.CreatedAt == nil || k.Retired {
			t.Errorf("key %+v is not a published, active ed25519 key with a creation time", k)
		}
	}

	if _, err := ring.Retire(oldID); err != nil {
		t.Fatal(err)
	}
	if err := ring.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	s.loadAttestSigner()
	keys = getAttestationKeys(t, s)
	if len(keys) != 2 || !keys[0].Retired || keys[1].Retired {
		t.Errorf("after retire and reload the route lists %+v, want the old key retired and still listed", keys)
	}
}

// A reload that fails keeps the loaded signer and its published set, and the
// journal names the file and why.
func TestAttestationReloadFailureKeepsSigner(t *testing.T) {
	path := pinAttestKeyPath(t)
	ring, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	s := hostedServer(t)
	want := ring.Signer().KeyID()
	logged := captureErrorLog(s)

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	s.loadAttestSigner()
	if got := s.attestSign.Load(); got == nil || got.signer.KeyID() != want {
		t.Fatalf("a failed reload replaced the signer: %+v", got)
	}
	if msg := logged(); !strings.Contains(msg, path) || !strings.Contains(msg, "readable beyond its owner") {
		t.Errorf("the logged failure does not name the file and the reason: %q", msg)
	}
	if keys := getAttestationKeys(t, s); len(keys) != 1 || keys[0].KeyID != want {
		t.Errorf("after a failed reload the route lists %+v, want the old key", keys)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s.loadAttestSigner()
	if got := s.attestSign.Load(); got == nil || got.signer.KeyID() != want {
		t.Fatalf("a reload with the key gone dropped the signer: %+v", got)
	}

	// A good key on the next reload replaces it.
	fresh, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	s.loadAttestSigner()
	if got := s.attestSign.Load().signer.KeyID(); got != fresh.Signer().KeyID() {
		t.Errorf("a successful reload kept %s, want %s", got, fresh.Signer().KeyID())
	}
}
