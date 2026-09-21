package pkgsign_test

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/ravinald/bodega/internal/pkgsign"
)

const catalogue = `{"name":"zsh","version":"5.9_3","repopath":"All/zsh-5.9_3.pkg"}` + "\n"

// A key generated here, signed with, and verified against the public half the
// archive would carry. Both algorithms, because the pairing of hash to signer
// is the thing under test and one algorithm cannot show it.
func TestGeneratedKeySignsAndVerifies(t *testing.T) {
	for _, kt := range []pkgsign.KeyType{pkgsign.KeyRSA, pkgsign.KeyEd25519} {
		t.Run(string(kt), func(t *testing.T) {
			kr := generate(t, kt)
			if kr.Algorithm() != string(kt) {
				t.Errorf("Algorithm() = %q, want %q", kr.Algorithm(), kt)
			}
			pub, err := kr.PublicKey()
			if err != nil {
				t.Fatalf("render the public key: %v", err)
			}
			sig, err := kr.Sign([]byte(catalogue))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := pkgsign.Verify(pub, []byte(catalogue), sig); err != nil {
				t.Fatalf("the signature does not verify against the key that made it: %v", err)
			}
			if err := pkgsign.Verify(pub, []byte(catalogue+"tampered\n"), sig); err == nil {
				t.Error("a signature over one document verified against another")
			}
		})
	}
}

// R8: a catalogue signed with one algorithm does not verify against another.
// The failure this guards is silent on the wire — pkg reports a repository it
// will not read and names the signature, never the key type that produced it.
func TestOneAlgorithmDoesNotVerifyAgainstAnother(t *testing.T) {
	rsaKey := generate(t, pkgsign.KeyRSA)
	edKey := generate(t, pkgsign.KeyEd25519)

	rsaPub, err := rsaKey.PublicKey()
	if err != nil {
		t.Fatalf("render the rsa public key: %v", err)
	}
	edPub, err := edKey.PublicKey()
	if err != nil {
		t.Fatalf("render the eddsa public key: %v", err)
	}
	rsaSig, err := rsaKey.Sign([]byte(catalogue))
	if err != nil {
		t.Fatalf("sign with rsa: %v", err)
	}
	edSig, err := edKey.Sign([]byte(catalogue))
	if err != nil {
		t.Fatalf("sign with eddsa: %v", err)
	}

	if err := pkgsign.Verify(edPub, []byte(catalogue), rsaSig); err == nil {
		t.Error("an rsa signature verified against an eddsa public key")
	}
	if err := pkgsign.Verify(rsaPub, []byte(catalogue), edSig); err == nil {
		t.Error("an eddsa signature verified against an rsa public key")
	}
}

// The hash is the signer's, not the caller's. Checked against the primitive
// rather than against Verify, which would pass on any self-consistent pair:
// pkg's RSA path signs the hex rendering of a SHA-256 with no DigestInfo, and
// its ecc path signs a raw BLAKE2b, so a refactor that unified them on one
// hash would ship signatures no client accepts and no test here would notice.
func TestEachAlgorithmSignsTheHashPkgReads(t *testing.T) {
	t.Run("rsa signs the hex sha256", func(t *testing.T) {
		kr := generate(t, pkgsign.KeyRSA)
		sig, err := kr.Sign([]byte(catalogue))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sum := sha256.Sum256([]byte(catalogue))
		hexed := []byte(hex.EncodeToString(sum[:]))
		pub := rsaPublic(t, kr)
		if err := rsa.VerifyPKCS1v15(pub, 0, hexed, sig); err != nil {
			t.Fatalf("the signature is not PKCS#1 v1.5 over the hex sha256 pkg signs: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, 0, sum[:], sig); err == nil {
			t.Error("the signature verified over the raw sha256; pkg signs the hex rendering of it")
		}
	})

	t.Run("eddsa signs a raw blake2b", func(t *testing.T) {
		kr := generate(t, pkgsign.KeyEd25519)
		sig, err := kr.Sign([]byte(catalogue))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		body, ok := strings.CutPrefix(string(sig), "$PKGSIGN:eddsa$")
		if !ok {
			t.Fatalf("the signature carries no $PKGSIGN:eddsa$ frame, which is what tells a client which verifier to use: %q", sig)
		}
		digest := blake2b.Sum512([]byte(catalogue))
		if !ed25519.Verify(ed25519Public(t, kr), digest[:], []byte(body)) {
			t.Error("the signature is not over a raw blake2b digest, which is what pkg's ecc signer reads")
		}
	})
}

// A key on disk the server would load, and the permissions it refuses. A key
// readable beyond its owner is one you have to assume is copied, and the
// refusal is the whole boundary: there is no passphrase behind it.
func TestLoadRefusesAKeyReadableBeyondItsOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pkgsign.KeyFileName)
	if err := generate(t, pkgsign.KeyEd25519).WritePrivate(path); err != nil {
		t.Fatalf("write the key: %v", err)
	}
	if _, err := pkgsign.LoadPath(path); err != nil {
		t.Fatalf("a freshly written key does not load: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := pkgsign.LoadPath(path)
	if err == nil {
		t.Fatal("a world-readable signing key loaded")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("the refusal does not say how to fix it: %v", err)
	}
}

// No key is not a failure. pkg's own signature_type defaults to NONE, so the
// server has to tell "nothing installed" — serve unsigned — from "installed
// and unusable", which is a configuration fault.
func TestLoadReportsNoKeySeparately(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	if _, err := pkgsign.Load([]string{absent}); !errors.Is(err, pkgsign.ErrNoKey) {
		t.Fatalf("Load over a search order with nothing in it = %v, want ErrNoKey", err)
	}
	if _, err := pkgsign.LoadPath(absent); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadPath on a missing file = %v; Load walks its order on fs.ErrNotExist alone, so anything else stops the search at the first empty path", err)
	}
}

// The search order is the one the CLI writes into and the server reads from.
// A generated key that lands outside it is a key the operator believes is
// installed and the server never finds.
func TestWritablePathsAreSearched(t *testing.T) {
	storage := t.TempDir()
	search := pkgsign.DefaultKeyPaths(storage)
	for _, w := range pkgsign.WritablePaths(storage) {
		if !containsPath(search, w) {
			t.Errorf("%s is writable but not searched", w)
		}
	}
}

func TestRoundTripsThroughDisk(t *testing.T) {
	for _, kt := range []pkgsign.KeyType{pkgsign.KeyRSA, pkgsign.KeyEd25519} {
		t.Run(string(kt), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), pkgsign.KeyFileName)
			fresh := generate(t, kt)
			if err := fresh.WritePrivate(path); err != nil {
				t.Fatalf("write: %v", err)
			}
			loaded, err := pkgsign.LoadPath(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if loaded.Fingerprint() != fresh.Fingerprint() {
				t.Errorf("fingerprint changed across a write and a read: %s then %s", fresh.Fingerprint(), loaded.Fingerprint())
			}
			if loaded.Algorithm() != string(kt) {
				t.Errorf("Algorithm() = %q after a round trip, want %q", loaded.Algorithm(), kt)
			}
			if got := loaded.TrustedFingerprintFile(); !strings.Contains(got, loaded.Fingerprint()) {
				t.Errorf("the trusted fingerprint file does not carry the fingerprint: %q", got)
			}
		})
	}
}

func generate(t *testing.T, kt pkgsign.KeyType) *pkgsign.KeyRing {
	t.Helper()
	kr, err := pkgsign.Generate(kt)
	if err != nil {
		t.Fatalf("generate a %s key: %v", kt, err)
	}
	return kr
}

func rsaPublic(t *testing.T, kr *pkgsign.KeyRing) *rsa.PublicKey {
	t.Helper()
	pub, ok := parsePublic(t, kr).(*rsa.PublicKey)
	if !ok {
		t.Fatalf("the key ring's public half is not RSA")
	}
	return pub
}

func ed25519Public(t *testing.T, kr *pkgsign.KeyRing) ed25519.PublicKey {
	t.Helper()
	pub, ok := parsePublic(t, kr).(ed25519.PublicKey)
	if !ok {
		t.Fatalf("the key ring's public half is not Ed25519")
	}
	return pub
}

func parsePublic(t *testing.T, kr *pkgsign.KeyRing) any {
	t.Helper()
	raw, err := kr.PublicKey()
	if err != nil {
		t.Fatalf("render the public key: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("the public key is not PEM: %q", raw)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse the public key: %v", err)
	}
	return pub
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
