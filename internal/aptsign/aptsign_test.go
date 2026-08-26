package aptsign

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// release is a stand-in for the document the apt index generator signs. The
// trailing newline matters: clearsign canonicalizes line endings, and a body
// that does not end in one comes back with one added.
const release = "Origin: bodega\nSuite: noble\nSHA256:\n abc 12 main/binary-amd64/Packages\n"

func testKey(t *testing.T) *KeyRing {
	t.Helper()
	kr, err := Generate("bodega test", "test@example.invalid", KeyEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kr
}

func TestClearSignBodyMatchesRelease(t *testing.T) {
	kr := testKey(t)
	signed, err := kr.ClearSign([]byte(release))
	if err != nil {
		t.Fatalf("ClearSign: %v", err)
	}
	if !bytes.HasPrefix(signed, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		t.Fatalf("InRelease does not open with the clearsign header:\n%s", signed)
	}
	block, _ := clearsign.Decode(signed)
	if block == nil {
		t.Fatal("clearsign.Decode returned no block")
	}
	if string(block.Plaintext) != release {
		t.Errorf("clearsigned body != Release\n got: %q\nwant: %q", block.Plaintext, release)
	}
	pub, err := kr.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if _, err := openpgp.CheckDetachedSignature(readArmoredPublic(t, pub), bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		t.Errorf("clearsigned signature does not verify: %v", err)
	}
}

func TestDetachSignVerifies(t *testing.T) {
	kr := testKey(t)
	sig, err := kr.DetachSign([]byte(release))
	if err != nil {
		t.Fatalf("DetachSign: %v", err)
	}
	if !bytes.HasPrefix(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Fatalf("Release.gpg is not an armored signature:\n%s", sig)
	}
	pub, err := kr.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(readArmoredPublic(t, pub), strings.NewReader(release), bytes.NewReader(sig), nil); err != nil {
		t.Errorf("detached signature does not verify: %v", err)
	}
}

// TestSignaturesUseSHA512 is the reason DefaultHash is set explicitly: apt's
// gpgv rejects SHA-1 on current releases, and the library default is not a
// property this repository's clients can depend on.
func TestSignaturesUseSHA512(t *testing.T) {
	kr := testKey(t)
	sig, err := kr.DetachSign([]byte(release))
	if err != nil {
		t.Fatalf("DetachSign: %v", err)
	}
	block, err := armor.Decode(bytes.NewReader(sig))
	if err != nil {
		t.Fatalf("armor.Decode: %v", err)
	}
	p, err := packet.Read(block.Body)
	if err != nil {
		t.Fatalf("packet.Read: %v", err)
	}
	s, ok := p.(*packet.Signature)
	if !ok {
		t.Fatalf("first packet is %T, want *packet.Signature", p)
	}
	if s.Hash != crypto.SHA512 {
		t.Errorf("signature hash = %v, want SHA512", s.Hash)
	}
}

// TestDualSignVerifiesUnderEitherKey is the rotation window: apt accepts an
// InRelease when any one signature verifies, so a client holding only the old
// key and a client holding only the new one both pass.
func TestDualSignVerifiesUnderEitherKey(t *testing.T) {
	old := testKey(t)
	incoming := testKey(t)
	both := &KeyRing{entities: append(append(openpgp.EntityList{}, old.entities...), incoming.entities...)}

	signed, err := both.ClearSign([]byte(release))
	if err != nil {
		t.Fatalf("ClearSign: %v", err)
	}
	block, _ := clearsign.Decode(signed)
	if block == nil {
		t.Fatal("clearsign.Decode returned no block")
	}
	var sigs bytes.Buffer
	if _, err := sigs.ReadFrom(block.ArmoredSignature.Body); err != nil {
		t.Fatalf("read signature packets: %v", err)
	}

	for name, kr := range map[string]*KeyRing{"outgoing": old, "incoming": incoming} {
		pub, err := kr.PublicKey()
		if err != nil {
			t.Fatalf("%s PublicKey: %v", name, err)
		}
		if _, err := openpgp.CheckDetachedSignature(readArmoredPublic(t, pub), bytes.NewReader(block.Bytes), bytes.NewReader(sigs.Bytes()), nil); err != nil {
			t.Errorf("%s key alone does not verify the dual-signed InRelease: %v", name, err)
		}
	}

	if len(both.Fingerprints()) != 2 {
		t.Errorf("Fingerprints = %v, want two", both.Fingerprints())
	}
}

func TestRetireRefusesTheLastKey(t *testing.T) {
	kr := testKey(t)
	if err := kr.Retire(kr.Fingerprints()[0]); err == nil {
		t.Fatal("Retire removed the only key; the repository would go unsigned with no warning")
	}
	incoming := testKey(t)
	fp := kr.Fingerprints()[0]
	kr.Add(incoming)
	if err := kr.Retire(fp); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if got := kr.Fingerprints(); len(got) != 1 || got[0] != incoming.Fingerprints()[0] {
		t.Errorf("after Retire: %v, want only the incoming key", got)
	}
}

// TestWriteLoadRoundTripsBothKeys covers the file format a rotation depends
// on: two armored blocks in one file, both read back.
func TestWriteLoadRoundTripsBothKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, KeyFileName)
	kr := testKey(t)
	kr.Add(testKey(t))
	if err := kr.WritePrivate(path); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadPath(path)
	if err != nil {
		t.Fatalf("LoadPath: %v", err)
	}
	if got, want := loaded.Fingerprints(), kr.Fingerprints(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("round-trip fingerprints = %v, want %v", got, want)
	}
}

func TestLoadRefusesWorldReadableKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, KeyFileName)
	if err := testKey(t).WritePrivate(path); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := LoadPath(path)
	if err == nil {
		t.Fatal("LoadPath accepted a 0644 signing key")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error does not name the fix: %v", err)
	}
}

func TestLoadReportsNoKey(t *testing.T) {
	dir := t.TempDir()
	_, err := Load([]string{filepath.Join(dir, "absent")})
	if err == nil || !strings.Contains(err.Error(), "no apt signing key found") {
		t.Fatalf("Load with no key = %v, want ErrNoKey", err)
	}
}

func TestDefaultKeyPathsPrefersCredentials(t *testing.T) {
	t.Setenv(CredentialsEnv, "/run/credentials/bodega.service")
	got := DefaultKeyPaths("/var/lib/bodega")
	want := []string{
		"/run/credentials/bodega.service/" + KeyFileName,
		SystemKeyPath,
		"/var/lib/bodega/" + KeyFileName,
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("DefaultKeyPaths = %v, want %v", got, want)
	}
}

func TestKeyringIsDearmored(t *testing.T) {
	kr := testKey(t)
	raw, err := kr.Keyring()
	if err != nil {
		t.Fatalf("Keyring: %v", err)
	}
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		t.Fatal("Keyring is armored; signed-by= would need a gpg --dearmor on the client")
	}
	el, err := openpgp.ReadKeyRing(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadKeyRing: %v", err)
	}
	if len(el) != 1 || el[0].PrivateKey != nil {
		t.Errorf("keyring holds %d entities (private=%v), want one public key", len(el), el[0].PrivateKey != nil)
	}
}

func readArmoredPublic(t *testing.T, pub []byte) openpgp.EntityList {
	t.Helper()
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	return el
}
