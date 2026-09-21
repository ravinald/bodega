package pkgsign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// Fixtures from pkg 2.8.2 itself, so the encodings here are pinned to the
// implementation that reads them rather than to a reading of its source.
//
// Produced on a Linux host with pkg 2.8.2 built from the 2.8.2 tag:
//
//	pkg key --create -t eddsa ed.key
//	pkg key --public -t eddsa ed.key > ed.pub
//	printf 'hello bodega' | pkg key --sign -t eddsa ed.key > doc.sig
//
// `pkg key --sign` signs the document as given, which is why pkgDoc is the
// message below and not a digest of it; the repository path digests first,
// and TestEdDSASignsTheMessagePkgVerifies covers that separately.
const (
	pkgPubDER = "MF4MA3BrZwIBAQwDZWNjDAhXRUkyNTUxOQEB/wNCAARNi1h2x2UZXDee8mKf3ZkOu+bJPuWBA1yBxlsxhwvjNhgJXVJ1HPvlF5Ql1YP/CiaOBK8jWNWWN69/tIGhUOlO"
	pkgSigDER = "MEQCIB1YBFZHCTIAAdO6H/VtkwXqFAZZKz7PxHoOWDo5yuPlAiAj/V+vu23xlJN+kRy0NBN8tFT303OLzyKLH1ccJyG1Bg=="
	pkgDoc    = "hello bodega"
)

func decodeFixture(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode the fixture: %v", err)
	}
	return b
}

// The WEI25519 affine point in pkg's own key is the Ed25519 public key that
// verifies pkg's own signature.
//
// This is what fixes the sign of edwardsC. Both square roots of -486664 put
// the point on the curve, and the wrong one yields (X, -Y): a valid key for a
// different point, which libecc encodes differently and hashes into every
// signature it makes. Nothing short of a signature from the real signer
// distinguishes them, and getting it backwards ships a repository whose every
// eddsa signature fails with "ecc signature verification failure".
func TestEdDSAReadsAKeyPkgGenerated(t *testing.T) {
	pub, err := parseEdDSAPublicKey(decodeFixture(t, pkgPubDER))
	if err != nil {
		t.Fatalf("read pkg's own public key: %v", err)
	}
	raw, err := parseEdDSASignature(append([]byte(eddsaPrefix), decodeFixture(t, pkgSigDER)...))
	if err != nil {
		t.Fatalf("read pkg's own signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(pkgDoc), raw) {
		t.Fatal("pkg's own signature does not verify under the key recovered from pkg's own public key, so the curve conversion is wrong")
	}
}

// And the forward direction lands on the bytes pkg wrote, which is the half a
// client parses. Byte-exact rather than semantically equal: pkg's reader takes
// the DER apart field by field, so a structure that merely decodes to the same
// values is not evidence it accepts this one.
func TestEdDSAWritesTheKeyEncodingPkgWrote(t *testing.T) {
	want := decodeFixture(t, pkgPubDER)
	pub, err := parseEdDSAPublicKey(want)
	if err != nil {
		t.Fatalf("read pkg's own public key: %v", err)
	}
	got, err := eddsaPublicKey(pub)
	if err != nil {
		t.Fatalf("render the public key: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the rendered public key differs from pkg's own:\n got %x\nwant %x", got, want)
	}
}

// The message a repository signature covers, which is not the message
// `pkg key --sign` covers: ecc_verify_cert_cb hashes the document to SHA-256
// and hands libecc the 64 hex characters, so that is what the signature is
// over. Checked against the ed25519 primitive rather than against Verify,
// which would pass on any self-consistent pair.
func TestEdDSASignsTheMessagePkgVerifies(t *testing.T) {
	kr, err := Generate(KeyEd25519)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	doc := []byte("{\"name\":\"zsh\"}\n")
	sig, err := kr.Sign(doc)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	member, err := kr.PublicKeyMember()
	if err != nil {
		t.Fatalf("render the public key member: %v", err)
	}
	// The frame goes on the .pub member too, and a client strips it before
	// hashing. An unframed .pub resets pkg's signer choice to rsa and the
	// key reaches the OpenSSL verifier, which reports only that it cannot
	// read a public key.
	bare, ok := bytesCutPrefix(member, eddsaPrefix)
	if !ok {
		t.Fatalf("the .pub member carries no %q frame: %q", eddsaPrefix, member[:min(len(member), 24)])
	}
	if pub, err := kr.PublicKey(); err != nil || !bytes.Equal(bare, pub) {
		t.Fatalf("the framed .pub member does not unwrap to the key the fingerprint is taken over (err %v)", err)
	}
	pub, err := parseEdDSAPublicKey(bare)
	if err != nil {
		t.Fatalf("read back the public key: %v", err)
	}
	raw, err := parseEdDSASignature(sig)
	if err != nil {
		t.Fatalf("read back the signature: %v", err)
	}
	if !ed25519.Verify(pub, eddsaDigest(doc), raw) {
		t.Error("the signature is not over the hex sha256 pkg's ecc fingerprint verifier supplies")
	}
	if ed25519.Verify(pub, doc, raw) {
		t.Error("the signature is over the raw document; pkg's fingerprint path digests it first")
	}
}

// R and S are 32-byte strings that DER carries as integers, so the encoding
// is not length-preserving in either direction: a leading zero is dropped on
// the way out, and a leading byte with the high bit set gains a 0x00 sign
// byte. pkg's own reader restores both, and a signature that does not survive
// the round trip is one it reassembles into different bytes.
//
// Deterministic rather than left to whatever a generated key produces: each
// of these shapes turns up in roughly half of random signatures, so a test
// that only signs would pass for a long time before failing on somebody's
// repository.
func TestEdDSASignatureSurvivesTheDERIntegerEdges(t *testing.T) {
	for name, half := range map[string][]byte{
		"high bit set":  bytes.Repeat([]byte{0xff}, 32),
		"leading zeros": append(make([]byte, 8), bytes.Repeat([]byte{0x11}, 24)...),
		"all zero":      make([]byte, 32),
		"low bit only":  append(make([]byte, 31), 0x01),
		"boundary 0x80": append([]byte{0x80}, bytes.Repeat([]byte{0x00}, 31)...),
		"boundary 0x7f": append([]byte{0x7f}, bytes.Repeat([]byte{0xff}, 31)...),
	} {
		t.Run(name, func(t *testing.T) {
			raw := append(append([]byte{}, half...), half...)
			framed, err := eddsaSignature(raw)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := parseEdDSASignature(framed)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("round trip changed the signature:\n got %x\nwant %x", got, raw)
			}
		})
	}
}
