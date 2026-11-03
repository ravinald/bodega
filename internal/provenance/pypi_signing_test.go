package provenance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorv1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

// localSigstore issues PEP 740 attestations for an identity the recorded
// fixtures do not hold: a Fulcio-style CA whose leaves carry the GitHub
// workflow extensions and an embedded SCT, a CT log, and VirtualSigstore's
// Rekor for the transparency entry, with both the promise and the inclusion
// proof a v0.3 bundle requires. verifyBundle requires all three, so a
// fixture missing any of them would fail for that reason rather than for the
// identity a test is about.
type localSigstore struct {
	t       *testing.T
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	ctKey   *ecdsa.PrivateKey
	ctLogID [32]byte
	rekor   *ca.VirtualSigstore
	now     time.Time
}

func newLocalSigstore(t *testing.T) *localSigstore {
	t.Helper()
	s := &localSigstore{t: t, now: time.Now().Truncate(time.Second)}
	var err error
	if s.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local fulcio"},
		NotBefore: s.now.Add(-time.Hour), NotAfter: s.now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	s.caCert = s.mustCert(tmpl, tmpl, &s.caKey.PublicKey)
	if s.ctKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&s.ctKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s.ctLogID = sha256.Sum256(spki)
	if s.rekor, err = ca.NewVirtualSigstore(); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *localSigstore) mustCert(tmpl, parent *x509.Certificate, pub any) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, s.caKey)
	if err != nil {
		s.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		s.t.Fatal(err)
	}
	return cert
}

// Root is the trusted material this sigstore's attestations verify against.
func (s *localSigstore) Root() root.TrustedMaterial {
	return &localTrust{s: s}
}

type localTrust struct {
	root.BaseTrustedMaterial
	s *localSigstore
}

func (l *localTrust) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: l.s.caCert,
		ValidityPeriodStart: l.s.now.Add(-time.Hour), ValidityPeriodEnd: l.s.now.Add(time.Hour)}}
}

func (l *localTrust) CTLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{hex.EncodeToString(l.s.ctLogID[:]): {
		BaseURL: "https://ct.localhost", ID: l.s.ctLogID[:], HashFunc: crypto.SHA256, PublicKey: &l.s.ctKey.PublicKey,
		ValidityPeriodStart: l.s.now.Add(-time.Hour), ValidityPeriodEnd: l.s.now.Add(time.Hour)}}
}

func (l *localTrust) RekorLogs() map[string]*root.TransparencyLog { return l.s.rekor.RekorLogs() }

// leaf issues a GitHub Actions certificate for repo (https://github.com/...)
// and signer, with an SCT signed over the certificate as it reads without the
// SCT list, which is what a verifier reconstructs.
func (s *localSigstore) leaf(repo, signer string, key *ecdsa.PrivateKey) *x509.Certificate {
	utf8 := func(v string) []byte {
		b, err := asn1.MarshalWithParams(v, "utf8")
		if err != nil {
			s.t.Fatal(err)
		}
		return b
	}
	oid := func(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, n} }
	san, err := url.Parse(signer)
	if err != nil {
		s.t.Fatal(err)
	}
	tmpl := func(extra ...pkix.Extension) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(2), URIs: []*url.URL{san},
			NotBefore: s.now.Add(-time.Minute), NotAfter: s.now.Add(10 * time.Minute),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			ExtraExtensions: append([]pkix.Extension{
				{Id: oid(8), Value: utf8("https://token.actions.githubusercontent.com")},
				{Id: oid(9), Value: utf8(signer)},
				{Id: oid(12), Value: utf8(repo)},
			}, extra...)}
	}
	unsigned := s.mustCert(tmpl(), s.caCert, &key.PublicKey)
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, LogID: ct.LogID{KeyID: s.ctLogID}, Timestamp: uint64(s.now.UnixMilli())}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{Timestamp: sct.Timestamp, EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{IssuerKeyHash: sha256.Sum256(s.caCert.RawSubjectPublicKeyInfo), TBSCertificate: unsigned.RawTBSCertificate}}}})
	if err != nil {
		s.t.Fatal(err)
	}
	h := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, s.ctKey, h[:])
	if err != nil {
		s.t.Fatal(err)
	}
	sct.Signature = ct.DigitallySigned{Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA}, Signature: sig}
	list, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		s.t.Fatal(err)
	}
	raw, err := cttls.Marshal(*list)
	if err != nil {
		s.t.Fatal(err)
	}
	ext, err := asn1.Marshal(raw)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.mustCert(tmpl(pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: ext}), s.caCert, &key.PublicKey)
}

// provenance is a PEP 740 provenance object for filename at sha256hex, one
// GitHub publisher bundle naming repository and workflow, its one attestation
// signed by a certificate binding repo and signer.
func (s *localSigstore) provenance(filename, sha256hex, repository, workflow, repo, signer string) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		s.t.Fatal(err)
	}
	cert := s.leaf(repo, signer, key)
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": filename, "digest": map[string]string{"sha256": sha256hex}}},
		"predicateType": PyPIPublishV1,
		"predicate":     nil,
	})
	if err != nil {
		s.t.Fatal(err)
	}
	sv, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		s.t.Fatal(err)
	}
	signerDSSE, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: sv, Pub: &key.PublicKey})
	if err != nil {
		s.t.Fatal(err)
	}
	env, err := signerDSSE.SignPayload(context.Background(), "application/vnd.in-toto+json", statement)
	if err != nil {
		s.t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		s.t.Fatal(err)
	}
	entry, err := s.rekor.GenerateTlogEntry(cert, env, sig, s.now.Unix(), true)
	if err != nil {
		s.t.Fatal(err)
	}
	tle := entry.TransparencyLogEntry()
	set, err := s.rekor.RekorSignPayload(tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(tle.CanonicalizedBody),
		IntegratedTime: tle.IntegratedTime, LogIndex: tle.LogIndex, LogID: hex.EncodeToString(tle.LogId.KeyId)})
	if err != nil {
		s.t.Fatal(err)
	}
	full := &rekorv1.TransparencyLogEntry{LogIndex: tle.LogIndex, LogId: &protocommon.LogId{KeyId: tle.LogId.KeyId},
		KindVersion: &rekorv1.KindVersion{Kind: "dsse", Version: "0.0.1"}, IntegratedTime: tle.IntegratedTime,
		InclusionPromise: &rekorv1.InclusionPromise{SignedEntryTimestamp: set}, InclusionProof: tle.InclusionProof,
		CanonicalizedBody: tle.CanonicalizedBody}
	tlogJSON, err := protojson.Marshal(full)
	if err != nil {
		s.t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"version": 1,
		"attestation_bundles": []map[string]any{{
			"publisher": map[string]any{"kind": "GitHub", "repository": repository, "workflow": workflow},
			"attestations": []map[string]any{{
				"version": 1,
				"verification_material": map[string]any{
					"certificate":          base64.StdEncoding.EncodeToString(cert.Raw),
					"transparency_entries": []json.RawMessage{tlogJSON},
				},
				"envelope": map[string]string{"statement": env.Payload, "signature": env.Signatures[0].Sig},
			}},
		}},
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

// The package's first verified release takes the pin, and a later release
// whose attestation verifies but was built from another repository is held
// to it: mismatch, with the first pin left in place.
func TestPypiSecondReleaseFromAnotherRepositoryMismatchesThePin(t *testing.T) {
	r := newTLSRegistry(t)
	local := newLocalSigstore(t)
	const (
		next      = "sampleproject-4.1.0-py3-none-any.whl"
		nextPath  = "/integrity/sampleproject/4.1.0/" + next + "/provenance"
		otherRepo = "https://github.com/example/sampleproject"
	)
	nextSum := sha256.Sum256([]byte("a wheel built somewhere else"))
	nextHex := hex.EncodeToString(nextSum[:])
	var files []map[string]any
	for _, f := range pypiFiles(t, r) {
		if f["filename"] == pypiWheel {
			files = append(files, f)
		}
	}
	files = append(files, map[string]any{"filename": next, "hashes": map[string]string{"sha256": nextHex}, "provenance": r.URL + nextPath})
	r.putJSON(t, pypiPagePath, map[string]any{"meta": map[string]any{"api-version": "1.4"}, "name": "sampleproject", "files": files})
	r.put(pypiWheelPath, fixture(t, "pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json"))
	r.put(nextPath, local.provenance(next, nextHex, "example/sampleproject", "release.yml",
		otherRepo, otherRepo+"/.github/workflows/release.yml@refs/tags/v4.1.0"))

	recorded, err := recordedRoot(t)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v := newPypiVerifier(t, r)
	v.Root = func(context.Context) (root.TrustedMaterial, error) {
		return root.TrustedMaterialCollection{recorded, local.Root()}, nil
	}
	pm := &manifest.PackageManifest{Type: manifest.TypePypi, Name: "sampleproject"}

	// The second release verifies on its own, so the mismatch below is the
	// pin's doing and not a broken fixture.
	if ev := checkPypi(t, v, "4.1.0"); ev.Outcome != audit.ProvenanceVerified || ev.SourceRepositoryURI != otherRepo {
		t.Fatalf("4.1.0 alone: %s (%s) from %s, want verified from %s", ev.Outcome, ev.Detail, ev.SourceRepositoryURI, otherRepo)
	}

	store := &fakeStore{}
	first := &Checker{Store: store, Verifier: v}
	if got := first.Check(context.Background(), pm, &manifest.VersionEntry{Version: "4.0.0"}); got.Provenance.Outcome != audit.ProvenanceVerified {
		t.Fatalf("4.0.0: %s (%s), want verified", got.Provenance.Outcome, got.Reason)
	}
	first.Commit(context.Background())
	want := store.pins["pypi/sampleproject"]
	if want.SourceRepositoryURI != pypiRepo || want.PinnedVersion != "4.0.0" {
		t.Fatalf("pin after 4.0.0: %+v", want)
	}

	second := &Checker{Store: store, Verifier: v}
	got := second.Check(context.Background(), pm, &manifest.VersionEntry{Version: "4.1.0"})
	if got.Provenance.Outcome != audit.ProvenanceMismatch || got.Action == policy.ActionPass {
		t.Fatalf("4.1.0 after the pin: %s, action %s (%s), want a mismatch that does not pass", got.Provenance.Outcome, got.Action, got.Reason)
	}
	if got.Provenance.SourceRepositoryURI != otherRepo {
		t.Errorf("the mismatch carries %q, want the identity 4.1.0 was built by, %q", got.Provenance.SourceRepositoryURI, otherRepo)
	}
	second.Commit(context.Background())
	if held := store.pins["pypi/sampleproject"]; held != want {
		t.Errorf("pin after 4.1.0: %+v, want the 4.0.0 pin %+v unchanged", held, want)
	}
}
