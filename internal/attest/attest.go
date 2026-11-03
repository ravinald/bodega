// Package attest builds, signs and verifies the statement bodega makes about
// each artifact it admits: an in-toto Statement v1 carrying a SLSA Dependency
// Ingestion predicate, wrapped in a DSSE envelope.
//
// The encoding is written here against the published in-toto, DSSE and purl
// specifications rather than taken from a library. The whole format is a JSON
// document, a length-prefixed byte string and an Ed25519 signature over it,
// and a dependency that did all three would be a larger thing to audit than
// the code it replaced.
//
// Signing goes through internal/attestsign and nothing else: there is one
// attestation key path, and this package never loads a key itself.
package attest

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ravinald/bodega/internal/attestsign"
)

// PredicateType names the SLSA Dependency track's ingestion predicate. The
// track is a working draft (slsa-framework/slsa main, not v1.2), so this one
// constant is what changes if the draft renames it. The fields and vocabulary
// bodega emits under it follow the revision DraftRevision names.
const PredicateType = "https://slsa.dev/dependency/v1"

// DraftRevision is the revision of the SLSA dependency-provenance draft the
// predicate follows, as read on 2026-11-02. The draft is unapproved and keeps
// moving; each later change is recorded on issue #277 before this moves.
const DraftRevision = "https://github.com/slsa-framework/slsa/blob/4d3f9d44a803aaa52eef08fdafd04a7409c263e7/spec/dependency-provenance.md"

// The predicate's verdict vocabulary, from DraftRevision. bodega's admission
// row keeps its own five provenance outcomes (audit.ProvenanceVerified and
// its siblings), which drive override rules this vocabulary cannot express;
// AvailabilityOf maps one onto the other at the predicate boundary.
const (
	ResultVerified          = "verified"
	ResultFailed            = "failed"
	ResultUnverified        = "unverified"
	ResultNotAttempted      = "not-attempted"
	AvailabilityUnavailable = "unavailable"
	IntegrityMethodHash     = "hash"
)

// StatementType is the in-toto Statement v1 type.
const StatementType = "https://in-toto.io/Statement/v1"

// PayloadType is the DSSE payload type of an in-toto statement.
const PayloadType = "application/vnd.in-toto+json"

// ObjectKeyAnnotation names the subject annotation carrying the storage key
// the digest was pinned under, which is how a verifier finds the bytes.
const ObjectKeyAnnotation = "bodega.objectKey"

// ResourceDescriptor is the in-toto v1 resource descriptor, as far as bodega
// fills it.
type ResourceDescriptor struct {
	Name        string            `json:"name,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Digest      map[string]string `json:"digest,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Statement is an in-toto Statement v1 with bodega's predicate.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     Predicate            `json:"predicate"`
}

// Predicate is the Dependency Ingestion predicate.
type Predicate struct {
	IngestionPlatform Platform          `json:"ingestionPlatform"`
	IngestedAt        time.Time         `json:"ingestedAt"`
	PolicyEvaluations PolicyEvaluations `json:"policyEvaluations"`
	// ResolvedFrom is the draft's ResolvedFromRef: the digest of the direct
	// dependency that brought this artifact in, as that parent's own subject
	// digest. Nil when bodega established none, which is not evidence the
	// artifact was a top-level dependency.
	ResolvedFrom *ResolvedFromRef `json:"resolvedFrom,omitempty"`
	// RequiredBy is a bodega addition outside the SLSA draft: every
	// direct-dependency reference bodega recorded or established for the pin,
	// each with the parent's digest or the reason none was found, so a
	// reference with no digest is kept rather than dropped from ResolvedFrom.
	RequiredBy []RequiredByRef `json:"requiredBy,omitempty"`
	// LegacyResolvedFrom holds the names an envelope signed before E29
	// carried, when resolvedFrom was an array of name-only descriptors.
	// UnmarshalJSON reads it so those envelopes still verify; it is never
	// marshaled, so a re-signed statement cannot carry the array form.
	LegacyResolvedFrom []string `json:"-"`
	// UpstreamProvenance and PublisherSignature are what the admission row's
	// upstream_provenance check concluded about the publisher's own signed
	// provenance. Both carry the same verdict and identity, because the
	// provenance and the signature over it are one Sigstore bundle verified
	// together; they differ only in how the draft spells a verdict nobody
	// reached. See AvailabilityOf and PublisherSignatureOf.
	UpstreamProvenance Availability `json:"upstreamProvenance"`
	PublisherSignature Availability `json:"publisherSignature"`
	// Integrity says the subject digest was checked against the bytes.
	// NewStatement is reached only after emit refuses a pin with no sha256,
	// and the pinned sha256 is what the fetch verified the bytes against, so
	// every statement it builds says verified.
	Integrity Integrity `json:"integrity"`
}

// UnmarshalJSON decodes resolvedFrom in either form: the draft's
// ResolvedFromRef object, or the pre-E29 array of name-only descriptors,
// whose names land in LegacyResolvedFrom.
func (p *Predicate) UnmarshalJSON(data []byte) error {
	type fields Predicate
	var wire struct {
		fields
		ResolvedFrom json.RawMessage `json:"resolvedFrom"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*p = Predicate(wire.fields)
	raw := bytes.TrimSpace(wire.ResolvedFrom)
	switch {
	case len(raw) == 0 || bytes.Equal(raw, []byte("null")):
	case raw[0] == '[':
		var legacy []ResourceDescriptor
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return fmt.Errorf("resolvedFrom: %w", err)
		}
		for _, d := range legacy {
			p.LegacyResolvedFrom = append(p.LegacyResolvedFrom, d.Name)
		}
	default:
		var ref ResolvedFromRef
		if err := json.Unmarshal(raw, &ref); err != nil {
			return fmt.Errorf("resolvedFrom: %w", err)
		}
		p.ResolvedFrom = &ref
	}
	return nil
}

// ResolvedFromRef is the draft's resolvedFrom object. Subject is the direct
// dependency's digest set, matching that parent's own subject digest.
type ResolvedFromRef struct {
	Subject map[string]string `json:"subject"`
}

// RequiredByRef is one direct-dependency reference: Ref as recorded, and
// exactly one of Digest (the parent's sha256) or Unavailable (why no digest
// was found).
type RequiredByRef struct {
	Ref         string            `json:"ref"`
	Digest      map[string]string `json:"digest,omitempty"`
	Unavailable string            `json:"unavailable,omitempty"`
}

// Integrity is the draft's integrity verdict: how the artifact was checked,
// and what the check concluded.
type Integrity struct {
	Method string `json:"method,omitempty"`
	Result string `json:"result,omitempty"`
}

// Platform identifies the bodega instance that admitted the artifact.
type Platform struct {
	ID string `json:"id"`
}

// Availability is the outcome of verifying a publisher's provenance, in the
// draft's vocabulary: Result is verified, failed, or not-attempted
// (unverified in publisherSignature), and Availability is unavailable when the
// publisher published nothing to verify. Exactly one of the two is set on a
// statement NewStatement builds. The identity fields are what the signing
// certificate and the provenance named, set only when Result is verified.
type Availability struct {
	Result       string `json:"result,omitempty"`
	Availability string `json:"availability,omitempty"`
	// LegacyStatus is the single status an envelope signed before E27
	// carried (verified, unavailable, invalid, unknown or mismatch, from the
	// draft of 2026-10-05). UnmarshalJSON reads it so those envelopes still
	// verify and print; it is never marshaled, so re-signing a decoded
	// statement cannot put the old vocabulary back on the wire.
	LegacyStatus        string `json:"-"`
	SourceRepositoryURI string `json:"sourceRepositoryUri,omitempty"`
	WorkflowRef         string `json:"workflowRef,omitempty"`
	BuilderID           string `json:"builderId,omitempty"`
	// BundleDigest is the digest of the Sigstore bundle that was verified,
	// as an in-toto digest set.
	BundleDigest map[string]string `json:"bundleDigest,omitempty"`
}

// UnmarshalJSON decodes the draft's fields and the pre-E27 status key, which
// the struct tag keeps out of every encoding.
func (a *Availability) UnmarshalJSON(data []byte) error {
	type fields Availability
	var wire struct {
		fields
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*a = Availability(wire.fields)
	a.LegacyStatus = wire.Status
	return nil
}

// PolicyEvaluations is the admission decision the statement rests on: the
// policy it was decided under, and what each check concluded.
type PolicyEvaluations struct {
	// PolicyDigest is empty for a decision nothing evaluated.
	PolicyDigest map[string]string `json:"policyDigest"`
	Decision     string            `json:"decision"`
	DecidedAt    time.Time         `json:"decidedAt"`
	Actor        string            `json:"actor,omitempty"`
	Identity     string            `json:"identity,omitempty"`
	Evaluations  []Evaluation      `json:"evaluations"`
}

// Evaluation is one check's verdict, as the admission row records it.
type Evaluation struct {
	Check  string `json:"check"`
	Action string `json:"action"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Envelope is a DSSE envelope. Payload and each Sig are standard base64.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// PAE is the DSSE v1 pre-authentication encoding, which is what gets signed:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths in ASCII decimal.
// Signing the payload alone would let a signature over one payload type verify
// as another.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// Sign serializes st and returns the DSSE envelope as JSON, signed by s.
func Sign(s attestsign.Signer, st Statement) ([]byte, error) {
	if s == nil {
		return nil, errors.New("no attestation signer")
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("encode statement: %w", err)
	}
	sig, err := s.Sign(rand.Reader, PAE(PayloadType, payload), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign statement: %w", err)
	}
	return json.MarshalIndent(Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, "", "  ")
}

// ParseEnvelope decodes an envelope and the statement it carries. It checks
// structure only; Verify checks everything a consumer acts on.
func ParseEnvelope(data []byte) (*Envelope, *Statement, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, nil, fmt.Errorf("not a DSSE envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope payload is not base64: %w", err)
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, nil, fmt.Errorf("envelope payload is not an in-toto statement: %w", err)
	}
	return &env, &st, nil
}

// KeyIDOf returns the attestation key ID of pub: the lowercase hex SHA-256 of
// its DER SubjectPublicKeyInfo, the same derivation attestsign uses.
func KeyIDOf(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// ParsePublicKeyPEM reads one Ed25519 PUBLIC KEY block.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM PUBLIC KEY block")
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("a %T, where attestation keys are Ed25519", raw)
	}
	return pub, nil
}
