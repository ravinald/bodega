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
// constant is what changes if the draft renames it.
const PredicateType = "https://slsa.dev/dependency/v1"

// StatementType is the in-toto Statement v1 type.
const StatementType = "https://in-toto.io/Statement/v1"

// PayloadType is the DSSE payload type of an in-toto statement.
const PayloadType = "application/vnd.in-toto+json"

// StatusUnavailable is what a predicate field says when bodega has nothing to
// put in it. It is a value rather than an omitted field so a consumer cannot
// read the absence as a pass.
const StatusUnavailable = "unavailable"

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
	IngestionPlatform Platform             `json:"ingestionPlatform"`
	IngestedAt        time.Time            `json:"ingestedAt"`
	PolicyEvaluations PolicyEvaluations    `json:"policyEvaluations"`
	ResolvedFrom      []ResourceDescriptor `json:"resolvedFrom,omitempty"`
	// UpstreamProvenance and PublisherSignature say unavailable until bodega
	// verifies a publisher's own statements; see StatusUnavailable.
	UpstreamProvenance Availability `json:"upstreamProvenance"`
	PublisherSignature Availability `json:"publisherSignature"`
}

// Platform identifies the bodega instance that admitted the artifact.
type Platform struct {
	ID string `json:"id"`
}

// Availability is a field's status when it carries no evidence of its own.
type Availability struct {
	Status string `json:"status"`
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
