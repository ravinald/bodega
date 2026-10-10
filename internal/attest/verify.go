package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/audit"
)

// Verification check names, in the order Verify runs them.
const (
	CheckSignature     = "signature"
	CheckPredicateType = "predicate-type"
	CheckSubjectDigest = "subject-digest"
	CheckSubjectName   = "subject-name"
	CheckPolicy        = "policy"
)

// VerifyInput is what a consumer brings to an envelope: the keys it trusts,
// the bytes it holds, and the package it asked about.
type VerifyInput struct {
	// Trusted maps a pinned key ID to its public key. A key whose ID does
	// not hash to the map key is the caller's bug; Verify trusts the map.
	Trusted map[string]ed25519.PublicKey
	// ArtifactSHA256 is the lowercase hex digest of the artifact bytes.
	ArtifactSHA256 string
	// WantPURL is the subject name expected, qualifiers stripped.
	WantPURL string
}

// Result is one check's outcome, with both sides shown so a failure needs no
// second command to explain.
type Result struct {
	Check    string
	OK       bool
	Expected string
	Observed string
}

// Verify runs every check against env and reports each one, failures
// included; it does not stop at the first. A statement whose signature fails
// is still decoded and checked, because "which key signed this" and "what does
// it claim" are both what the person debugging needs, and nothing here acts
// on an unverified claim: the caller fails on any result that is not OK.
func Verify(env *Envelope, st *Statement, in VerifyInput) []Result {
	return []Result{
		verifySignature(env, in.Trusted),
		{Check: CheckPredicateType, OK: st.Type == StatementType && st.PredicateType == PredicateType,
			Expected: StatementType + " / " + PredicateType, Observed: st.Type + " / " + st.PredicateType},
		verifyDigest(st, in.ArtifactSHA256),
		verifyName(st, in.WantPURL),
		verifyPolicy(st),
	}
}

func verifySignature(env *Envelope, trusted map[string]ed25519.PublicKey) Result {
	ids := make([]string, 0, len(trusted))
	for id := range trusted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	r := Result{Check: CheckSignature, Expected: "a valid signature by " + strings.Join(ids, " or ")}
	if env.PayloadType != PayloadType {
		r.Observed = "payloadType " + env.PayloadType
		return r
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		r.Observed = "payload is not base64"
		return r
	}
	msg := PAE(env.PayloadType, payload)
	var seen []string
	for _, s := range env.Signatures {
		seen = append(seen, s.KeyID)
		pub, ok := trusted[s.KeyID]
		if !ok {
			continue
		}
		if len(pub) != ed25519.PublicKeySize {
			r.Observed = "signed by trusted key " + s.KeyID + ", but no public key hashing to that ID was found"
			return r
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err == nil && ed25519.Verify(pub, msg, sig) {
			r.OK = true
			r.Observed = "valid signature by " + s.KeyID
			return r
		}
		r.Observed = "signature by " + s.KeyID + " does not verify over this payload"
		return r
	}
	if len(seen) == 0 {
		r.Observed = "no signatures"
	} else if r.Observed == "" {
		r.Observed = "signed only by untrusted key " + strings.Join(seen, ", ")
	}
	return r
}

func verifyDigest(st *Statement, want string) Result {
	r := Result{Check: CheckSubjectDigest, Expected: "sha256:" + want}
	var got []string
	for _, s := range st.Subject {
		d := s.Digest["sha256"]
		got = append(got, "sha256:"+d)
		if want != "" && strings.EqualFold(d, want) {
			r.OK = true
		}
	}
	r.Observed = strings.Join(got, ", ")
	return r
}

func verifyName(st *Statement, want string) Result {
	r := Result{Check: CheckSubjectName, Expected: want}
	var got []string
	for _, s := range st.Subject {
		got = append(got, s.Name)
		if want != "" && PURLBase(s.Name) == want {
			r.OK = true
		}
	}
	r.Observed = strings.Join(got, ", ")
	return r
}

// verifyPolicy fails on a block only. A not_evaluated check passes this test
// and still shows in the statement: it is a gap a consumer may refuse on, but
// it is not a policy that refused.
func verifyPolicy(st *Statement) Result {
	r := Result{Check: CheckPolicy, Expected: "no evaluation with status " + audit.CheckBlock, OK: true}
	var blocked, gaps []string
	for _, e := range st.Predicate.PolicyEvaluations.Evaluations {
		switch e.Status {
		case audit.CheckBlock:
			blocked = append(blocked, e.Check)
		case audit.CheckNotEvaluated:
			gaps = append(gaps, e.Check)
		}
	}
	switch d := st.Predicate.PolicyEvaluations.Decision; {
	case d != audit.AdmissionAdmitted:
		r.OK = false
		r.Observed = "decision " + d
	case len(blocked) > 0:
		r.OK = false
		r.Observed = "blocked by " + strings.Join(blocked, ", ")
	case len(gaps) > 0:
		r.Observed = "no block; not evaluated: " + strings.Join(gaps, ", ")
	default:
		r.Observed = "no block"
	}
	return r
}
