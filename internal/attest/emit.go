package attest

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// ErrRefused marks an emission the emitter declined because the admission
// record does not support the statement. Callers log it at ERROR: a pin went
// through with no signed record behind it.
var ErrRefused = errors.New("refused to sign")

// StandardChecks are the checks every admission runs. A statement lists each
// one, so a row written before a check existed reads as not_evaluated for it
// rather than leaving the check out, which a consumer could read as a pass.
var StandardChecks = []string{audit.CheckAllowList, audit.CheckAge, audit.CheckOSV, audit.CheckUpstreamProvenance, audit.CheckNameSimilarity}

// AdmissionReader is the audit trail's read surface for decisions.
type AdmissionReader interface {
	Admissions(ctx context.Context, f audit.AdmissionFilter) ([]audit.Admission, error)
}

// ChecksumLister is the audit checksum table's read surface: the pinned
// digests a parent reference resolves against.
type ChecksumLister interface {
	ListChecksums(ctx context.Context, pkgType, pkgName string) ([]audit.StoredChecksum, error)
}

// Parent is a direct dependency whose digest the caller already holds, such
// as a wheel in the same pypi closure. Ref is pypi/{dist}@{version} or
// another {type}/{name}@{version}.
type Parent struct {
	Ref    string
	SHA256 string
}

// noChecksumTable is the reason every catalog reference carries when the
// emitter has no table to look parents up in.
const noChecksumTable = "no checksum table to resolve the parent from"

// Pin is one digest pinned under one object key: what an envelope is about.
type Pin struct {
	Type, Name, Version string
	ObjectKey           string
	SHA256              string
	// RequiredBy is the manifest entry's RequiredBy: the packages whose
	// import brought this version in.
	RequiredBy []string
	// Parents are direct dependencies whose digest the caller established
	// itself; they join requiredBy without a checksum lookup.
	Parents []Parent
	// Outcome is what PinAdmission reported for this pin.
	Outcome audit.PinOutcome
}

// Emitter signs and stores the envelope for each pin.
type Emitter struct {
	// Signer returns the key to sign with, or nil when none is loaded. A func
	// so a server reload is seen by the next pin.
	Signer     func() attestsign.Signer
	Admissions AdmissionReader
	// Checksums resolves each RequiredBy reference to its parent's pinned
	// sha256 at signing time. Nil marks every reference unavailable.
	Checksums  ChecksumLister
	PlatformID string
	// Now stamps ingestedAt; nil means time.Now.
	Now func() time.Time
}

// Emit signs the envelope for p and writes it to store, returning its key. An
// empty key with a nil error means nothing was to be signed: no key loaded,
// or an audit sink with no table to re-read. An envelope already written for
// the same decision is left as it is and its key returned.
//
// The admission row is re-read here rather than handed in, so what gets signed
// is what the table says at signing time and not what a caller believed a
// moment earlier. A missing row, a newest decision that is not admitted, or one
// that names another object is refused with ErrRefused.
func (e *Emitter) Emit(ctx context.Context, store storage.ObjectStore, p Pin) (string, error) {
	return e.emit(ctx, store, p, audit.AdmissionAdmitted)
}

// Revoke signs the envelope for a re-vet that refused p: the same statement
// Emit signs, over a newest decision of policy_blocked. Its key sorts after
// every envelope signed for an earlier decision, so the attestation route and
// a consumer reading the newest envelope see the refusal rather than the
// admission it overturned. The refusals Emit applies apply here with the
// decision reversed: a newest decision that is not policy_blocked, or one
// naming another object, is refused with ErrRefused.
func (e *Emitter) Revoke(ctx context.Context, store storage.ObjectStore, p Pin) (string, error) {
	return e.emit(ctx, store, p, audit.AdmissionPolicyBlocked)
}

func (e *Emitter) emit(ctx context.Context, store storage.ObjectStore, p Pin, decision string) (string, error) {
	if e == nil || e.Signer == nil || p.Outcome == audit.PinUnverified {
		return "", nil
	}
	signer := e.Signer()
	if signer == nil {
		return "", nil
	}
	if store == nil {
		return "", errors.New("no storage backend to write the envelope to")
	}
	if p.SHA256 == "" {
		return "", fmt.Errorf("%w: %s has no sha256 digest pinned", ErrRefused, p.ObjectKey)
	}
	row, err := e.admission(ctx, p, decision)
	if err != nil {
		return "", err
	}
	key := manifest.AttestationKey(p.ObjectKey, row.DecidedAt)
	if info, err := store.Head(ctx, key); err == nil && info != nil && info.Exists {
		return key, nil
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	env, err := Sign(signer, newStatement(p, row, e.PlatformID, now(), requiredByOf(ctx, e.Checksums, p)))
	if err != nil {
		return "", err
	}
	if err := store.Put(ctx, key, env); err != nil {
		return "", fmt.Errorf("write %s: %w", key, err)
	}
	return key, nil
}

// admission is the row an envelope for p may cite. Copies of one decision
// share its decided_at (a second wheel of a pypi release is a copy carrying
// the second key), so "the newest decision" is every row of that decision at
// the newest timestamp, and one of them has to name this object.
func (e *Emitter) admission(ctx context.Context, p Pin, decision string) (audit.Admission, error) {
	if e.Admissions == nil {
		return audit.Admission{}, fmt.Errorf("%w: no audit trail to read the admission from", ErrRefused)
	}
	rows, err := e.Admissions.Admissions(ctx, audit.AdmissionFilter{PkgType: p.Type, PkgName: p.Name, PkgVersion: p.Version, Limit: 200})
	if err != nil {
		return audit.Admission{}, fmt.Errorf("re-read the admission for %s/%s@%s: %w", p.Type, p.Name, p.Version, err)
	}
	var mine []audit.Admission
	for _, r := range rows {
		// An empty filter field matches everything, and distfiles pins
		// with an empty version.
		if r.PkgVersion == p.Version {
			mine = append(mine, r)
		}
	}
	if len(mine) == 0 {
		return audit.Admission{}, fmt.Errorf("%w: no admission row for %s/%s@%s", ErrRefused, p.Type, p.Name, p.Version)
	}
	newest := mine[0]
	if newest.Decision != decision {
		return audit.Admission{}, fmt.Errorf("%w: the newest decision for %s/%s@%s is %s, not %s",
			ErrRefused, p.Type, p.Name, p.Version, newest.Decision, decision)
	}
	var named []string
	for _, r := range mine {
		if !r.DecidedAt.Equal(newest.DecidedAt) || r.Decision != decision {
			break
		}
		if r.ObjectKey == p.ObjectKey {
			return r, nil
		}
		named = append(named, r.ObjectKey)
	}
	return audit.Admission{}, fmt.Errorf("%w: the newest admission for %s/%s@%s names object %q, not %s",
		ErrRefused, p.Type, p.Name, p.Version, strings.Join(named, ", "), p.ObjectKey)
}

// NewStatement builds the statement for p under the decision row. It has no
// checksum table, so each of p.RequiredBy is unavailable; Emit resolves them.
func NewStatement(p Pin, row audit.Admission, platformID string, ingestedAt time.Time) Statement {
	return newStatement(p, row, platformID, ingestedAt, requiredByOf(context.Background(), nil, p))
}

func newStatement(p Pin, row audit.Admission, platformID string, ingestedAt time.Time, refs []RequiredByRef) Statement {
	pe := PolicyEvaluations{
		PolicyDigest: map[string]string{},
		Decision:     row.Decision,
		DecidedAt:    row.DecidedAt.UTC(),
		Actor:        row.Actor,
		Identity:     row.Identity,
		Evaluations:  Evaluations(row.Checks),
	}
	if alg, hex, ok := strings.Cut(row.PolicyDigest, ":"); ok && hex != "" {
		pe.PolicyDigest[alg] = hex
	}
	upstream := AvailabilityOf(row.Checks)
	return Statement{
		Type: StatementType,
		Subject: []ResourceDescriptor{{
			Name:        PURL(p.Type, p.Name, p.Version, p.ObjectKey),
			Digest:      map[string]string{"sha256": strings.ToLower(p.SHA256)},
			Annotations: map[string]string{ObjectKeyAnnotation: p.ObjectKey},
		}},
		PredicateType: PredicateType,
		Predicate: Predicate{
			IngestionPlatform:  Platform{ID: platformID},
			IngestedAt:         ingestedAt.UTC(),
			PolicyEvaluations:  pe,
			ResolvedFrom:       resolvedFromOf(refs),
			RequiredBy:         refs,
			UpstreamProvenance: upstream,
			PublisherSignature: PublisherSignatureOf(upstream),
			Integrity:          Integrity{Method: IntegrityMethodHash, Result: ResultVerified},
		},
	}
}

// requiredByOf lists p's catalog references in manifest order, each resolved
// against src, then p.Parents sorted by ref, dropping an entry that repeats an
// earlier one.
func requiredByOf(ctx context.Context, src ChecksumLister, p Pin) []RequiredByRef {
	var out []RequiredByRef
	seen := map[[2]string]bool{}
	add := func(r RequiredByRef) {
		key := [2]string{r.Ref, "unavailable:" + r.Unavailable}
		if r.Digest != nil {
			key[1] = "sha256:" + r.Digest["sha256"]
		}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, r)
	}
	for _, ref := range p.RequiredBy {
		add(resolveRef(ctx, src, ref))
	}
	parents := append([]Parent(nil), p.Parents...)
	sort.SliceStable(parents, func(i, j int) bool { return parents[i].Ref < parents[j].Ref })
	for _, pa := range parents {
		if pa.SHA256 == "" {
			add(RequiredByRef{Ref: pa.Ref, Unavailable: fmt.Sprintf("no sha256 was established for %s", pa.Ref)})
			continue
		}
		add(RequiredByRef{Ref: pa.Ref, Digest: map[string]string{"sha256": strings.ToLower(pa.SHA256)}})
	}
	return out
}

// resolvedFromOf is the digest of the first reference that carries one.
func resolvedFromOf(refs []RequiredByRef) *ResolvedFromRef {
	for _, r := range refs {
		if r.Digest != nil {
			return &ResolvedFromRef{Subject: map[string]string{"sha256": r.Digest["sha256"]}}
		}
	}
	return nil
}

// resolveRef finds the one sha256 pinned for a catalog reference. The forms
// are {type}/{name}@{version}, {type}/{name} for every version (what apt
// discovery records), and a bare {name}, which reads as git/{name} because a
// bare required_by is how a git repository is named. Anything that does not
// give exactly one distinct digest is unavailable, with the reason.
func resolveRef(ctx context.Context, src ChecksumLister, ref string) RequiredByRef {
	out := RequiredByRef{Ref: ref}
	if src == nil {
		out.Unavailable = noChecksumTable
		return out
	}
	typ, rest, ok := strings.Cut(ref, "/")
	if !ok {
		typ, rest = manifest.TypeGit, ref
	}
	name, version, versioned := rest, "", false
	// An npm scope opens with @, so only an @ past the first byte separates
	// a version.
	if i := strings.LastIndex(rest, "@"); i > 0 {
		name, version, versioned = rest[:i], rest[i+1:], true
	}
	if typ == "" || name == "" {
		out.Unavailable = fmt.Sprintf("reference %q names no package type and name to look a parent up by", ref)
		return out
	}
	rows, err := src.ListChecksums(ctx, typ, name)
	if err != nil {
		out.Unavailable = fmt.Sprintf("reading the pinned checksums for %q failed: %v", ref, err)
		return out
	}
	var digests []string
	for _, r := range rows {
		if r.PkgType != typ || r.PkgName != name || r.Value == "" || !strings.EqualFold(r.Algorithm, "sha256") {
			continue
		}
		if versioned && r.PkgVersion != version {
			continue
		}
		if d := strings.ToLower(r.Value); !slices.Contains(digests, d) {
			digests = append(digests, d)
		}
	}
	switch len(digests) {
	case 0:
		out.Unavailable = fmt.Sprintf("no sha256 is pinned for %q", ref)
	case 1:
		out.Digest = map[string]string{"sha256": digests[0]}
	default:
		out.Unavailable = fmt.Sprintf("%q matches %d distinct pinned sha256 digests, so none of them names the parent", ref, len(digests))
	}
	return out
}

// AvailabilityOf maps the upstream_provenance check of a row onto the
// draft's upstreamProvenance verdict. A row without one, a check that did not
// run, and an outcome this table does not name all say not-attempted: an
// outcome nobody evaluated is never reported as verified.
//
// mismatch carries two cases. A bundle that verified but was signed from a
// repository or builder other than the pinned one names its identity, and is
// verified here: the signature did verify. A version that published nothing
// after a pinned version that did names none, and is unavailable. Either way
// the pin disagreement is the upstream_provenance entry of policyEvaluations,
// not this field.
func AvailabilityOf(checks []audit.AdmissionCheck) Availability {
	for _, c := range checks {
		if c.Check != audit.CheckUpstreamProvenance || c.Status == audit.CheckNotEvaluated || c.Provenance == nil || c.Provenance.Outcome == "" {
			continue
		}
		p := c.Provenance
		switch {
		case p.Outcome == audit.ProvenanceVerified,
			p.Outcome == audit.ProvenanceMismatch && p.SourceRepositoryURI != "":
			a := Availability{Result: ResultVerified, SourceRepositoryURI: p.SourceRepositoryURI, WorkflowRef: p.WorkflowRef, BuilderID: p.BuilderID}
			if alg, hex, ok := strings.Cut(p.BundleDigest, ":"); ok && hex != "" {
				a.BundleDigest = map[string]string{alg: hex}
			}
			return a
		case p.Outcome == audit.ProvenanceMismatch, p.Outcome == audit.ProvenanceUnavailable:
			return Availability{Availability: AvailabilityUnavailable}
		case p.Outcome == audit.ProvenanceInvalid:
			return Availability{Result: ResultFailed}
		default:
			return Availability{Result: ResultNotAttempted}
		}
	}
	return Availability{Result: ResultNotAttempted}
}

// PublisherSignatureOf is upstream as publisherSignature spells it: the draft
// gives that field verified, failed and unverified, with no not-attempted.
func PublisherSignatureOf(upstream Availability) Availability {
	if upstream.Result == ResultNotAttempted {
		upstream.Result = ResultUnverified
	}
	return upstream
}

// Evaluations copies a row's checks as recorded and appends each standard
// check the row does not carry as not_evaluated.
func Evaluations(checks []audit.AdmissionCheck) []Evaluation {
	out := make([]Evaluation, 0, len(checks)+len(StandardChecks))
	have := map[string]bool{}
	for _, c := range checks {
		have[c.Check] = true
		out = append(out, Evaluation{Check: c.Check, Action: c.Action, Status: c.Status, Detail: c.Detail})
	}
	for _, c := range StandardChecks {
		if !have[c] {
			out = append(out, Evaluation{Check: c, Action: audit.ActionNone, Status: audit.CheckNotEvaluated,
				Detail: "not recorded on the admission row"})
		}
	}
	return out
}

// Newest returns the key of the newest envelope signed for any of objectKeys
// in store, or "" when there is none. Envelope keys sort by decision time, so
// no envelope is read to answer.
func Newest(ctx context.Context, store storage.ObjectStore, objectKeys []string) (string, error) {
	var best, bestStamp string
	for _, k := range objectKeys {
		keys, err := store.List(ctx, manifest.AttestationDir(k))
		if err != nil {
			return "", err
		}
		for _, ek := range keys {
			if !strings.HasSuffix(ek, manifest.AttestationExt) || path.Dir(ek)+"/" != manifest.AttestationDir(k) {
				continue
			}
			if stamp := path.Base(ek); stamp > bestStamp {
				best, bestStamp = ek, stamp
			}
		}
	}
	return best, nil
}

// ObjectKeyOf inverts AttestationKey: the artifact key an envelope key is
// filed under.
func ObjectKeyOf(envelopeKey string) (string, bool) {
	rest, ok := strings.CutPrefix(envelopeKey, manifest.AttestationPrefix)
	if !ok || !strings.HasSuffix(rest, manifest.AttestationExt) {
		return "", false
	}
	return path.Dir(rest), true
}
