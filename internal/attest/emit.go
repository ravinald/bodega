package attest

import (
	"context"
	"errors"
	"fmt"
	"path"
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
var StandardChecks = []string{audit.CheckAllowList, audit.CheckAge, audit.CheckOSV}

// AdmissionReader is the audit trail's read surface for decisions.
type AdmissionReader interface {
	Admissions(ctx context.Context, f audit.AdmissionFilter) ([]audit.Admission, error)
}

// Pin is one digest pinned under one object key: what an envelope is about.
type Pin struct {
	Type, Name, Version string
	ObjectKey           string
	SHA256              string
	// RequiredBy is the manifest entry's RequiredBy: the packages whose
	// import brought this version in.
	RequiredBy []string
	// Outcome is what PinAdmission reported for this pin.
	Outcome audit.PinOutcome
}

// Emitter signs and stores the envelope for each pin.
type Emitter struct {
	// Signer returns the key to sign with, or nil when none is loaded. A func
	// so a server reload is seen by the next pin.
	Signer     func() attestsign.Signer
	Admissions AdmissionReader
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
	row, err := e.admission(ctx, p)
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
	env, err := Sign(signer, NewStatement(p, row, e.PlatformID, now()))
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
// the second key), so "the newest decision" is every admitted row at the
// newest timestamp, and one of them has to name this object.
func (e *Emitter) admission(ctx context.Context, p Pin) (audit.Admission, error) {
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
	if newest.Decision != audit.AdmissionAdmitted {
		return audit.Admission{}, fmt.Errorf("%w: the newest decision for %s/%s@%s is %s, not %s",
			ErrRefused, p.Type, p.Name, p.Version, newest.Decision, audit.AdmissionAdmitted)
	}
	var named []string
	for _, r := range mine {
		if !r.DecidedAt.Equal(newest.DecidedAt) || r.Decision != audit.AdmissionAdmitted {
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

// NewStatement builds the statement for p under the decision row.
func NewStatement(p Pin, row audit.Admission, platformID string, ingestedAt time.Time) Statement {
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
	var from []ResourceDescriptor
	for _, r := range p.RequiredBy {
		from = append(from, ResourceDescriptor{Name: r})
	}
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
			ResolvedFrom:       from,
			UpstreamProvenance: Availability{Status: StatusUnavailable},
			PublisherSignature: Availability{Status: StatusUnavailable},
		},
	}
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
