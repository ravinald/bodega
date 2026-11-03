package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Admission decisions. The set matches the CHECK on admissions.decision in
// both migration trees.
const (
	AdmissionAdmitted      = "admitted"
	AdmissionPolicyBlocked = "policy_blocked"
	AdmissionInvalid       = "invalid"
)

// Check names an admission row's checks carry.
const (
	CheckAllowList = "allowlist"
	CheckAge       = "age"
	CheckOSV       = "osv"
	// CheckUpstreamProvenance is the publisher's own signed provenance,
	// verified against the Sigstore trusted root. Its entry carries the
	// outcome and the identity verified in Provenance.
	CheckUpstreamProvenance = "upstream_provenance"
	// CheckChecksumDatabase is a Go module version looked up in the checksum
	// database and verified against its signed tree head. Only gomod rows
	// carry it. Its entry carries the outcome, the tree and both hashes in
	// ChecksumDatabase.
	CheckChecksumDatabase = "checksum_database"
	// CheckOverride is the operator answering y to the allow-list prompt
	// `bodega pkg create` carried before two-person overrides replaced it.
	// Nothing writes it now; rows decided under the prompt still carry it.
	CheckOverride = "override"
)

// Check statuses: what one check concluded about one version.
const (
	CheckPass  = "pass"
	CheckWarn  = "warn"
	CheckBlock = "block"
	// CheckNotEvaluated means the check did not run on this decision: an
	// earlier check refused first, the path has no version to evaluate, or
	// the row was written by a pin no decision preceded. It is never a pass.
	CheckNotEvaluated = "not_evaluated"
)

// ActionNone is the action a check records when no policy is configured for
// the ecosystem, so there is nothing it could have done on a failure.
const ActionNone = "none"

// AdmissionCheck is one check's verdict inside an admission row. Action is
// what the configured policy does on a failure (block, warn, ignore, none);
// Status is what happened.
type AdmissionCheck struct {
	Check  string `json:"check"`
	Action string `json:"action"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	// Provenance is set on the upstream_provenance entry when the check
	// ran, and nil everywhere else.
	Provenance *UpstreamProvenance `json:"provenance,omitempty"`
	// ChecksumDatabase is set on the checksum_database entry when the check
	// ran, and nil everywhere else.
	ChecksumDatabase *ChecksumDatabase `json:"checksum_database,omitempty"`
	// Override is the ID of the override that admitted past this check's
	// failure, set when Status is CheckOverridden.
	Override string `json:"override,omitempty"`
	// Unwaivable is why no override or queue approval may admit past this
	// check's block, set when the result named a version as hostile. An
	// override request reads it here rather than re-deriving it from config
	// that may have changed since.
	Unwaivable string `json:"unwaivable,omitempty"`
}

// Upstream provenance outcomes: what verifying a publisher's signed
// provenance concluded, as distinct from what the policy then did about it.
const (
	ProvenanceVerified = "verified"
	// ProvenanceUnavailable means the package publishes no provenance, or
	// its ecosystem has no mechanism bodega reads.
	ProvenanceUnavailable = "unavailable"
	// ProvenanceInvalid means provenance was published, checked against a
	// trusted root, and did not verify: a signature, a certificate chain or a
	// subject digest failed.
	ProvenanceInvalid = "invalid"
	// ProvenanceUnknown means the evidence could not be read: a registry or
	// API lookup failed or answered something unparseable, the registry no
	// longer lists the version, the pin or publish times a comparison needed
	// were missing, or there was no Sigstore trusted root to check a bundle
	// against. Nothing was concluded, so it says neither that provenance is
	// absent nor that it failed, and an override may admit it.
	ProvenanceUnknown = "unknown"
	// ProvenanceMismatch means the provenance verified, but from a source
	// repository or builder other than the one the package is pinned to.
	ProvenanceMismatch = "mismatch"
)

// DetailNoTrustedRoot is the Details key, true, on an unknown upstream
// provenance result reached because no Sigstore trusted root could be had.
// The root error itself stays in the check's detail, which is not served to
// clients.
const DetailNoTrustedRoot = "no_trusted_root"

// UpstreamProvenance is what the upstream_provenance check verified. The
// identity fields are empty unless a signature verified.
type UpstreamProvenance struct {
	Outcome             string `json:"outcome"`
	SourceRepositoryURI string `json:"source_repository_uri,omitempty"`
	WorkflowRef         string `json:"workflow_ref,omitempty"`
	BuilderID           string `json:"builder_id,omitempty"`
	// BundleDigest is "sha256:<hex>" over the Sigstore bundle as fetched.
	BundleDigest string `json:"bundle_digest,omitempty"`
}

// ChecksumDatabase is what the checksum_database check read. Outcome is one
// of the upstream provenance outcomes: verified, invalid, unknown, or
// unavailable for a module gomod_nosumdb names. The tree and hashes are set
// when the database answered; File and Computed are set on a refusal at the
// fetch, naming the file whose bytes disagreed and the hash they computed to.
type ChecksumDatabase struct {
	Outcome  string `json:"outcome"`
	Database string `json:"database,omitempty"`
	TreeSize int64  `json:"tree_size,omitempty"`
	TreeHash string `json:"tree_hash,omitempty"`
	// ZipHash and ModHash are the h1: hashes the database holds for the
	// module zip and for its go.mod alone.
	ZipHash  string `json:"zip_hash,omitempty"`
	ModHash  string `json:"mod_hash,omitempty"`
	File     string `json:"file,omitempty"`
	Computed string `json:"computed,omitempty"`
}

// Admission is one decision on one version.
// The JSON names are the column names, as on the write-only sinks' records.
type Admission struct {
	ID           int64            `json:"id"`
	PkgType      string           `json:"pkg_type"`
	PkgName      string           `json:"pkg_name"`
	PkgVersion   string           `json:"pkg_version"`
	ObjectKey    string           `json:"object_key"` // empty until the digest is pinned
	Decision     string           `json:"decision"`
	Checks       []AdmissionCheck `json:"checks"`
	PolicyDigest string           `json:"policy_digest"`
	Actor        string           `json:"actor"`
	Identity     string           `json:"identity"`
	DecidedAt    time.Time        `json:"decided_at"`
}

// Evaluated reports whether any check on the row ran. A row a pin wrote with
// no decision behind it carries only not_evaluated checks and an empty digest,
// and a consumer citing rows as evidence must refuse it.
func (a Admission) Evaluated() bool {
	for _, c := range a.Checks {
		if c.Status != CheckNotEvaluated {
			return true
		}
	}
	return false
}

// AdmissionFilter selects admission rows. PkgType and PkgName are required by
// the CLI but not here; an empty field matches everything.
type AdmissionFilter struct {
	PkgType    string
	PkgName    string
	PkgVersion string
	// ObjectKey keeps rows pinned under that key. In AdmittedVersions it
	// selects the unversioned object at that key and no version.
	ObjectKey string
	// Since keeps rows decided at or after it; zero keeps every row.
	Since time.Time
	Limit int // 0 = default (1000)
}

// AdmissionPin names the object a version's digest was pinned under.
type AdmissionPin struct {
	PkgType    string
	PkgName    string
	PkgVersion string
	ObjectKey  string
	// Admitted is the decision the pinning fetch was admitted under, when the
	// caller holds it. The newest admitted row stands in for it only when both
	// carry the same checksum_database entry; otherwise the pin attaches to the
	// newest row that does, or to none. Two fetches of one module version can
	// overlap, and bytes never compared with the checksum database must not be
	// pinned, then signed, under another fetch's verified comparison. With
	// Admitted nil, a row whose checksum_database outcome is verified is never
	// attached to a new object: ErrUnboundChecksumEvidence.
	Admitted *Admission
}

// ErrUnboundChecksumEvidence is PinAdmission refusing to attach an object to a
// row whose checksum_database outcome is verified when the caller named no
// admission: verified says the object's bytes were compared with the signed
// hashes, and a pin that names no admission proves no comparison ran. The
// caller compares the bytes and names the row, or the object goes unattached.
var ErrUnboundChecksumEvidence = errors.New("a verified checksum database row is attached only to bytes compared under it, and this pin names no admission")

// admissionPinResult is what a queryable sink found when it tried to attach a
// pin. Found is false when the version has no admitted row; Attached is true
// when the sink wrote something, as opposed to finding the key already there.
type admissionPinResult struct {
	Found    bool
	Attached bool
	Row      Admission
}

// PinOutcome is what DB.PinAdmission did with a pin.
type PinOutcome int

const (
	// PinAttached means an evaluated decision for the version now carries the
	// object key, or already did.
	PinAttached PinOutcome = iota
	// PinUnadmitted means no evaluated decision covered the version, so a row
	// whose checks are all not_evaluated was written for the key. The caller
	// logs a WARN.
	PinUnadmitted
	// PinUnverified means the sink keeps no table to look in (syslog, jsonl)
	// or the store is read-only. The pin was emitted where it could be, and
	// whether a decision preceded it is for whatever reads the stream.
	PinUnverified
)

// RecordAdmission writes one decision to the configured sink. It is not
// subject to audit_events: that list selects which event types an operator
// wants in the trail, and a decision missing from this table is a version no
// attestation can cite, whatever the operator chose to keep of the events.
// A principal in ctx names the actor and identity, as it does for Record.
func (a *DB) RecordAdmission(ctx context.Context, row Admission) error {
	if a.readOnly {
		return nil
	}
	if p, ok := PrincipalFrom(ctx); ok {
		row.Actor, row.Identity = p.Subject, p.Issuer
	}
	if !ValidAdmissionDecision(row.Decision) {
		return fmt.Errorf("admission decision %q is outside the set (%s, %s, %s)", row.Decision, AdmissionAdmitted, AdmissionPolicyBlocked, AdmissionInvalid)
	}
	if row.DecidedAt.IsZero() {
		row.DecidedAt = time.Now()
	}
	row.DecidedAt = row.DecidedAt.UTC()
	return a.sink.RecordAdmission(ctx, row)
}

// PinAdmission attaches objectKey to the newest admitted decision for the
// version. With none to attach to, it writes a row for the key whose checks
// all say not_evaluated, and reports PinUnadmitted so the caller can say so:
// bytes reached the store with no decision behind them, and a fabricated pass
// would hide exactly that.
func (a *DB) PinAdmission(ctx context.Context, p AdmissionPin) (PinOutcome, error) {
	if a.readOnly {
		return PinUnverified, nil
	}
	if _, ok := a.sink.(EventReader); !ok {
		return PinUnverified, a.sink.PinAdmission(ctx, p)
	}
	res, err := a.sink.(admissionPinner).pinAdmission(ctx, p)
	if err != nil {
		return PinAttached, err
	}
	if res.Found {
		if res.Attached && !res.Row.Evaluated() {
			return PinUnadmitted, nil
		}
		return PinAttached, nil
	}
	return PinUnadmitted, a.RecordAdmission(ctx, Admission{
		PkgType:    p.PkgType,
		PkgName:    p.PkgName,
		PkgVersion: p.PkgVersion,
		ObjectKey:  p.ObjectKey,
		Decision:   AdmissionAdmitted,
		Checks:     NotEvaluatedChecksFor(p.PkgType, "pinned with no admission decision on record for this version"),
	})
}

// Admissions returns decisions matching f, newest first.
func (a *DB) Admissions(ctx context.Context, f AdmissionFilter) ([]Admission, error) {
	r, err := a.reader("admission decisions")
	if err != nil {
		return nil, err
	}
	rows, err := r.QueryAdmissions(ctx, f)
	if err != nil {
		return nil, err
	}
	if a.location != nil {
		for i := range rows {
			rows[i].DecidedAt = rows[i].DecidedAt.In(a.location)
		}
	}
	return rows, nil
}

// AdmittedVersions lists, once each and sorted, every version f selects that
// the table holds an admitted or pinned decision for. A version whose only
// rows are refusals with no object behind them was never served, and is left
// out. f.Limit is ignored: the list is the set of versions, not of rows.
//
// A row with no version is listed once per object key it was pinned under,
// with ObjectKey set: a distfile or a binary whose key names no version
// shares (type, name, "") with every sibling file, so only the key tells them
// apart. One with no key either is a decision about the package, not about
// anything served, and is left out. A version filter selects none of these.
func (a *DB) AdmittedVersions(ctx context.Context, f AdmissionFilter) ([]AdmissionPin, error) {
	r, err := a.reader("admission decisions")
	if err != nil {
		return nil, err
	}
	l, ok := r.(admittedVersionLister)
	if !ok {
		return nil, &UnqueryableSinkError{Sink: a.sink.Name(), Op: "admitted versions"}
	}
	return l.admittedVersions(ctx, f)
}

// admittedVersionLister is the half of a queryable sink that answers
// AdmittedVersions. It sits outside EventReader so a reader that keeps no
// admissions table need not grow a method to say so.
type admittedVersionLister interface {
	admittedVersions(ctx context.Context, f AdmissionFilter) ([]AdmissionPin, error)
}

// buildAdmittedVersionsQuery renders AdmittedVersions' read. ph renders the
// nth bind placeholder, as in pinTx.
func buildAdmittedVersionsQuery(f AdmissionFilter, ph func(int) string) (string, []any) {
	var args []any
	match := func(where []string, cols ...struct{ col, val string }) string {
		for _, c := range cols {
			if c.val == "" {
				continue
			}
			args = append(args, c.val)
			where = append(where, c.col+" = "+ph(len(args)))
		}
		return strings.Join(where, " AND ")
	}
	typ, name := struct{ col, val string }{"pkg_type", f.PkgType}, struct{ col, val string }{"pkg_name", f.PkgName}
	var parts []string
	if f.ObjectKey == "" {
		parts = append(parts, `SELECT pkg_type, pkg_name, pkg_version, '' AS object_key FROM admissions WHERE `+
			match([]string{"pkg_version <> ''", "(decision = 'admitted' OR object_key IS NOT NULL)"},
				typ, name, struct{ col, val string }{"pkg_version", f.PkgVersion})+
			` GROUP BY pkg_type, pkg_name, pkg_version`)
	}
	if f.PkgVersion == "" {
		parts = append(parts, `SELECT pkg_type, pkg_name, pkg_version, object_key FROM admissions WHERE `+
			match([]string{"pkg_version = ''", "object_key IS NOT NULL", "object_key <> ''"},
				typ, name, struct{ col, val string }{"object_key", f.ObjectKey})+
			` GROUP BY pkg_type, pkg_name, pkg_version, object_key`)
	}
	if len(parts) == 0 {
		return `SELECT pkg_type, pkg_name, pkg_version, object_key FROM admissions WHERE 1 = 0`, nil
	}
	return strings.Join(parts, " UNION ALL ") + ` ORDER BY 1, 2, 3, 4`, args
}

func scanAdmittedVersions(rows *sql.Rows) ([]AdmissionPin, error) {
	defer rows.Close()
	var out []AdmissionPin
	for rows.Next() {
		var p AdmissionPin
		if err := rows.Scan(&p.PkgType, &p.PkgName, &p.PkgVersion, &p.ObjectKey); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// NotEvaluatedChecks is the check list of a decision that evaluated nothing,
// every entry carrying the same reason.
func NotEvaluatedChecks(detail string) []AdmissionCheck {
	return []AdmissionCheck{
		{Check: CheckAllowList, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
		{Check: CheckAge, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
		{Check: CheckOSV, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
		{Check: CheckUpstreamProvenance, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
		{Check: CheckNameSimilarity, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
	}
}

// NotEvaluatedChecksFor is NotEvaluatedChecks for a row of typ: a gomod row
// also carries checksum_database, after upstream_provenance, as every gomod
// admission row does.
func NotEvaluatedChecksFor(typ, detail string) []AdmissionCheck {
	checks := NotEvaluatedChecks(detail)
	if typ != gomodType {
		return checks
	}
	for i, c := range checks {
		if c.Check == CheckUpstreamProvenance {
			sumdb := AdmissionCheck{Check: CheckChecksumDatabase, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail}
			return append(checks[:i+1], append([]AdmissionCheck{sumdb}, checks[i+1:]...)...)
		}
	}
	return checks
}

// gomodType is manifest.TypeGomod, which audit cannot import.
const gomodType = "gomod"

// ValidAdmissionDecision reports whether d is one of the three decisions.
func ValidAdmissionDecision(d string) bool {
	switch d {
	case AdmissionAdmitted, AdmissionPolicyBlocked, AdmissionInvalid:
		return true
	}
	return false
}

// admissionPinner is the pin half a queryable sink implements. It is separate
// from EventSink.PinAdmission because only a sink with a table can say whether
// a decision was found, and DB needs that answer to decide whether to write
// the not_evaluated row.
type admissionPinner interface {
	pinAdmission(ctx context.Context, p AdmissionPin) (admissionPinResult, error)
}

// encodeChecks renders the checks column. A nil list is stored as [] so a
// reader never has to tell "no checks" from "column empty".
func encodeChecks(checks []AdmissionCheck) (string, error) {
	if checks == nil {
		checks = []AdmissionCheck{}
	}
	b, err := json.Marshal(checks)
	return string(b), err
}

func decodeChecks(s string) ([]AdmissionCheck, error) {
	var out []AdmissionCheck
	if s == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("decode admission checks: %w", err)
	}
	return out, nil
}

// sqliteDecidedAt is the stored form of decided_at. Fixed-width rather than
// RFC3339Nano, which drops trailing zeros: the newest-first order is a string
// comparison in SQLite, and "…05.1Z" sorts after "…05.12Z".
const sqliteDecidedAt = "2006-01-02T15:04:05.000000Z"

// pinTx is the shared pin logic over one transaction. ph renders the nth bind
// placeholder, which is the one difference between the two SQL dialects here.
//
// A version with an admitted row whose key is already another object (a
// second wheel of one pypi release, say) gets a copy of that decision carrying
// the new key, rather than a second key overwriting the first.
func pinTx(ctx context.Context, tx *sql.Tx, p AdmissionPin, ph func(int) string, forUpdate string, parseTime func(any) time.Time) (admissionPinResult, error) {
	q := `SELECT id, object_key, checks, policy_digest, actor, identity, decided_at FROM admissions
		WHERE pkg_type = ` + ph(1) + ` AND pkg_name = ` + ph(2) + ` AND pkg_version = ` + ph(3) + ` AND decision = 'admitted'
		ORDER BY decided_at DESC, id DESC LIMIT `
	rows, err := tx.QueryContext(ctx, q+"1"+forUpdate, p.PkgType, p.PkgName, p.PkgVersion)
	if err != nil {
		return admissionPinResult{}, err
	}
	row, key, found, err := pinCandidate(rows, p, nil, parseTime)
	if err != nil || !found {
		return admissionPinResult{}, err
	}
	if p.Admitted != nil && !sameChecksumEvidence(row.Checks, p.Admitted.Checks) {
		rows, err := tx.QueryContext(ctx, q+"200"+forUpdate, p.PkgType, p.PkgName, p.PkgVersion)
		if err != nil {
			return admissionPinResult{}, err
		}
		if row, key, found, err = pinCandidate(rows, p, p.Admitted, parseTime); err != nil || !found {
			return admissionPinResult{}, err
		}
	}

	unbound := p.Admitted == nil && key.String != p.ObjectKey && verifiedChecksumEvidence(row.Checks)
	switch {
	case unbound:
		return admissionPinResult{}, fmt.Errorf("%w: %s/%s@%s, object %s", ErrUnboundChecksumEvidence, p.PkgType, p.PkgName, p.PkgVersion, p.ObjectKey)
	case !key.Valid:
		//nolint:gosec // G202: only bind placeholders are concatenated; every value is bound.
		if _, err := tx.ExecContext(ctx, `UPDATE admissions SET object_key = `+ph(1)+` WHERE id = `+ph(2), p.ObjectKey, row.ID); err != nil {
			return admissionPinResult{}, err
		}
		row.ObjectKey = p.ObjectKey
		return admissionPinResult{Found: true, Attached: true, Row: row}, nil
	case key.String == p.ObjectKey:
		return admissionPinResult{Found: true, Row: row}, nil
	}

	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM admissions
		WHERE pkg_type = `+ph(1)+` AND pkg_name = `+ph(2)+` AND pkg_version = `+ph(3)+` AND decision = 'admitted' AND object_key = `+ph(4)+` LIMIT 1`,
		p.PkgType, p.PkgName, p.PkgVersion, p.ObjectKey).Scan(&one)
	if err == nil {
		return admissionPinResult{Found: true, Row: row}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return admissionPinResult{}, err
	}
	//nolint:gosec // G202: only bind placeholders are concatenated; every value is bound.
	if _, err := tx.ExecContext(ctx, `INSERT INTO admissions
		(pkg_type, pkg_name, pkg_version, object_key, decision, checks, policy_digest, actor, identity, decided_at)
		SELECT pkg_type, pkg_name, pkg_version, `+ph(1)+`, decision, checks, policy_digest, actor, identity, decided_at
		FROM admissions WHERE id = `+ph(2), p.ObjectKey, row.ID); err != nil {
		return admissionPinResult{}, err
	}
	row.ObjectKey = p.ObjectKey
	return admissionPinResult{Found: true, Attached: true, Row: row}, nil
}

// pinCandidate reads rows newest first and returns the first whose
// checksum_database entry matches admitted's, or the first row at all when
// admitted is nil. It closes rows.
func pinCandidate(rows *sql.Rows, p AdmissionPin, admitted *Admission, parseTime func(any) time.Time) (Admission, sql.NullString, bool, error) {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			row     = Admission{PkgType: p.PkgType, PkgName: p.PkgName, PkgVersion: p.PkgVersion, Decision: AdmissionAdmitted}
			key     sql.NullString
			checks  string
			decided any
		)
		if err := rows.Scan(&row.ID, &key, &checks, &row.PolicyDigest, &row.Actor, &row.Identity, &decided); err != nil {
			return Admission{}, key, false, err
		}
		var err error
		if row.Checks, err = decodeChecks(checks); err != nil {
			return Admission{}, key, false, err
		}
		if admitted != nil && !sameChecksumEvidence(row.Checks, admitted.Checks) {
			continue
		}
		row.DecidedAt = parseTime(decided)
		row.ObjectKey = key.String
		return row, key, true, rows.Close()
	}
	return Admission{}, sql.NullString{}, false, rows.Err()
}

// verifiedChecksumEvidence reports whether checks carry a checksum_database
// entry whose outcome is verified.
func verifiedChecksumEvidence(checks []AdmissionCheck) bool {
	for _, c := range checks {
		if c.Check == CheckChecksumDatabase && c.ChecksumDatabase != nil && c.ChecksumDatabase.Outcome == ProvenanceVerified {
			return true
		}
	}
	return false
}

// ChecksumComparison is a caller vouching that the bytes whose SHA-256 is
// SHA256 were fetched under Checks: compared with the hashes in its
// checksum_database entry and matched, where that entry is verified.
type ChecksumComparison struct {
	SHA256 string
	Checks []AdmissionCheck
}

// AdmissionLister is the read DB.Admissions serves.
type AdmissionLister interface {
	Admissions(ctx context.Context, f AdmissionFilter) ([]Admission, error)
}

// ComparedAdmissions is Reader with every row whose checksum_database outcome
// is verified withheld, unless Compared vouches for SHA256 under that row's
// evidence. A signer reading the newest row for a version would otherwise sign
// any digest pinned under the version's object key with whichever fetch
// verified last: two fetches of one key can carry different bytes and
// different evidence, and the key names neither. Rows no comparison could
// support (any other outcome) pass through, because they claim nothing about
// the bytes.
type ComparedAdmissions struct {
	Reader   AdmissionLister
	SHA256   string
	Compared *ChecksumComparison
}

// Admissions reads Reader and drops what the comparison does not support.
func (c ComparedAdmissions) Admissions(ctx context.Context, f AdmissionFilter) ([]Admission, error) {
	rows, err := c.Reader.Admissions(ctx, f)
	if err != nil {
		return nil, err
	}
	out := rows[:0:0]
	for _, r := range rows {
		if verifiedChecksumEvidence(r.Checks) && !c.vouches(r) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (c ComparedAdmissions) vouches(r Admission) bool {
	return c.Compared != nil && c.SHA256 != "" && strings.EqualFold(c.Compared.SHA256, c.SHA256) &&
		sameChecksumEvidence(r.Checks, c.Compared.Checks)
}

// sameChecksumEvidence reports whether a and b carry the same checksum_database
// entry, status, detail and hashes included, or neither carries one.
func sameChecksumEvidence(a, b []AdmissionCheck) bool {
	entry := func(checks []AdmissionCheck) string {
		for _, c := range checks {
			if c.Check == CheckChecksumDatabase {
				raw, _ := json.Marshal(c)
				return string(raw)
			}
		}
		return ""
	}
	return entry(a) == entry(b)
}

// buildAdmissionQuery renders the newest-first read for f. ph renders the nth
// bind placeholder, as in pinTx; since renders f.Since in the form the
// dialect's decided_at column compares against.
func buildAdmissionQuery(f AdmissionFilter, ph func(int) string, since func(time.Time) any) (string, []any) {
	var (
		where []string
		args  []any
	)
	for _, c := range []struct{ col, val string }{
		{"pkg_type", f.PkgType}, {"pkg_name", f.PkgName}, {"pkg_version", f.PkgVersion}, {"object_key", f.ObjectKey},
	} {
		if c.val == "" {
			continue
		}
		args = append(args, c.val)
		where = append(where, c.col+" = "+ph(len(args)))
	}
	if !f.Since.IsZero() {
		args = append(args, since(f.Since.UTC()))
		where = append(where, "decided_at >= "+ph(len(args)))
	}
	q := `SELECT id, pkg_type, pkg_name, pkg_version, object_key, decision, checks, policy_digest, actor, identity, decided_at FROM admissions`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY decided_at DESC, id DESC LIMIT %d", effectiveLimit(f.Limit))
	return q, args
}

// scanAdmissions reads the rows buildAdmissionQuery selects.
func scanAdmissions(rows *sql.Rows, parseTime func(any) time.Time) ([]Admission, error) {
	defer rows.Close()
	var out []Admission
	for rows.Next() {
		var (
			a       Admission
			key     sql.NullString
			checks  string
			decided any
		)
		if err := rows.Scan(&a.ID, &a.PkgType, &a.PkgName, &a.PkgVersion, &key, &a.Decision,
			&checks, &a.PolicyDigest, &a.Actor, &a.Identity, &decided); err != nil {
			return nil, err
		}
		var err error
		if a.Checks, err = decodeChecks(checks); err != nil {
			return nil, err
		}
		a.ObjectKey = key.String
		a.DecidedAt = parseTime(decided)
		out = append(out, a)
	}
	return out, rows.Err()
}

// nullKey stores an empty object key as NULL, which is what "not yet pinned"
// means in the column.
func nullKey(k string) sql.NullString {
	return sql.NullString{String: k, Valid: k != ""}
}
