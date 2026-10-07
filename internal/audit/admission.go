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
	// CheckOverride is the operator answering y to `bodega pkg create`'s
	// allow-list prompt. It is its own entry so the allow-list entry beside it
	// can still say block: the row records that the rule refused and who
	// overrode it, not a pass nobody evaluated.
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
	Limit      int // 0 = default (1000)
}

// AdmissionPin names the object a version's digest was pinned under.
type AdmissionPin struct {
	PkgType    string
	PkgName    string
	PkgVersion string
	ObjectKey  string
}

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
func (a *DB) RecordAdmission(ctx context.Context, row Admission) error {
	if a.readOnly {
		return nil
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
		Checks:     NotEvaluatedChecks("pinned with no admission decision on record for this version"),
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

// NotEvaluatedChecks is the check list of a decision that evaluated nothing,
// every entry carrying the same reason.
func NotEvaluatedChecks(detail string) []AdmissionCheck {
	return []AdmissionCheck{
		{Check: CheckAllowList, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
		{Check: CheckAge, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
		{Check: CheckOSV, Action: ActionNone, Status: CheckNotEvaluated, Detail: detail},
	}
}

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
		ORDER BY decided_at DESC, id DESC LIMIT 1` + forUpdate
	var (
		row     = Admission{PkgType: p.PkgType, PkgName: p.PkgName, PkgVersion: p.PkgVersion, Decision: AdmissionAdmitted}
		key     sql.NullString
		checks  string
		decided any
	)
	err := tx.QueryRowContext(ctx, q, p.PkgType, p.PkgName, p.PkgVersion).
		Scan(&row.ID, &key, &checks, &row.PolicyDigest, &row.Actor, &row.Identity, &decided)
	if errors.Is(err, sql.ErrNoRows) {
		return admissionPinResult{}, nil
	}
	if err != nil {
		return admissionPinResult{}, err
	}
	if row.Checks, err = decodeChecks(checks); err != nil {
		return admissionPinResult{}, err
	}
	row.DecidedAt = parseTime(decided)
	row.ObjectKey = key.String

	switch {
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

// buildAdmissionQuery renders the newest-first read for f. ph renders the nth
// bind placeholder, as in pinTx.
func buildAdmissionQuery(f AdmissionFilter, ph func(int) string) (string, []any) {
	var (
		where []string
		args  []any
	)
	for _, c := range []struct{ col, val string }{
		{"pkg_type", f.PkgType}, {"pkg_name", f.PkgName}, {"pkg_version", f.PkgVersion},
	} {
		if c.val == "" {
			continue
		}
		args = append(args, c.val)
		where = append(where, c.col+" = "+ph(len(args)))
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
