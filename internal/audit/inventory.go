package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// InventoryComponent is one installed component as the store holds it. Its
// fields match inventory.Component one for one, so the inventory package
// converts between the two without copying field by field.
type InventoryComponent struct {
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Path            string `json:"path,omitempty"`
	DigestAlgorithm string `json:"digest_algorithm,omitempty"`
	DigestValue     string `json:"digest_value,omitempty"`
	Origin          string `json:"origin,omitempty"`
	PURL            string `json:"purl,omitempty"`
}

// InventoryReport is one stored report. Seq, PrevSHA256 and SHA256 are
// assigned by AppendInventoryReport; a caller's values for them are ignored.
type InventoryReport struct {
	ID         int64                `json:"id"`
	Source     string               `json:"source"`
	ExternalID string               `json:"external_id"`
	Identity   string               `json:"identity"`
	ObservedAt time.Time            `json:"observed_at"`
	ReceivedAt time.Time            `json:"received_at"`
	Seq        int64                `json:"seq"`
	PrevSHA256 string               `json:"prev_sha256"`
	SHA256     string               `json:"sha256"`
	Components []InventoryComponent `json:"components"`
}

// InventoryAttempt is one piece of evidence that a host reached for a
// package registry without going through bodega.
type InventoryAttempt struct {
	Source      string    `json:"source"`
	ExternalID  string    `json:"external_id"`
	Identity    string    `json:"identity"`
	ObservedAt  time.Time `json:"observed_at"`
	ReceivedAt  time.Time `json:"received_at"`
	Destination string    `json:"destination"`
	Ecosystem   string    `json:"ecosystem,omitempty"`
	Detail      string    `json:"detail,omitempty"`
}

// InventoryHost is one row of the per-source host mapping.
type InventoryHost struct {
	Source     string    `json:"source"`
	ExternalID string    `json:"external_id"`
	Identity   string    `json:"identity"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// UnboundInventoryHost is an external id that has delivered reports and that
// no mapping names.
type UnboundInventoryHost struct {
	Source       string    `json:"source"`
	ExternalID   string    `json:"external_id"`
	Reports      int64     `json:"reports"`
	FirstReport  time.Time `json:"first_report"`
	LatestReport time.Time `json:"latest_report"`
}

// InventorySourceStats is what `bodega inventory sources` prints per instance.
type InventorySourceStats struct {
	LastReport    time.Time
	LastAttempt   time.Time
	LastSuccess   time.Time
	LastError     string
	MappedHosts   int64
	UnboundHosts  int64
	ReportsStored int64
}

// InventoryHostConflict refuses a mapping that would move an external id from
// one identity to another. Unbind first: a host silently changing identity is
// how one host's history ends up under another's name.
type InventoryHostConflict struct {
	Existing InventoryHost
	Want     string
}

func (e *InventoryHostConflict) Error() string {
	return fmt.Sprintf("%s %s is already bound to %q; unbind it first to bind it to %q",
		e.Existing.Source, e.Existing.ExternalID, e.Existing.Identity, e.Want)
}

const inventoryTime = "2006-01-02T15:04:05.000Z"

func invTime(t time.Time) string { return t.UTC().Format(inventoryTime) }

func parseInvTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// InventoryHostIdentity returns the identity an external id is mapped to
// under source, or "" when nothing maps it.
func (a *DB) InventoryHostIdentity(ctx context.Context, source, externalID string) (string, error) {
	var id string
	err := a.db.QueryRowContext(ctx,
		`SELECT identity FROM inventory_hosts WHERE source = ? AND external_id = ?`,
		source, externalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// BindInventoryHost maps an external id to an identity. Binding an id to the
// identity it already has reports false and changes nothing; binding it to a
// different one is refused with *InventoryHostConflict.
func (a *DB) BindInventoryHost(ctx context.Context, source, externalID, identity string) (bool, error) {
	source, externalID, identity = strings.TrimSpace(source), strings.TrimSpace(externalID), strings.TrimSpace(identity)
	if source == "" || externalID == "" || identity == "" {
		return false, errors.New("a host mapping needs a source, an external id and an identity")
	}
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	existing, err := a.InventoryHostIdentity(ctx, source, externalID)
	if err != nil {
		return false, err
	}
	if existing == identity {
		return false, nil
	}
	if existing != "" {
		return false, &InventoryHostConflict{
			Existing: InventoryHost{Source: source, ExternalID: externalID, Identity: existing},
			Want:     identity,
		}
	}
	// first_seen and last_seen describe the host's reports, not the bind, so
	// a host that reported unbound for a week keeps that week.
	now := invTime(time.Now())
	_, err = a.writer().ExecContext(ctx, `
INSERT INTO inventory_hosts (source, external_id, identity, first_seen, last_seen)
SELECT ?, ?, ?,
       COALESCE(MIN(received_at), ?),
       COALESCE(MAX(received_at), ?)
FROM inventory_reports WHERE source = ? AND external_id = ?`,
		source, externalID, identity, now, now, source, externalID)
	if err != nil {
		return false, err
	}
	return true, nil
}

// UnbindInventoryHost removes a mapping, reporting whether it was there.
// Reports already stored keep the identity they were stored under.
func (a *DB) UnbindInventoryHost(ctx context.Context, source, externalID string) (bool, error) {
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	res, err := a.writer().ExecContext(ctx,
		`DELETE FROM inventory_hosts WHERE source = ? AND external_id = ?`, source, externalID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ListInventoryHosts returns every mapping, ordered by source then id.
func (a *DB) ListInventoryHosts(ctx context.Context) ([]InventoryHost, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT source, external_id, identity, first_seen, last_seen FROM inventory_hosts ORDER BY source, external_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryHost
	for rows.Next() {
		var h InventoryHost
		var first, last string
		if err := rows.Scan(&h.Source, &h.ExternalID, &h.Identity, &first, &last); err != nil {
			return nil, err
		}
		h.FirstSeen, h.LastSeen = parseInvTime(first), parseInvTime(last)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListUnboundInventoryHosts returns the external ids that have reported and
// that no mapping names. A report stored unbound stays unbound in its row,
// so this reads the mapping table now rather than the identity column.
func (a *DB) ListUnboundInventoryHosts(ctx context.Context) ([]UnboundInventoryHost, error) {
	rows, err := a.db.QueryContext(ctx, `
SELECT r.source, r.external_id, COUNT(*), MIN(r.received_at), MAX(r.received_at)
FROM inventory_reports r
WHERE NOT EXISTS (SELECT 1 FROM inventory_hosts h WHERE h.source = r.source AND h.external_id = r.external_id)
GROUP BY r.source, r.external_id
ORDER BY r.source, r.external_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnboundInventoryHost
	for rows.Next() {
		var u UnboundInventoryHost
		var first, last string
		if err := rows.Scan(&u.Source, &u.ExternalID, &u.Reports, &first, &last); err != nil {
			return nil, err
		}
		u.FirstReport, u.LatestReport = parseInvTime(first), parseInvTime(last)
		out = append(out, u)
	}
	return out, rows.Err()
}

// reportDigest is the SHA-256 a report is chained by. It covers prev_sha256,
// so each row commits to the one before it under the same chain key.
func reportDigest(r InventoryReport) (string, error) {
	r.ID, r.SHA256 = 0, ""
	r.ObservedAt, r.ReceivedAt = r.ObservedAt.UTC(), r.ReceivedAt.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// AppendInventoryReport stores one report and its components in a single
// transaction, assigning its sequence number and chaining it to the previous
// report from the same host under the same source. The returned report
// carries the assigned ID, Seq, PrevSHA256 and SHA256.
//
// A report for a mapped host also moves that mapping's last_seen. That is
// the only write this path makes outside the append-only tables.
func (a *DB) AppendInventoryReport(ctx context.Context, r InventoryReport) (InventoryReport, error) {
	if a.readOnly {
		return r, errors.New("audit db is read-only")
	}
	if r.Source == "" || r.ExternalID == "" {
		return r, errors.New("an inventory report needs a source and an external id")
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer func() { _ = tx.Rollback() }()

	// Bound reports chain on the identity, so a host re-enrolled under a new
	// external id continues its own history. An unbound report has no
	// identity to chain on and chains on its external id instead.
	var (
		prevSeq int64
		prevSum string
	)
	err = tx.QueryRowContext(ctx, `
SELECT seq, sha256 FROM inventory_reports
WHERE source = ? AND identity = ? AND (identity <> '' OR external_id = ?)
ORDER BY seq DESC, id DESC LIMIT 1`,
		r.Source, r.Identity, r.ExternalID).Scan(&prevSeq, &prevSum)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	r.Seq, r.PrevSHA256 = prevSeq+1, prevSum
	if r.SHA256, err = reportDigest(r); err != nil {
		return r, err
	}

	res, err := tx.ExecContext(ctx, `
INSERT INTO inventory_reports (source, external_id, identity, observed_at, received_at, seq, prev_sha256, sha256)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Source, r.ExternalID, r.Identity, invTime(r.ObservedAt), invTime(r.ReceivedAt), r.Seq, r.PrevSHA256, r.SHA256)
	if err != nil {
		return r, err
	}
	if r.ID, err = res.LastInsertId(); err != nil {
		return r, err
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO inventory_components (report_id, ecosystem, name, version, path, digest_alg, digest, origin, purl)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return r, err
	}
	defer func() { _ = stmt.Close() }()
	for _, c := range r.Components {
		if _, err := stmt.ExecContext(ctx, r.ID, c.Ecosystem, c.Name, c.Version, c.Path,
			c.DigestAlgorithm, c.DigestValue, c.Origin, c.PURL); err != nil {
			return r, err
		}
	}
	if r.Identity != "" {
		if _, err := tx.ExecContext(ctx,
			`UPDATE inventory_hosts SET last_seen = ? WHERE source = ? AND external_id = ?`,
			invTime(r.ReceivedAt), r.Source, r.ExternalID); err != nil {
			return r, err
		}
	}
	return r, tx.Commit()
}

// InventoryReports returns the stored reports for one source, oldest first,
// with their components. An empty source returns every source's.
func (a *DB) InventoryReports(ctx context.Context, source string) ([]InventoryReport, error) {
	rows, err := a.db.QueryContext(ctx, `
SELECT id, source, external_id, identity, observed_at, received_at, seq, prev_sha256, sha256
FROM inventory_reports WHERE (? = '' OR source = ?) ORDER BY id`, source, source)
	if err != nil {
		return nil, err
	}
	var out []InventoryReport
	index := map[int64]int{}
	for rows.Next() {
		var r InventoryReport
		var obs, rec string
		if err := rows.Scan(&r.ID, &r.Source, &r.ExternalID, &r.Identity, &obs, &rec, &r.Seq, &r.PrevSHA256, &r.SHA256); err != nil {
			rows.Close()
			return nil, err
		}
		r.ObservedAt, r.ReceivedAt = parseInvTime(obs), parseInvTime(rec)
		index[r.ID] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	crows, err := a.db.QueryContext(ctx, `
SELECT c.report_id, c.ecosystem, c.name, c.version, c.path, c.digest_alg, c.digest, c.origin, c.purl
FROM inventory_components c JOIN inventory_reports r ON r.id = c.report_id
WHERE (? = '' OR r.source = ?) ORDER BY c.rowid`, source, source)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var id int64
		var c InventoryComponent
		if err := crows.Scan(&id, &c.Ecosystem, &c.Name, &c.Version, &c.Path, &c.DigestAlgorithm, &c.DigestValue, &c.Origin, &c.PURL); err != nil {
			return nil, err
		}
		if i, ok := index[id]; ok {
			out[i].Components = append(out[i].Components, c)
		}
	}
	return out, crows.Err()
}

// AppendInventoryAttempts stores attempt evidence.
func (a *DB) AppendInventoryAttempts(ctx context.Context, attempts []InventoryAttempt) error {
	if len(attempts) == 0 {
		return nil
	}
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, at := range attempts {
		if at.Source == "" || at.ExternalID == "" || at.Destination == "" {
			return errors.New("an inventory attempt needs a source, an external id and a destination")
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO inventory_attempts (source, external_id, identity, observed_at, received_at, destination, ecosystem, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			at.Source, at.ExternalID, at.Identity, invTime(at.ObservedAt), invTime(at.ReceivedAt),
			at.Destination, at.Ecosystem, at.Detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InventoryAttempts returns the stored attempts for one source, oldest first.
// An empty source returns every source's.
func (a *DB) InventoryAttempts(ctx context.Context, source string) ([]InventoryAttempt, error) {
	rows, err := a.db.QueryContext(ctx, `
SELECT source, external_id, identity, observed_at, received_at, destination, ecosystem, detail
FROM inventory_attempts WHERE (? = '' OR source = ?) ORDER BY id`, source, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryAttempt
	for rows.Next() {
		var at InventoryAttempt
		var obs, rec string
		if err := rows.Scan(&at.Source, &at.ExternalID, &at.Identity, &obs, &rec, &at.Destination, &at.Ecosystem, &at.Detail); err != nil {
			return nil, err
		}
		at.ObservedAt, at.ReceivedAt = parseInvTime(obs), parseInvTime(rec)
		out = append(out, at)
	}
	return out, rows.Err()
}

// RecordInventoryPoll records one poll of a pull source. A nil pollErr is a
// success and moves last_success_at; a failure keeps the last success, which
// is what a staleness check reads.
func (a *DB) RecordInventoryPoll(ctx context.Context, source string, at time.Time, pollErr error) error {
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	ts := invTime(at)
	if pollErr == nil {
		_, err := a.writer().ExecContext(ctx, `
INSERT INTO inventory_source_polls (source, last_attempt_at, last_success_at, last_error) VALUES (?, ?, ?, '')
ON CONFLICT(source) DO UPDATE SET last_attempt_at = excluded.last_attempt_at,
    last_success_at = excluded.last_success_at, last_error = ''`, source, ts, ts)
		return err
	}
	_, err := a.writer().ExecContext(ctx, `
INSERT INTO inventory_source_polls (source, last_attempt_at, last_error) VALUES (?, ?, ?)
ON CONFLICT(source) DO UPDATE SET last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error`,
		source, ts, pollErr.Error())
	return err
}

// InventorySourceStats summarizes one source instance for inspection.
func (a *DB) InventorySourceStats(ctx context.Context, source string) (InventorySourceStats, error) {
	var st InventorySourceStats
	var lastReport, lastAttempt, lastSuccess sql.NullString
	if err := a.db.QueryRowContext(ctx,
		`SELECT MAX(received_at), COUNT(*) FROM inventory_reports WHERE source = ?`, source,
	).Scan(&lastReport, &st.ReportsStored); err != nil {
		return st, err
	}
	st.LastReport = parseInvTime(lastReport.String)
	err := a.db.QueryRowContext(ctx,
		`SELECT last_attempt_at, last_success_at, last_error FROM inventory_source_polls WHERE source = ?`, source,
	).Scan(&lastAttempt, &lastSuccess, &st.LastError)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}
	st.LastAttempt, st.LastSuccess = parseInvTime(lastAttempt.String), parseInvTime(lastSuccess.String)
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM inventory_hosts WHERE source = ?`, source).Scan(&st.MappedHosts); err != nil {
		return st, err
	}
	if err := a.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT r.external_id) FROM inventory_reports r
WHERE r.source = ? AND NOT EXISTS (SELECT 1 FROM inventory_hosts h WHERE h.source = r.source AND h.external_id = r.external_id)`,
		source).Scan(&st.UnboundHosts); err != nil {
		return st, err
	}
	return st, nil
}

// PruneInventory deletes one source's reports, components and attempts
// received before cutoff. It is the only path that removes a row from the
// three append-only tables, and only the retention setting calls it.
func (a *DB) PruneInventory(ctx context.Context, source string, cutoff time.Time) (int64, error) {
	if a.readOnly {
		return 0, errors.New("audit db is read-only")
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	ts := invTime(cutoff)
	if _, err := tx.ExecContext(ctx, `
DELETE FROM inventory_components WHERE report_id IN
    (SELECT id FROM inventory_reports WHERE source = ? AND received_at < ?)`, source, ts); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`DELETE FROM inventory_reports WHERE source = ? AND received_at < ?`, source, ts)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	res, err = tx.ExecContext(ctx,
		`DELETE FROM inventory_attempts WHERE source = ? AND received_at < ?`, source, ts)
	if err != nil {
		return 0, err
	}
	m, _ := res.RowsAffected()
	return n + m, tx.Commit()
}
