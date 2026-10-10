package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// EventInventory is a reconciliation finding on an inventory report. Status
// says which: InventoryBypass when the report holds a refused or unknown
// component, InventoryDisagreement when two sources disagree about the host.
const EventInventory EventType = "inventory"

const (
	InventoryBypass       = "bypass"
	InventoryDisagreement = "source_disagreement"
)

// ClassifiedComponent is one component of a report with the class it was
// given when the report arrived, and why.
type ClassifiedComponent struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
	Class     string `json:"class"`
	Reason    string `json:"reason"`
}

// SourceDisagreement is a component one source instance reports for a host
// and another enabled instance covering that ecosystem on the host does not.
type SourceDisagreement struct {
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	ReportedBy string `json:"reported_by"`
	ReportedIn int64  `json:"reported_in"`
	AbsentFrom string `json:"absent_from"`
	AbsentIn   int64  `json:"absent_in"`
}

// InventoryClassification is what reconciliation recorded for one report.
type InventoryClassification struct {
	ReportID      int64                 `json:"report_id"`
	Source        string                `json:"source"`
	Identity      string                `json:"identity"`
	ClassifiedAt  time.Time             `json:"classified_at"`
	Components    []ClassifiedComponent `json:"components"`
	Disagreements []SourceDisagreement  `json:"disagreements"`
}

// RecordInventoryClassification stores a report's classification. A report
// is classified once; a second write for the same report is refused, so a
// class recorded at arrival is never replaced by one computed later.
func (a *DB) RecordInventoryClassification(ctx context.Context, c InventoryClassification) error {
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	comps, err := json.Marshal(nonNil(c.Components))
	if err != nil {
		return err
	}
	dis, err := json.Marshal(nonNil(c.Disagreements))
	if err != nil {
		return err
	}
	_, err = a.writer().ExecContext(ctx, `
INSERT INTO inventory_classifications (report_id, source, identity, classified_at, components, disagreements)
VALUES (?, ?, ?, ?, ?, ?)`,
		c.ReportID, c.Source, c.Identity, invTime(c.ClassifiedAt), string(comps), string(dis))
	return err
}

// InventoryClassifications returns the recorded classification of each named
// report that has one, keyed by report id.
func (a *DB) InventoryClassifications(ctx context.Context, reportIDs []int64) (map[int64]InventoryClassification, error) {
	out := map[int64]InventoryClassification{}
	if len(reportIDs) == 0 {
		return out, nil
	}
	//nolint:gosec // G202: the IN list is placeholders only; every value is bound.
	rows, err := a.db.QueryContext(ctx, `
SELECT report_id, source, identity, classified_at, components, disagreements
FROM inventory_classifications WHERE report_id IN (`+placeholders(len(reportIDs))+`)`, int64Args(reportIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c InventoryClassification
		var at, comps, dis string
		if err := rows.Scan(&c.ReportID, &c.Source, &c.Identity, &at, &comps, &dis); err != nil {
			return nil, err
		}
		c.ClassifiedAt = parseInvTime(at)
		if err := json.Unmarshal([]byte(comps), &c.Components); err != nil {
			return nil, fmt.Errorf("classification of report %d: %w", c.ReportID, err)
		}
		if err := json.Unmarshal([]byte(dis), &c.Disagreements); err != nil {
			return nil, fmt.Errorf("disagreements of report %d: %w", c.ReportID, err)
		}
		out[c.ReportID] = c
	}
	return out, rows.Err()
}

// LatestInventoryReports returns, for each source instance the host mapping
// binds to identity, the newest report stored under that identity, with its
// components. Ordered by source.
func (a *DB) LatestInventoryReports(ctx context.Context, identity string) ([]InventoryReport, error) {
	rows, err := a.db.QueryContext(ctx, `
SELECT MAX(r.id) FROM inventory_reports r
WHERE r.identity = ? AND r.identity <> ''
  AND EXISTS (SELECT 1 FROM inventory_hosts h WHERE h.source = r.source AND h.identity = r.identity)
GROUP BY r.source ORDER BY r.source`, identity)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return a.InventoryReportsByID(ctx, ids)
}

// InventoryReportsByID returns the named reports with their components, in
// the order the ids were given. An id with no row is left out.
func (a *DB) InventoryReportsByID(ctx context.Context, ids []int64) ([]InventoryReport, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	in, args := placeholders(len(ids)), int64Args(ids)
	//nolint:gosec // G202: the IN list is placeholders only; every value is bound.
	rows, err := a.db.QueryContext(ctx, `
SELECT id, source, external_id, identity, observed_at, received_at, seq, prev_sha256, sha256
FROM inventory_reports WHERE id IN (`+in+`)`, args...)
	if err != nil {
		return nil, err
	}
	byID := map[int64]*InventoryReport{}
	for rows.Next() {
		var r InventoryReport
		var obs, rec string
		if err := rows.Scan(&r.ID, &r.Source, &r.ExternalID, &r.Identity, &obs, &rec, &r.Seq, &r.PrevSHA256, &r.SHA256); err != nil {
			rows.Close()
			return nil, err
		}
		r.ObservedAt, r.ReceivedAt = parseInvTime(obs), parseInvTime(rec)
		byID[r.ID] = &r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	//nolint:gosec // G202: the IN list is placeholders only; every value is bound.
	crows, err := a.db.QueryContext(ctx, `
SELECT report_id, ecosystem, name, version, path, digest_alg, digest, origin, purl
FROM inventory_components WHERE report_id IN (`+in+`) ORDER BY rowid`, args...)
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
		if r := byID[id]; r != nil {
			r.Components = append(r.Components, c)
		}
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}
	out := make([]InventoryReport, 0, len(ids))
	for _, id := range ids {
		if r := byID[id]; r != nil {
			out = append(out, *r)
		}
	}
	return out, nil
}

// BaselineComponent is one component an accepted baseline covers. An empty
// Version covers every version of the name; an empty digest covers any bytes.
type BaselineComponent struct {
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	DigestAlgorithm string `json:"digest_algorithm,omitempty"`
	DigestValue     string `json:"digest_value,omitempty"`
}

// InventoryBaseline is one accepted baseline, for an identity or for every
// identity bound to a profile. Exactly one of Identity and Profile is set.
type InventoryBaseline struct {
	ID         int64               `json:"id"`
	Identity   string              `json:"identity,omitempty"`
	Profile    string              `json:"profile,omitempty"`
	ReportIDs  []int64             `json:"report_ids,omitempty"`
	Actor      string              `json:"actor"`
	Comment    string              `json:"comment,omitempty"`
	CreatedAt  time.Time           `json:"created_at"`
	Components []BaselineComponent `json:"components"`
}

// AcceptInventoryBaseline stores a baseline and its components in one
// transaction. It becomes the one in force for its identity or profile; the
// earlier ones stay as history.
func (a *DB) AcceptInventoryBaseline(ctx context.Context, b InventoryBaseline) (InventoryBaseline, error) {
	b.Identity, b.Profile = strings.TrimSpace(b.Identity), strings.TrimSpace(b.Profile)
	if (b.Identity == "") == (b.Profile == "") {
		return b, errors.New("a baseline names an identity or a profile, not both and not neither")
	}
	if a.readOnly {
		return b, errors.New("audit db is read-only")
	}
	b.CreatedAt = time.Now().UTC().Truncate(time.Millisecond)
	ids := make([]string, len(b.ReportIDs))
	for i, id := range b.ReportIDs {
		ids[i] = strconv.FormatInt(id, 10)
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
INSERT INTO inventory_baselines (identity, profile, report_ids, actor, comment, created_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		b.Identity, b.Profile, strings.Join(ids, ","), b.Actor, b.Comment, invTime(b.CreatedAt))
	if err != nil {
		return b, err
	}
	if b.ID, err = res.LastInsertId(); err != nil {
		return b, err
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO inventory_baseline_components (baseline_id, ecosystem, name, version, digest_alg, digest)
VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return b, err
	}
	defer func() { _ = stmt.Close() }()
	for _, c := range b.Components {
		if _, err := stmt.ExecContext(ctx, b.ID, c.Ecosystem, c.Name, c.Version, c.DigestAlgorithm, c.DigestValue); err != nil {
			return b, err
		}
	}
	return b, tx.Commit()
}

// CurrentInventoryBaseline returns the baseline in force for an identity
// (profile empty) or a profile (identity empty), or nil when none was
// accepted.
func (a *DB) CurrentInventoryBaseline(ctx context.Context, identity, profile string) (*InventoryBaseline, error) {
	var b InventoryBaseline
	var reports, created string
	err := a.db.QueryRowContext(ctx, `
SELECT id, identity, profile, report_ids, actor, comment, created_at FROM inventory_baselines
WHERE identity = ? AND profile = ? ORDER BY id DESC LIMIT 1`, identity, profile).
		Scan(&b.ID, &b.Identity, &b.Profile, &reports, &b.Actor, &b.Comment, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.CreatedAt = parseInvTime(created)
	for _, s := range strings.Split(reports, ",") {
		if id, err := strconv.ParseInt(s, 10, 64); err == nil {
			b.ReportIDs = append(b.ReportIDs, id)
		}
	}
	rows, err := a.db.QueryContext(ctx, `
SELECT ecosystem, name, version, digest_alg, digest FROM inventory_baseline_components
WHERE baseline_id = ? ORDER BY ecosystem, name, version`, b.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c BaselineComponent
		if err := rows.Scan(&c.Ecosystem, &c.Name, &c.Version, &c.DigestAlgorithm, &c.DigestValue); err != nil {
			return nil, err
		}
		b.Components = append(b.Components, c)
	}
	return &b, rows.Err()
}

// ProfileBindingFor returns the profile bound to identity, or "" when none is.
func (a *DB) ProfileBindingFor(ctx context.Context, identity string) (string, error) {
	var p string
	err := a.db.QueryRowContext(ctx, `SELECT profile FROM profile_bindings WHERE identity = ?`, identity).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return p, err
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func int64Args(ids []int64) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
