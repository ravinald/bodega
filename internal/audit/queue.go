package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Queue row states.
const (
	QueueOpen      = "open"
	QueueApproved  = "approved"
	QueueDismissed = "dismissed"
)

// EventQueue is a queue row approved or dismissed.
const EventQueue EventType = "queue"

// queueRequesterLimit bounds the requesters one listing carries per row. The
// table keeps them all; a row a whole fleet hit would otherwise print the
// fleet.
const queueRequesterLimit = 20

// QueueRefusal is one refused client request, as the server records it.
type QueueRefusal struct {
	PkgType    string
	PkgName    string
	PkgVersion string
	Check      string
	Pattern    string
	Detail     string
	Unwaivable string
	Profile    string
	Incident   string
	Identity   string
	ClientIP   string
}

// QueueRow is one (type, package, version, check) bodega refused, with who
// asked for it and how it was resolved.
type QueueRow struct {
	ID               int64            `json:"id"`
	PkgType          string           `json:"pkg_type"`
	PkgName          string           `json:"pkg_name"`
	PkgVersion       string           `json:"pkg_version"`
	Check            string           `json:"check"`
	Pattern          string           `json:"pattern,omitempty"`
	Detail           string           `json:"detail"`
	Unwaivable       string           `json:"unwaivable,omitempty"`
	Profiles         []string         `json:"profiles,omitempty"`
	Incident         string           `json:"incident"`
	FirstSeen        time.Time        `json:"first_seen"`
	LastSeen         time.Time        `json:"last_seen"`
	RequestCount     int64            `json:"request_count"`
	Requesters       []QueueRequester `json:"requesters"`
	State            string           `json:"state"`
	ResolvedAt       *time.Time       `json:"resolved_at,omitempty"`
	ResolvedBy       string           `json:"resolved_by,omitempty"`
	Resolution       string           `json:"resolution,omitempty"`
	ResolutionReason string           `json:"resolution_reason,omitempty"`
}

// QueueRequester is one identity and client address that asked for a row.
type QueueRequester struct {
	Identity     string    `json:"identity"`
	ClientIP     string    `json:"client_ip"`
	RequestCount int64     `json:"request_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// QueueFilter selects queue rows. An empty field matches everything.
type QueueFilter struct {
	PkgType string
	Check   string
	State   string
}

// Errors a resolution can be refused with.
var (
	ErrQueueRowNotFound = errors.New("no queue row with that id")
	ErrQueueRowClosed   = errors.New("the queue row is not open")
)

// RecordRefusal writes or updates the queue row for f at now. A row that was
// approved or dismissed before now reopens: the same refusal arriving after
// its resolution means the resolution did not admit it.
func (a *DB) RecordRefusal(ctx context.Context, f QueueRefusal, now time.Time) error {
	ts := formatQueueTime(now)
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var id int64
	var profiles, state, resolvedAt string
	err = tx.QueryRowContext(ctx, `SELECT id, profiles, state, resolved_at FROM refusal_queue
		WHERE pkg_type = ? AND pkg_name = ? AND pkg_version = ? AND check_name = ?`,
		f.PkgType, f.PkgName, f.PkgVersion, f.Check).Scan(&id, &profiles, &state, &resolvedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `INSERT INTO refusal_queue (pkg_type, pkg_name, pkg_version, check_name,
			pattern, detail, unwaivable, profiles, incident, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.PkgType, f.PkgName, f.PkgVersion, f.Check, f.Pattern, f.Detail, f.Unwaivable,
			f.Profile, f.Incident, ts, ts)
		if err != nil {
			return err
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		if state != QueueOpen && resolvedAt < ts {
			state = QueueOpen
		}
		if f.Profile != "" && !slices.Contains(splitProfiles(profiles), f.Profile) {
			profiles = strings.Join(append(splitProfiles(profiles), f.Profile), ",")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refusal_queue SET
			pattern = CASE WHEN ? = '' THEN pattern ELSE ? END,
			detail = ?, unwaivable = ?, profiles = ?, incident = ?, last_seen = ?,
			request_count = request_count + 1, state = ?
			WHERE id = ?`,
			f.Pattern, f.Pattern, f.Detail, f.Unwaivable, profiles, f.Incident, ts, state, id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refusal_queue_requesters (queue_id, identity, client_ip, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (queue_id, identity, client_ip) DO UPDATE SET
			request_count = request_count + 1, last_seen = excluded.last_seen`,
		id, f.Identity, f.ClientIP, ts); err != nil {
		return err
	}
	return tx.Commit()
}

// ListQueue returns the rows f selects, most recently refused first, each
// with its most recent requesters.
func (a *DB) ListQueue(ctx context.Context, f QueueFilter) ([]QueueRow, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT `+queueColumns+` FROM refusal_queue
		WHERE (? = '' OR pkg_type = ?) AND (? = '' OR check_name = ?) AND (? = '' OR state = ?)
		ORDER BY last_seen DESC, id DESC`,
		f.PkgType, f.PkgType, f.Check, f.Check, f.State, f.State)
	if err != nil {
		return nil, err
	}
	out := []QueueRow{}
	for rows.Next() {
		q, err := scanQueueRow(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, q)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Requesters, err = queueRequesters(ctx, a.db, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetQueueRow returns one row with its most recent requesters.
func (a *DB) GetQueueRow(ctx context.Context, id int64) (QueueRow, error) {
	return getQueueRow(ctx, a.db, id)
}

// ResolveQueueRow closes open row id as state, approved or dismissed, by
// actor at now. resolution names what the approval did, and reason is the
// operator's. The read and the write are one transaction, so two resolutions
// racing each other cannot both see the row open.
func (a *DB) ResolveQueueRow(ctx context.Context, id int64, state, actor, resolution, reason string, now time.Time) (QueueRow, error) {
	if state != QueueApproved && state != QueueDismissed {
		return QueueRow{}, fmt.Errorf("resolve queue row %d: state %q is not a resolution", id, state)
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return QueueRow{}, err
	}
	defer func() { _ = tx.Rollback() }()
	q, err := getQueueRow(ctx, tx, id)
	if err != nil {
		return q, err
	}
	if q.State != QueueOpen {
		return q, fmt.Errorf("%w: it was %s by %s", ErrQueueRowClosed, q.State, q.ResolvedBy)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE refusal_queue SET state = ?, resolved_at = ?, resolved_by = ?,
		resolution = ?, resolution_reason = ? WHERE id = ?`,
		state, formatQueueTime(now), actor, resolution, reason, id); err != nil {
		return q, err
	}
	t := now.UTC()
	q.State, q.ResolvedAt, q.ResolvedBy, q.Resolution, q.ResolutionReason = state, &t, actor, resolution, reason
	return q, tx.Commit()
}

const queueColumns = `id, pkg_type, pkg_name, pkg_version, check_name, pattern, detail, unwaivable,
	profiles, incident, first_seen, last_seen, request_count, state, resolved_at, resolved_by,
	resolution, resolution_reason`

func getQueueRow(ctx context.Context, q queryer, id int64) (QueueRow, error) {
	row, err := scanQueueRow(q.QueryRowContext(ctx, `SELECT `+queueColumns+` FROM refusal_queue WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrQueueRowNotFound
	}
	if err != nil {
		return row, err
	}
	row.Requesters, err = queueRequesters(ctx, q, id)
	return row, err
}

func scanQueueRow(s rowScanner) (QueueRow, error) {
	var q QueueRow
	var profiles, first, last, resolved string
	if err := s.Scan(&q.ID, &q.PkgType, &q.PkgName, &q.PkgVersion, &q.Check, &q.Pattern, &q.Detail,
		&q.Unwaivable, &profiles, &q.Incident, &first, &last, &q.RequestCount, &q.State, &resolved,
		&q.ResolvedBy, &q.Resolution, &q.ResolutionReason); err != nil {
		return q, err
	}
	q.Profiles = splitProfiles(profiles)
	q.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
	q.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
	if resolved != "" {
		if t, err := time.Parse(time.RFC3339Nano, resolved); err == nil {
			q.ResolvedAt = &t
		}
	}
	return q, nil
}

func queueRequesters(ctx context.Context, q queryer, id int64) ([]QueueRequester, error) {
	rows, err := q.QueryContext(ctx, `SELECT identity, client_ip, request_count, last_seen
		FROM refusal_queue_requesters WHERE queue_id = ? ORDER BY last_seen DESC, identity, client_ip LIMIT ?`,
		id, queueRequesterLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QueueRequester{}
	for rows.Next() {
		var r QueueRequester
		var ts string
		if err := rows.Scan(&r.Identity, &r.ClientIP, &r.RequestCount, &ts); err != nil {
			return nil, err
		}
		r.LastSeen, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// formatQueueTime writes a fixed-width UTC timestamp. RFC3339Nano trims
// trailing zeros, so two of its strings inside one second compare in the
// wrong order, and the queue both sorts on last_seen and compares it with
// resolved_at as text.
func formatQueueTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}

func splitProfiles(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
