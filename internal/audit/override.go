package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CheckOverridden is the status a check records when it failed and an
// approved override admitted the version anyway. The check's Override field
// names which one.
const CheckOverridden = "overridden"

// Override states. Expiry is not among them: an approved override past its
// expiry is still approved, and simply no longer applies.
const (
	OverridePending  = "pending"
	OverrideApproved = "approved"
	OverrideRejected = "rejected"
)

// What an override amounts to at a given moment, for listing: StatusAt.
const (
	OverrideStatusPending  = "pending"
	OverrideStatusActive   = "active"
	OverrideStatusExpired  = "expired"
	OverrideStatusRejected = "rejected"
)

// Override votes.
const (
	VoteApprove = "approve"
	VoteReject  = "reject"
)

// Override is a request to admit one version past one check's failure.
// RequestedBy and every vote's Identity are compared as plain strings, so two
// spellings of one person count as two people; see docs/threat-model.md.
type Override struct {
	ID          string         `json:"id"`
	PkgType     string         `json:"pkg_type"`
	PkgName     string         `json:"pkg_name"`
	PkgVersion  string         `json:"pkg_version"`
	Check       string         `json:"check"`
	Reason      string         `json:"reason"`
	RequestedBy string         `json:"requested_by"`
	RequestedAt time.Time      `json:"requested_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Quorum      int            `json:"quorum"`
	State       string         `json:"state"`
	DecidedAt   *time.Time     `json:"decided_at,omitempty"`
	Votes       []OverrideVote `json:"votes"`
	// Status is StatusAt the moment a listing was taken. It is never stored.
	Status string `json:"status,omitempty"`
}

// OverrideVote is one identity's decision on an override.
type OverrideVote struct {
	Identity string    `json:"identity"`
	Vote     string    `json:"vote"`
	Comment  string    `json:"comment,omitempty"`
	VotedAt  time.Time `json:"voted_at"`
}

// Approvers is the requester plus every distinct identity that approved,
// which is the count the quorum is held to.
func (o Override) Approvers() []string {
	out := []string{o.RequestedBy}
	for _, v := range o.Votes {
		if v.Vote == VoteApprove && v.Identity != o.RequestedBy {
			out = append(out, v.Identity)
		}
	}
	return out
}

// Expired reports whether the override's window has closed at now.
func (o Override) Expired(now time.Time) bool { return !now.Before(o.ExpiresAt) }

// Active reports whether the override applies to an admission decided at now.
func (o Override) Active(now time.Time) bool {
	return o.State == OverrideApproved && !o.Expired(now)
}

// StatusAt is what the override amounts to at now. A rejection outranks
// expiry, so a request somebody refused reads as refused for good.
func (o Override) StatusAt(now time.Time) string {
	switch {
	case o.State == OverrideRejected:
		return OverrideStatusRejected
	case o.Expired(now):
		return OverrideStatusExpired
	case o.State == OverrideApproved:
		return OverrideStatusActive
	}
	return OverrideStatusPending
}

// Errors an override vote can be refused with. Each is a refusal of the vote,
// never of the database.
var (
	ErrOverrideNotFound = errors.New("no override with that id")
	ErrSelfApproval     = errors.New("the requester cannot approve their own override")
	ErrAlreadyVoted     = errors.New("this identity has already voted on the override")
	ErrOverrideClosed   = errors.New("the override is no longer open to votes")
)

// InsertOverride records a new pending request.
func (a *DB) InsertOverride(ctx context.Context, o Override) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO overrides (id, pkg_type, pkg_name, pkg_version, check_name, reason,
			requested_by, requested_at, expires_at, quorum, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.PkgType, o.PkgName, o.PkgVersion, o.Check, o.Reason,
		o.RequestedBy, formatOverrideTime(o.RequestedAt), formatOverrideTime(o.ExpiresAt), o.Quorum, OverridePending)
	return err
}

// VoteOverride records identity's vote on override id at now and returns the
// override as the vote left it. A rejection closes the request whatever its
// state; an approval that brings the distinct approvers to the quorum
// approves it. The read, the vote and the state change are one transaction,
// so two approvals racing each other cannot both see the request pending and
// one short.
func (a *DB) VoteOverride(ctx context.Context, id, identity, vote, comment string, now time.Time) (Override, error) {
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return Override{}, err
	}
	defer func() { _ = tx.Rollback() }()

	o, err := getOverride(ctx, tx, id)
	if err != nil {
		return Override{}, err
	}
	switch {
	case o.State == OverrideRejected:
		return o, fmt.Errorf("%w: it was rejected", ErrOverrideClosed)
	case o.Expired(now):
		return o, fmt.Errorf("%w: it expired at %s", ErrOverrideClosed, o.ExpiresAt.UTC().Format(time.RFC3339))
	case vote == VoteApprove && o.State == OverrideApproved:
		return o, fmt.Errorf("%w: it is already approved", ErrOverrideClosed)
	case vote == VoteApprove && identity == o.RequestedBy:
		return o, ErrSelfApproval
	}
	for _, v := range o.Votes {
		if v.Identity == identity {
			return o, fmt.Errorf("%w (%s, at %s)", ErrAlreadyVoted, v.Vote, v.VotedAt.UTC().Format(time.RFC3339))
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO override_votes (override_id, identity, vote, comment, voted_at) VALUES (?, ?, ?, ?, ?)`,
		id, identity, vote, comment, formatOverrideTime(now)); err != nil {
		return o, err
	}
	o.Votes = append(o.Votes, OverrideVote{Identity: identity, Vote: vote, Comment: comment, VotedAt: now.UTC()})

	next := o.State
	switch {
	case vote == VoteReject:
		next = OverrideRejected
	case len(o.Approvers()) >= o.Quorum:
		next = OverrideApproved
	}
	if next != o.State {
		if _, err := tx.ExecContext(ctx, `UPDATE overrides SET state = ?, decided_at = ? WHERE id = ?`,
			next, formatOverrideTime(now), id); err != nil {
			return o, err
		}
		o.State = next
		t := now.UTC()
		o.DecidedAt = &t
	}
	return o, tx.Commit()
}

// GetOverride returns one override with its votes.
func (a *DB) GetOverride(ctx context.Context, id string) (Override, error) {
	return getOverride(ctx, a.db, id)
}

// OverrideFilter selects overrides. An empty field matches everything.
type OverrideFilter struct {
	PkgType string
	PkgName string
	State   string
}

// ListOverrides returns the overrides f selects, newest request first, each
// with its votes.
func (a *DB) ListOverrides(ctx context.Context, f OverrideFilter) ([]Override, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT `+overrideColumns+` FROM overrides
		WHERE (? = '' OR pkg_type = ?) AND (? = '' OR pkg_name = ?) AND (? = '' OR state = ?)
		ORDER BY requested_at DESC, id`, f.PkgType, f.PkgType, f.PkgName, f.PkgName, f.State, f.State)
	if err != nil {
		return nil, err
	}
	var out []Override
	for rows.Next() {
		o, err := scanOverride(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, o)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Votes, err = overrideVotes(ctx, a.db, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

const overrideColumns = `id, pkg_type, pkg_name, pkg_version, check_name, reason,
	requested_by, requested_at, expires_at, quorum, state, decided_at`

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func getOverride(ctx context.Context, q queryer, id string) (Override, error) {
	o, err := scanOverride(q.QueryRowContext(ctx, `SELECT `+overrideColumns+` FROM overrides WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return o, ErrOverrideNotFound
	}
	if err != nil {
		return o, err
	}
	o.Votes, err = overrideVotes(ctx, q, id)
	return o, err
}

func scanOverride(s rowScanner) (Override, error) {
	var o Override
	var requested, expires, decided string
	if err := s.Scan(&o.ID, &o.PkgType, &o.PkgName, &o.PkgVersion, &o.Check, &o.Reason,
		&o.RequestedBy, &requested, &expires, &o.Quorum, &o.State, &decided); err != nil {
		return o, err
	}
	var err error
	if o.RequestedAt, err = time.Parse(time.RFC3339Nano, requested); err != nil {
		return o, fmt.Errorf("override %s: requested_at %q: %w", o.ID, requested, err)
	}
	// An expiry that cannot be read must not read as "never": the zero time
	// is already past, so such a row applies to nothing.
	o.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if decided != "" {
		if t, err := time.Parse(time.RFC3339Nano, decided); err == nil {
			o.DecidedAt = &t
		}
	}
	return o, nil
}

func overrideVotes(ctx context.Context, q queryer, id string) ([]OverrideVote, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT identity, vote, comment, voted_at FROM override_votes WHERE override_id = ? ORDER BY voted_at, identity`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OverrideVote{}
	for rows.Next() {
		var v OverrideVote
		var ts string
		if err := rows.Scan(&v.Identity, &v.Vote, &v.Comment, &ts); err != nil {
			return nil, err
		}
		v.VotedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, v)
	}
	return out, rows.Err()
}

func formatOverrideTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
