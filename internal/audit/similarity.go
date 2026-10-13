package audit

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CheckNameSimilarity compares a candidate name with the ecosystem's popular
// names. Its detail names the nearest popular name and the distance.
const CheckNameSimilarity = "name_similarity"

// SimilarityPolicy is the name-similarity check's action for one ecosystem.
// Absent means warn; see ErrSimilarityPolicyNotFound.
type SimilarityPolicy struct {
	Ecosystem string
	Action    string
	Actor     string
	UpdatedAt time.Time
}

// ErrSimilarityPolicyNotFound means nobody set an action for the ecosystem,
// which the check reads as warn.
var ErrSimilarityPolicyNotFound = errors.New("name similarity policy not set for ecosystem")

func (a *DB) SetSimilarityPolicy(ctx context.Context, p SimilarityPolicy) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO name_similarity_policy (ecosystem, action, actor, updated_at)
		VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			action     = excluded.action,
			actor      = excluded.actor,
			updated_at = excluded.updated_at
	`, p.Ecosystem, p.Action, p.Actor)
	return err
}

func (a *DB) GetSimilarityPolicy(ctx context.Context, ecosystem string) (SimilarityPolicy, error) {
	var p SimilarityPolicy
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, action, actor, updated_at FROM name_similarity_policy WHERE ecosystem = ?`,
		ecosystem,
	).Scan(&p.Ecosystem, &p.Action, &p.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrSimilarityPolicyNotFound
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return p, nil
}

func (a *DB) ListSimilarityPolicies(ctx context.Context) ([]SimilarityPolicy, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, action, actor, updated_at FROM name_similarity_policy ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SimilarityPolicy
	for rows.Next() {
		var p SimilarityPolicy
		var ts string
		if err := rows.Scan(&p.Ecosystem, &p.Action, &p.Actor, &ts); err != nil {
			return nil, err
		}
		p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PopularList is a popular-name list an operator loaded over the embedded one.
// Names is the text as loaded, one name per line; SHA256 is over Names.
type PopularList struct {
	Ecosystem string
	Names     string
	NameCount int
	SHA256    string
	Source    string
	Actor     string
	LoadedAt  time.Time
}

// ErrPopularListNotFound means the ecosystem uses its embedded list.
var ErrPopularListNotFound = errors.New("no popular-name list loaded for ecosystem")

func (a *DB) SetPopularList(ctx context.Context, l PopularList) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO name_similarity_lists (ecosystem, names, name_count, sha256, source, actor, loaded_at)
		VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			names      = excluded.names,
			name_count = excluded.name_count,
			sha256     = excluded.sha256,
			source     = excluded.source,
			actor      = excluded.actor,
			loaded_at  = excluded.loaded_at
	`, l.Ecosystem, l.Names, l.NameCount, l.SHA256, l.Source, l.Actor)
	return err
}

func (a *DB) GetPopularList(ctx context.Context, ecosystem string) (PopularList, error) {
	var l PopularList
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, names, name_count, sha256, source, actor, loaded_at FROM name_similarity_lists WHERE ecosystem = ?`,
		ecosystem,
	).Scan(&l.Ecosystem, &l.Names, &l.NameCount, &l.SHA256, &l.Source, &l.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrPopularListNotFound
	}
	if err != nil {
		return l, err
	}
	l.LoadedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return l, nil
}

// ListPopularLists returns every loaded list without its names, which is what
// the policy digest and `policy similarity list` read.
func (a *DB) ListPopularLists(ctx context.Context) ([]PopularList, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, name_count, sha256, source, actor, loaded_at FROM name_similarity_lists ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PopularList
	for rows.Next() {
		var l PopularList
		var ts string
		if err := rows.Scan(&l.Ecosystem, &l.NameCount, &l.SHA256, &l.Source, &l.Actor, &ts); err != nil {
			return nil, err
		}
		l.LoadedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, l)
	}
	return out, rows.Err()
}

// NameBaselineKey is one package the manifest store held when the
// name-similarity baseline was taken, under the check's normalization.
type NameBaselineKey struct {
	PkgType string
	PkgKey  string
}

// NameBaselineState is the baseline's marker: whether it has been taken,
// when, and how many names each source contributed.
type NameBaselineState struct {
	Taken   bool
	TakenAt time.Time
	// Packages counts the manifest store's names; Admitted counts the names
	// with an admitted row that no earlier source had already contributed.
	Packages int
	Admitted int
}

// TakeNameBaseline records the names in use before the check, unless a
// baseline was already taken here, and reports whether this call took it.
// Two sources are in use: keys, the manifest store's names, and every name
// the admissions table holds an admitted row for, which is the only record a
// pass-through proxy fill leaves. normalize maps an admission row's type and
// name to the key a lookup computes from the candidate.
//
// An admitted row whose name_similarity entry says warn does not count: the
// check had already run and flagged that name, so it was not in use before
// the check. Rows from before the check carry no such entry.
//
// The marker and both sources land in one transaction, which holds the write
// lock from the marker insert on: a crash cannot leave a marker with half a
// baseline behind it, and an admission committed by another process after
// the read is after the baseline, judged like any other.
func (a *DB) TakeNameBaseline(ctx context.Context, keys []NameBaselineKey, normalize func(pkgType, name string) string) (bool, error) {
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO name_similarity_baseline_taken (id, package_count) VALUES (1, ?)`, len(keys))
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false, err
	}
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO name_similarity_baseline (pkg_type, pkg_key) VALUES (?, ?)`, k.PkgType, k.PkgKey); err != nil {
			return false, err
		}
	}
	admitted, err := admittedBeforeCheck(ctx, tx, normalize)
	if err != nil {
		return false, err
	}
	added := 0
	for _, k := range admitted {
		res, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO name_similarity_baseline (pkg_type, pkg_key) VALUES (?, ?)`, k.PkgType, k.PkgKey)
		if err != nil {
			return false, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return false, err
		} else if n > 0 {
			added++
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE name_similarity_baseline_taken SET admission_count = ? WHERE id = 1`, added); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// admittedBeforeCheck returns the normalized names with an admitted row the
// name_similarity check did not warn on, read whole before any insert so no
// result set is open on the transaction's connection while it writes.
func admittedBeforeCheck(ctx context.Context, tx *sql.Tx, normalize func(pkgType, name string) string) ([]NameBaselineKey, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT pkg_type, pkg_name FROM admissions
		WHERE decision = ?
		  AND NOT EXISTS (
			SELECT 1 FROM json_each(admissions.checks) c
			WHERE json_extract(c.value, '$.check') = ?
			  AND json_extract(c.value, '$.status') IN (?, ?)
		  )`,
		AdmissionAdmitted, CheckNameSimilarity, CheckWarn, CheckBlock)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NameBaselineKey
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			return nil, err
		}
		out = append(out, NameBaselineKey{PkgType: typ, PkgKey: normalize(typ, name)})
	}
	return out, rows.Err()
}

// NameBaseline reports whether the baseline has been taken, when, and from
// how many names.
func (a *DB) NameBaseline(ctx context.Context) (NameBaselineState, error) {
	var st NameBaselineState
	var ts string
	// The writer, not the read pool: a command takes the baseline and then
	// admits in the same process, and the read pool can lag the write
	// connection.
	err := a.writer().QueryRowContext(ctx,
		`SELECT package_count, admission_count, taken_at FROM name_similarity_baseline_taken WHERE id = 1`).
		Scan(&st.Packages, &st.Admitted, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return NameBaselineState{}, nil
	}
	if err != nil {
		return NameBaselineState{}, err
	}
	st.Taken = true
	st.TakenAt, _ = time.Parse(time.RFC3339Nano, ts)
	return st, nil
}

// InNameBaseline reports whether key was in use, in the manifest store or
// admitted, when the baseline was taken.
func (a *DB) InNameBaseline(ctx context.Context, pkgType, key string) (bool, error) {
	var n int
	err := a.writer().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM name_similarity_baseline WHERE pkg_type = ? AND pkg_key = ?`, pkgType, key).Scan(&n)
	return n > 0, err
}
