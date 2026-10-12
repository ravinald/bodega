package audit

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ProvenancePolicy is the upstream provenance check's action for one
// ecosystem. Absent means warn; see ErrProvenancePolicyNotFound.
type ProvenancePolicy struct {
	Ecosystem string
	Action    string
	Actor     string
	UpdatedAt time.Time
}

// ErrProvenancePolicyNotFound means nobody set an action for the ecosystem,
// which the check reads as warn.
var ErrProvenancePolicyNotFound = errors.New("upstream provenance policy not set for ecosystem")

func (a *DB) SetProvenancePolicy(ctx context.Context, p ProvenancePolicy) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO upstream_provenance_policy (ecosystem, action, actor, updated_at)
		VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			action     = excluded.action,
			actor      = excluded.actor,
			updated_at = excluded.updated_at
	`, p.Ecosystem, p.Action, p.Actor)
	return err
}

func (a *DB) GetProvenancePolicy(ctx context.Context, ecosystem string) (ProvenancePolicy, error) {
	var p ProvenancePolicy
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, action, actor, updated_at FROM upstream_provenance_policy WHERE ecosystem = ?`,
		ecosystem,
	).Scan(&p.Ecosystem, &p.Action, &p.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrProvenancePolicyNotFound
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return p, nil
}

func (a *DB) ListProvenancePolicies(ctx context.Context) ([]ProvenancePolicy, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, action, actor, updated_at FROM upstream_provenance_policy ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProvenancePolicy
	for rows.Next() {
		var p ProvenancePolicy
		var ts string
		if err := rows.Scan(&p.Ecosystem, &p.Action, &p.Actor, &ts); err != nil {
			return nil, err
		}
		p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProvenancePin is the source repository and builder a package's first
// verified version was built by. BuilderID has any "@<ref>" suffix removed;
// WorkflowRef is the full value the pin was taken from.
type ProvenancePin struct {
	PkgType             string
	PkgName             string
	SourceRepositoryURI string
	BuilderID           string
	WorkflowRef         string
	PinnedVersion       string
	PinnedAt            time.Time
}

// ErrProvenancePinNotFound means no version of the package has verified yet.
var ErrProvenancePinNotFound = errors.New("no upstream provenance pin for package")

// PinProvenance records p as the package's pin unless one is already held,
// and returns whichever pin is in force afterwards. created says whether it
// is p. Two admissions racing to pin the same package both read back the one
// that won, so neither compares against a pin that was never stored.
func (a *DB) PinProvenance(ctx context.Context, p ProvenancePin) (pin ProvenancePin, created bool, err error) {
	res, err := a.writer().ExecContext(ctx, `
		INSERT INTO upstream_provenance_pins
			(pkg_type, pkg_name, source_repository_uri, builder_id, workflow_ref, pinned_version, pinned_at)
		VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(pkg_type, pkg_name) DO NOTHING
	`, p.PkgType, p.PkgName, p.SourceRepositoryURI, p.BuilderID, p.WorkflowRef, p.PinnedVersion)
	if err != nil {
		return ProvenancePin{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ProvenancePin{}, false, err
	}
	pin, err = a.GetProvenancePin(ctx, p.PkgType, p.PkgName)
	return pin, n > 0, err
}

func (a *DB) GetProvenancePin(ctx context.Context, pkgType, pkgName string) (ProvenancePin, error) {
	p := ProvenancePin{PkgType: pkgType, PkgName: pkgName}
	var ts string
	// The writer, not the read pool: PinProvenance reads back the row it may
	// have just written, and the read pool can lag the write connection.
	err := a.writer().QueryRowContext(ctx, `
		SELECT source_repository_uri, builder_id, workflow_ref, pinned_version, pinned_at
		FROM upstream_provenance_pins WHERE pkg_type = ? AND pkg_name = ?`, pkgType, pkgName,
	).Scan(&p.SourceRepositoryURI, &p.BuilderID, &p.WorkflowRef, &p.PinnedVersion, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrProvenancePinNotFound
	}
	if err != nil {
		return p, err
	}
	p.PinnedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return p, nil
}

// ResetProvenancePin deletes the package's pin and returns what it held, so
// the caller can record what was cleared. ErrProvenancePinNotFound when there
// was none.
func (a *DB) ResetProvenancePin(ctx context.Context, pkgType, pkgName string) (ProvenancePin, error) {
	old, err := a.GetProvenancePin(ctx, pkgType, pkgName)
	if err != nil {
		return old, err
	}
	if _, err := a.writer().ExecContext(ctx,
		`DELETE FROM upstream_provenance_pins WHERE pkg_type = ? AND pkg_name = ?`, pkgType, pkgName); err != nil {
		return old, err
	}
	return old, nil
}
