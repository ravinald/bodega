package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AptMirrorHide is one version of a mirrored apt package an operator withdrew
// from every host. Name and Version are the binary package's, as a Packages
// stanza and a pool filename carry them. Codenames records where the version
// was found when the hide was set; the rebuild drops the stanza wherever it
// appears, so it describes the decision rather than limiting it.
type AptMirrorHide struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Codenames []string  `json:"codenames,omitempty"`
	HiddenBy  string    `json:"hidden_by"`
	HiddenAt  time.Time `json:"hidden_at"`
}

// InsertAptMirrorHide records a hide. A second hide of the same version is an
// error rather than an update, because the CLI toggles: it reads first and
// deletes a hide that is already there.
func (a *DB) InsertAptMirrorHide(ctx context.Context, h AptMirrorHide) error {
	if h.Name == "" || h.Version == "" {
		return errors.New("a mirrored apt hide needs a package name and a version")
	}
	_, err := a.writer().ExecContext(ctx,
		`INSERT INTO apt_mirror_hides (name, version, codenames, hidden_by) VALUES (?, ?, ?, ?)`,
		h.Name, h.Version, strings.Join(h.Codenames, " "), h.HiddenBy)
	return err
}

// DeleteAptMirrorHide removes a hide and reports whether one was there.
func (a *DB) DeleteAptMirrorHide(ctx context.Context, name, version string) (bool, error) {
	res, err := a.writer().ExecContext(ctx,
		`DELETE FROM apt_mirror_hides WHERE name = ? AND version = ?`, name, version)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// GetAptMirrorHide returns the hide on one version, with ok false when none.
func (a *DB) GetAptMirrorHide(ctx context.Context, name, version string) (AptMirrorHide, bool, error) {
	found, err := a.queryAptMirrorHides(ctx,
		`SELECT name, version, codenames, hidden_by, hidden_at FROM apt_mirror_hides WHERE name = ? AND version = ?`,
		name, version)
	if err != nil || len(found) == 0 {
		return AptMirrorHide{}, false, err
	}
	return found[0], true, nil
}

// ListAptMirrorHides returns every hide, by name then version. An empty name
// lists all of them.
func (a *DB) ListAptMirrorHides(ctx context.Context, name string) ([]AptMirrorHide, error) {
	if name == "" {
		return a.queryAptMirrorHides(ctx,
			`SELECT name, version, codenames, hidden_by, hidden_at FROM apt_mirror_hides ORDER BY name, version`)
	}
	return a.queryAptMirrorHides(ctx,
		`SELECT name, version, codenames, hidden_by, hidden_at FROM apt_mirror_hides WHERE name = ? ORDER BY version`,
		name)
}

func (a *DB) queryAptMirrorHides(ctx context.Context, query string, args ...any) ([]AptMirrorHide, error) {
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read mirrored apt hides: %w", err)
	}
	defer rows.Close()
	var out []AptMirrorHide
	for rows.Next() {
		var h AptMirrorHide
		var codenames, hiddenAt sql.NullString
		if err := rows.Scan(&h.Name, &h.Version, &codenames, &h.HiddenBy, &hiddenAt); err != nil {
			return nil, fmt.Errorf("scan mirrored apt hides: %w", err)
		}
		h.Codenames = strings.Fields(codenames.String)
		if t, err := time.Parse(time.RFC3339Nano, hiddenAt.String); err == nil {
			h.HiddenAt = t
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan mirrored apt hides: %w", err)
	}
	return out, nil
}
