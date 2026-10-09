package audit

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// OsquerySecret is an enroll secret's metadata. The secret itself is never
// stored, so nothing here can print it.
type OsquerySecret struct {
	ID        string     `json:"id"`
	Source    string     `json:"source"`
	Label     string     `json:"label"`
	Identity  string     `json:"identity"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil never expires
	Nodes     int64      `json:"nodes"`
}

// Expired reports whether the secret is past its expiry at now.
func (s OsquerySecret) Expired(now time.Time) bool {
	return s.ExpiresAt != nil && !s.ExpiresAt.After(now)
}

// OsqueryNode is one enrolled node_key, by its sha256.
type OsqueryNode struct {
	Source         string
	KeySHA256      string
	SecretID       string
	Identity       string
	HostIdentifier string
}

// ErrNoOsquerySecret is a secret id or hash no row holds.
var ErrNoOsquerySecret = errors.New("no such osquery enroll secret")

// InsertOsquerySecret stores an enroll secret's hash.
func (a *DB) InsertOsquerySecret(ctx context.Context, s OsquerySecret, hash string) error {
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	if s.ID == "" || s.Source == "" || s.Identity == "" || hash == "" {
		return errors.New("an enroll secret needs an id, a source, an identity and a hash")
	}
	var exp sql.NullString
	if s.ExpiresAt != nil {
		exp = sql.NullString{String: invTime(*s.ExpiresAt), Valid: true}
	}
	_, err := a.writer().ExecContext(ctx,
		`INSERT INTO osquery_enroll_secrets (id, source, label, identity, hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.Source, s.Label, s.Identity, hash, exp)
	return err
}

// OsquerySecretByHash returns the secret source stores under hash, or
// ErrNoOsquerySecret.
func (a *DB) OsquerySecretByHash(ctx context.Context, source, hash string) (OsquerySecret, error) {
	rows, err := a.listOsquerySecrets(ctx, osquerySecretFilter{source: source, hash: hash})
	if err != nil {
		return OsquerySecret{}, err
	}
	if len(rows) == 0 {
		return OsquerySecret{}, ErrNoOsquerySecret
	}
	return rows[0], nil
}

// ListOsquerySecrets returns every enroll secret, ordered by source then
// creation, each with the count of nodes enrolled with it.
func (a *DB) ListOsquerySecrets(ctx context.Context) ([]OsquerySecret, error) {
	return a.listOsquerySecrets(ctx, osquerySecretFilter{})
}

// osquerySecretFilter narrows listOsquerySecrets; an empty field matches all.
type osquerySecretFilter struct{ id, source, hash string }

func (a *DB) listOsquerySecrets(ctx context.Context, f osquerySecretFilter) ([]OsquerySecret, error) {
	rows, err := a.db.QueryContext(ctx, `
SELECT s.id, s.source, s.label, s.identity, s.created_at, s.expires_at,
       (SELECT COUNT(*) FROM osquery_nodes n WHERE n.secret_id = s.id)
FROM osquery_enroll_secrets s
WHERE (? = '' OR s.id = ?) AND (? = '' OR s.source = ?) AND (? = '' OR s.hash = ?)
ORDER BY s.source, s.created_at, s.id`, f.id, f.id, f.source, f.source, f.hash, f.hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OsquerySecret
	for rows.Next() {
		var s OsquerySecret
		var created string
		var expires sql.NullString
		if err := rows.Scan(&s.ID, &s.Source, &s.Label, &s.Identity, &created, &expires, &s.Nodes); err != nil {
			return nil, err
		}
		s.CreatedAt = parseInvTime(created)
		if expires.Valid {
			t := parseInvTime(expires.String)
			s.ExpiresAt = &t
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RevokeOsquerySecret deletes a secret and every node enrolled with it, in
// one transaction, and returns how many nodes went. The host mappings those
// nodes wrote stay: reports already stored under them keep their identity,
// and with the node gone no further report can arrive under the key.
func (a *DB) RevokeOsquerySecret(ctx context.Context, id string) (OsquerySecret, int64, error) {
	if a.readOnly {
		return OsquerySecret{}, 0, errors.New("audit db is read-only")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return OsquerySecret{}, 0, ErrNoOsquerySecret
	}
	found, err := a.listOsquerySecrets(ctx, osquerySecretFilter{id: id})
	if err != nil {
		return OsquerySecret{}, 0, err
	}
	if len(found) == 0 {
		return OsquerySecret{}, 0, ErrNoOsquerySecret
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return OsquerySecret{}, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM osquery_nodes WHERE secret_id = ?`, found[0].ID)
	if err != nil {
		return OsquerySecret{}, 0, err
	}
	nodes, err := res.RowsAffected()
	if err != nil {
		return OsquerySecret{}, 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM osquery_enroll_secrets WHERE id = ?`, found[0].ID); err != nil {
		return OsquerySecret{}, 0, err
	}
	return found[0], nodes, tx.Commit()
}

// EnrollOsqueryNode records a node_key by its sha256 and maps that sha256 to
// the secret's identity in inventory_hosts, in one transaction, so a node
// that exists always resolves to the identity it enrolled as.
func (a *DB) EnrollOsqueryNode(ctx context.Context, n OsqueryNode) error {
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	if n.Source == "" || n.KeySHA256 == "" || n.SecretID == "" || n.Identity == "" {
		return errors.New("an osquery node needs a source, a key digest, a secret and an identity")
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO osquery_nodes (source, key_sha256, secret_id, identity, host_identifier) VALUES (?, ?, ?, ?, ?)`,
		n.Source, n.KeySHA256, n.SecretID, n.Identity, n.HostIdentifier); err != nil {
		return err
	}
	now := invTime(time.Now())
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO inventory_hosts (source, external_id, identity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)`,
		n.Source, n.KeySHA256, n.Identity, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// OsqueryNodeByKey returns the node source holds under a node_key's sha256,
// and false when none does.
func (a *DB) OsqueryNodeByKey(ctx context.Context, source, keySHA256 string) (OsqueryNode, bool, error) {
	n := OsqueryNode{Source: source, KeySHA256: keySHA256}
	err := a.db.QueryRowContext(ctx,
		`SELECT secret_id, identity, host_identifier FROM osquery_nodes WHERE source = ? AND key_sha256 = ?`,
		source, keySHA256).Scan(&n.SecretID, &n.Identity, &n.HostIdentifier)
	if errors.Is(err, sql.ErrNoRows) {
		return OsqueryNode{}, false, nil
	}
	if err != nil {
		return OsqueryNode{}, false, err
	}
	return n, true, nil
}
