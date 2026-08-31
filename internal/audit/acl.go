package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ACL list names. They are the config.json keys they replace, minus the
// suffix, so the CLI, the file and the table share one vocabulary.
const (
	ACLAdmin   = "admin"   // admin_permit_cidr
	ACLDeny    = "deny"    // deny_list
	ACLProxies = "proxies" // trusted_proxies
)

// ErrACLUnknownList is returned for a list name outside the three above.
var ErrACLUnknownList = errors.New("unknown acl list")

// ACLLists returns the three list names in a stable order.
func ACLLists() []string { return []string{ACLAdmin, ACLDeny, ACLProxies} }

// ACLConfigKey maps a list name back to the config.json key it replaces, for
// error text and documentation that has to name both.
func ACLConfigKey(list string) string {
	switch list {
	case ACLAdmin:
		return "admin_permit_cidr"
	case ACLDeny:
		return "deny_list"
	case ACLProxies:
		return "trusted_proxies"
	}
	return ""
}

// ValidACLList reports whether list is one of the three.
func ValidACLList(list string) bool { return ACLConfigKey(list) != "" }

// ACLEntry is one CIDR in one list.
type ACLEntry struct {
	List      string
	CIDR      string
	Comment   string
	Actor     string // OS user who added it; empty when copied from the config file
	CreatedAt time.Time
}

// ACLSeeded reports whether the database owns this list. False means the list
// has never been copied out of config.json, and the config file still decides.
func (a *DB) ACLSeeded(ctx context.Context, list string) (bool, error) {
	if !ValidACLList(list) {
		return false, fmt.Errorf("%w: %q", ErrACLUnknownList, list)
	}
	var n int
	err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM acl_lists WHERE list = ?`, list).Scan(&n)
	return n > 0, err
}

// SeedACL copies a config file list into the database and marks the list as
// owned by it. It is a no-op on a list already owned, and reports whether it
// wrote anything.
//
// entries may be empty, which claims the list with no members: that is how an
// operator's `"trusted_proxies": []` survives the move. The marker row and the
// entries land in one transaction, because a marker with a half-written list
// behind it is an access control decision nobody made.
func (a *DB) SeedACL(ctx context.Context, list string, entries []string, actor string) (bool, error) {
	if !ValidACLList(list) {
		return false, fmt.Errorf("%w: %q", ErrACLUnknownList, list)
	}
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO acl_lists (list) VALUES (?)`, list)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil // already owned; leave its entries alone
	}
	for _, cidr := range entries {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO acl_entries (list, cidr, actor) VALUES (?, ?, ?)`,
			list, cidr, actor,
		); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// ListACL returns the entries of one list, ordered by CIDR.
func (a *DB) ListACL(ctx context.Context, list string) ([]ACLEntry, error) {
	if !ValidACLList(list) {
		return nil, fmt.Errorf("%w: %q", ErrACLUnknownList, list)
	}
	rows, err := a.db.QueryContext(ctx,
		`SELECT list, cidr, comment, actor, created_at FROM acl_entries WHERE list = ? ORDER BY cidr`, list)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ACLEntry
	for rows.Next() {
		var e ACLEntry
		var ts string
		if err := rows.Scan(&e.List, &e.CIDR, &e.Comment, &e.Actor, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ACLCIDRs returns just the CIDR strings of one list, in the same order.
func (a *DB) ACLCIDRs(ctx context.Context, list string) ([]string, error) {
	entries, err := a.ListACL(ctx, list)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.CIDR)
	}
	return out, nil
}

// AddACL inserts one entry. It reports false when the CIDR is already in the
// list, which is not an error.
func (a *DB) AddACL(ctx context.Context, e ACLEntry) (bool, error) {
	if !ValidACLList(e.List) {
		return false, fmt.Errorf("%w: %q", ErrACLUnknownList, e.List)
	}
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	res, err := a.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO acl_entries (list, cidr, comment, actor) VALUES (?, ?, ?, ?)`,
		e.List, e.CIDR, e.Comment, e.Actor)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RemoveACL deletes one entry, reporting whether it was there.
func (a *DB) RemoveACL(ctx context.Context, list, cidr string) (bool, error) {
	if !ValidACLList(list) {
		return false, fmt.Errorf("%w: %q", ErrACLUnknownList, list)
	}
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	res, err := a.db.ExecContext(ctx, `DELETE FROM acl_entries WHERE list = ? AND cidr = ?`, list, cidr)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 1 {
		return false, fmt.Errorf("acl delete %s %s: unexpected row count %d", list, cidr, n)
	}
	return n == 1, nil
}
