package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
)

// Membership values decide which packages of a type a profile covers.
const (
	MembershipClosed = "closed" // only the packages the profile lists
	MembershipOpen   = "open"   // every package of this type in the catalog
)

// Version default values decide the version rule for a package the profile
// covers but carries no per-entry constraint for.
const (
	VersionPinned   = "pinned"   // only the version the entry names
	VersionFloating = "floating" // any version
)

// Expansion values decide what a closed type does about a package it does not
// list. The default is ExpansionWarn: a new transitive dependency is ordinary
// upstream maintenance, and refusing it by default leaves the host unpatched.
//
// The strings are policy.ActionWarn, ActionBlock and ActionIgnore, spelled
// again here because internal/policy imports this package and the import
// cannot run the other way. TestExpansionMatchesPolicyActions holds the two
// together.
const (
	ExpansionWarn   = "warn"   // serve it, and record the reach outside the class
	ExpansionBlock  = "block"  // refuse it
	ExpansionIgnore = "ignore" // serve it and record nothing
)

// Expansions returns the legal values in a stable order, for error text and
// flag help that has to enumerate them.
func Expansions() []string { return []string{ExpansionWarn, ExpansionBlock, ExpansionIgnore} }

// ValidExpansion reports whether e is one of the three.
func ValidExpansion(e string) bool {
	return e == ExpansionWarn || e == ExpansionBlock || e == ExpansionIgnore
}

// ErrNoProfile is returned for a profile name no row has.
var ErrNoProfile = errors.New("no such profile")

// ErrProfileExists is returned by CreateProfile for a name already taken.
var ErrProfileExists = errors.New("profile already exists")

// Memberships and VersionDefaults return the legal values in a stable order,
// for error text and flag help that has to enumerate them.
func Memberships() []string     { return []string{MembershipClosed, MembershipOpen} }
func VersionDefaults() []string { return []string{VersionPinned, VersionFloating} }

// ValidMembership reports whether m is one of the two.
func ValidMembership(m string) bool { return m == MembershipClosed || m == MembershipOpen }

// ValidVersionDefault reports whether v is one of the two.
func ValidVersionDefault(v string) bool { return v == VersionPinned || v == VersionFloating }

// expansionOrDefault fills the unset expansion with warn, matching the column
// default. A marker written before expansion existed, and one written by a
// caller that states nothing about it, both mean "detect, do not refuse".
func expansionOrDefault(e string) string {
	if e == "" {
		return ExpansionWarn
	}
	return e
}

// ProfileConstraints returns the constraint kinds an entry may carry. They are
// the four already on manifest.VersionEntry rather than a private spelling of
// the same idea: two vocabularies for "^" is a defect waiting for the day they
// disagree about what it matches.
func ProfileConstraints() []string {
	return []string{
		manifest.ConstraintExact,
		manifest.ConstraintCompatible,
		manifest.ConstraintPatch,
		manifest.ConstraintAny,
	}
}

// ValidProfileConstraint reports whether kind is one of the four. The empty
// string is not: it means "no override" and callers test for it directly.
func ValidProfileConstraint(kind string) bool {
	return slices.Contains(ProfileConstraints(), kind)
}

// Profile names a class of host. It carries no rules itself: those live in the
// per-type markers and the entries, which is what makes the three levels
// separable.
type Profile struct {
	Name        string
	Description string
	Actor       string
	CreatedAt   time.Time
}

// ProfileTypeRule is the per-(profile, type) marker. Its presence is itself an
// answer: a type with no rule is one the profile states nothing about.
type ProfileTypeRule struct {
	Profile        string
	Type           string
	Membership     string
	VersionDefault string
	// Expansion is what a closed membership does about an unlisted package.
	// It has no meaning on an open type, which lists nothing to be outside of.
	Expansion string
	Actor     string
	UpdatedAt time.Time
}

// ProfileEntry names one package inside a profile. Constraint is empty when
// the entry declines to override its type's version default; when set it is
// one of the manifest.Constraint* values.
type ProfileEntry struct {
	Profile     string
	Type        string
	Name        string
	Constraint  string
	Version     string
	Origin      string // the host this entry was cataloged from, when it came from one
	Reason      string
	ReviewAfter string
	Actor       string
	CreatedAt   time.Time
}

// ProfileBinding attaches a profile to an identity migration 013 resolves.
type ProfileBinding struct {
	Identity  string
	Profile   string
	Comment   string
	Actor     string
	CreatedAt time.Time
}

// ProfileDetail is a whole profile in one read: the row, its type markers and
// its entries. The predicate needs all three to answer anything, so handing
// back less would make every caller run the same three queries.
type ProfileDetail struct {
	Profile Profile
	Types   []ProfileTypeRule
	Entries []ProfileEntry
}

// CreateProfile inserts a profile, returning ErrProfileExists for a name
// already taken.
func (a *DB) CreateProfile(ctx context.Context, p Profile) error {
	p.Name = strings.TrimSpace(p.Name)
	if err := validateProfileName(p.Name); err != nil {
		return err
	}
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	res, err := a.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO profiles (name, description, actor) VALUES (?, ?, ?)`,
		p.Name, p.Description, p.Actor)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrProfileExists, p.Name)
	}
	return nil
}

// validateProfileName rejects a name the CLI could not address again. Nothing
// here is a storage constraint; it is what keeps `bodega profile show <name>`
// from needing quoting rules of its own.
func validateProfileName(name string) error {
	if name == "" {
		return errors.New("a profile needs a name")
	}
	if strings.ContainsAny(name, " \t\n/,") {
		return fmt.Errorf("profile name %q contains whitespace, a slash or a comma; "+
			"use a plain word like 'web' or 'db-primary'", name)
	}
	return nil
}

// ListProfiles returns every profile, ordered by name.
func (a *DB) ListProfiles(ctx context.Context) ([]Profile, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT name, description, actor, created_at FROM profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		var p Profile
		var ts string
		if err := rows.Scan(&p.Name, &p.Description, &p.Actor, &ts); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProfile returns one profile with its markers and entries, or ErrNoProfile.
func (a *DB) GetProfile(ctx context.Context, name string) (*ProfileDetail, error) {
	var d ProfileDetail
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT name, description, actor, created_at FROM profiles WHERE name = ?`, name).
		Scan(&d.Profile.Name, &d.Profile.Description, &d.Profile.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %q", ErrNoProfile, name)
	}
	if err != nil {
		return nil, err
	}
	d.Profile.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)

	if d.Types, err = a.profileTypes(ctx, name); err != nil {
		return nil, err
	}
	if d.Entries, err = a.profileEntries(ctx, name); err != nil {
		return nil, err
	}
	return &d, nil
}

func (a *DB) profileTypes(ctx context.Context, profile string) ([]ProfileTypeRule, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT profile, pkg_type, membership, version_default, expansion, actor, updated_at
		   FROM profile_types WHERE profile = ? ORDER BY pkg_type`, profile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileTypeRule
	for rows.Next() {
		var r ProfileTypeRule
		var ts string
		if err := rows.Scan(&r.Profile, &r.Type, &r.Membership, &r.VersionDefault,
			&r.Expansion, &r.Actor, &ts); err != nil {
			return nil, err
		}
		r.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (a *DB) profileEntries(ctx context.Context, profile string) ([]ProfileEntry, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT profile, pkg_type, pkg_name, constraint_kind, version, origin, reason,
		        review_after, actor, created_at
		   FROM profile_entries WHERE profile = ? ORDER BY pkg_type, pkg_name`, profile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileEntry
	for rows.Next() {
		var e ProfileEntry
		var ts string
		if err := rows.Scan(&e.Profile, &e.Type, &e.Name, &e.Constraint, &e.Version,
			&e.Origin, &e.Reason, &e.ReviewAfter, &e.Actor, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetProfileTypeRule writes or replaces one type marker.
func (a *DB) SetProfileTypeRule(ctx context.Context, r ProfileTypeRule) error {
	r.Expansion = expansionOrDefault(r.Expansion)
	if err := validateProfileTypeRule(r); err != nil {
		return err
	}
	if err := a.requireProfile(ctx, r.Profile); err != nil {
		return err
	}
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	_, err := a.db.ExecContext(ctx, insertProfileTypeSQL,
		r.Profile, r.Type, r.Membership, r.VersionDefault, r.Expansion, r.Actor)
	return err
}

const insertProfileTypeSQL = `INSERT INTO profile_types (profile, pkg_type, membership, version_default, expansion, actor)
	 VALUES (?, ?, ?, ?, ?, ?)
	 ON CONFLICT(profile, pkg_type) DO UPDATE SET
	     membership = excluded.membership,
	     version_default = excluded.version_default,
	     expansion = excluded.expansion,
	     actor = excluded.actor,
	     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`

// PutProfileEntry writes or replaces one entry, reporting whether it was new.
//
// Replace rather than refuse, because the ordinary operation on an entry is
// changing the version it pins: an operator who has to remove and re-add loses
// the reason and the review date in the gap.
func (a *DB) PutProfileEntry(ctx context.Context, e ProfileEntry) (bool, error) {
	e.Name = strings.TrimSpace(e.Name)
	if err := validateProfileEntry(e); err != nil {
		return false, err
	}
	if err := a.requireProfile(ctx, e.Profile); err != nil {
		return false, err
	}
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	var existed int
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM profile_entries WHERE profile = ? AND pkg_type = ? AND pkg_name = ?`,
		e.Profile, e.Type, e.Name).Scan(&existed); err != nil {
		return false, err
	}
	_, err := a.db.ExecContext(ctx, insertProfileEntrySQL,
		e.Profile, e.Type, e.Name, e.Constraint, e.Version, e.Origin, e.Reason, e.ReviewAfter, e.Actor)
	if err != nil {
		return false, err
	}
	return existed == 0, nil
}

const insertProfileEntrySQL = `INSERT INTO profile_entries
	     (profile, pkg_type, pkg_name, constraint_kind, version, origin, reason, review_after, actor)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	 ON CONFLICT(profile, pkg_type, pkg_name) DO UPDATE SET
	     constraint_kind = excluded.constraint_kind,
	     version = excluded.version,
	     origin = excluded.origin,
	     reason = excluded.reason,
	     review_after = excluded.review_after,
	     actor = excluded.actor`

// RemoveProfileEntry deletes one entry, reporting whether it was there.
func (a *DB) RemoveProfileEntry(ctx context.Context, profile, typ, name string) (bool, error) {
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	res, err := a.db.ExecContext(ctx,
		`DELETE FROM profile_entries WHERE profile = ? AND pkg_type = ? AND pkg_name = ?`,
		profile, typ, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// BindProfile attaches a profile to an identity, returning the profile the
// identity was bound to before, empty when it was bound to nothing.
//
// Rebinding replaces, because reclassifying a host is the ordinary operation
// and the identity is the primary key: one host resolves to one profile, and
// two rows would leave the read path picking by row order.
func (a *DB) BindProfile(ctx context.Context, b ProfileBinding) (string, error) {
	b.Identity = strings.TrimSpace(b.Identity)
	if b.Identity == "" {
		return "", errors.New("a binding needs an identity to bind")
	}
	if err := a.requireProfile(ctx, b.Profile); err != nil {
		return "", err
	}
	if a.readOnly {
		return "", errors.New("audit db is read-only")
	}
	var previous string
	err := a.db.QueryRowContext(ctx,
		`SELECT profile FROM profile_bindings WHERE identity = ?`, b.Identity).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	_, err = a.db.ExecContext(ctx,
		`INSERT INTO profile_bindings (identity, profile, comment, actor) VALUES (?, ?, ?, ?)
		 ON CONFLICT(identity) DO UPDATE SET
		     profile = excluded.profile,
		     comment = excluded.comment,
		     actor = excluded.actor,
		     created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
		b.Identity, b.Profile, b.Comment, b.Actor)
	if err != nil {
		return "", err
	}
	return previous, nil
}

// UnbindProfile removes one binding, reporting whether it was there.
func (a *DB) UnbindProfile(ctx context.Context, identity string) (bool, error) {
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	res, err := a.db.ExecContext(ctx, `DELETE FROM profile_bindings WHERE identity = ?`, identity)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ListProfileBindings returns every binding, or those of one profile when it
// is named. Ordered by identity.
func (a *DB) ListProfileBindings(ctx context.Context, profile string) ([]ProfileBinding, error) {
	query := `SELECT identity, profile, comment, actor, created_at FROM profile_bindings`
	var args []any
	if profile != "" {
		query += ` WHERE profile = ?`
		args = append(args, profile)
	}
	query += ` ORDER BY identity`
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileBinding
	for rows.Next() {
		var b ProfileBinding
		var ts string
		if err := rows.Scan(&b.Identity, &b.Profile, &b.Comment, &b.Actor, &ts); err != nil {
			return nil, err
		}
		b.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, b)
	}
	return out, rows.Err()
}

// requireProfile refuses a write naming a profile that does not exist. The
// connection does not enable foreign keys, so this is the whole of that check:
// without it a typo produces an entry no profile reads and no command lists.
func (a *DB) requireProfile(ctx context.Context, name string) error {
	var n int
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM profiles WHERE name = ?`, name).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrNoProfile, name)
	}
	return nil
}

// CreateProfileWith writes a profile, its type markers and its entries in one
// transaction.
//
// A document rejected partway would otherwise leave a bindable profile holding
// a subset of what was authored, which is not a failed create: a closed type
// listing three of seven packages is a working access control permitting less
// than anyone wrote, under a name no verb here can reuse or remove. Same reason
// SeedACL claims a list and fills it atomically.
func (a *DB) CreateProfileWith(ctx context.Context, p Profile, types []ProfileTypeRule, entries []ProfileEntry) error {
	p.Name = strings.TrimSpace(p.Name)
	if err := validateProfileName(p.Name); err != nil {
		return err
	}
	for _, r := range types {
		if err := validateProfileTypeRule(r); err != nil {
			return fmt.Errorf("%s: %w", r.Type, err)
		}
	}
	for i := range entries {
		entries[i].Name = strings.TrimSpace(entries[i].Name)
		if err := validateProfileEntry(entries[i]); err != nil {
			return fmt.Errorf("%s/%s: %w", entries[i].Type, entries[i].Name, err)
		}
	}
	if a.readOnly {
		return errors.New("audit db is read-only")
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO profiles (name, description, actor) VALUES (?, ?, ?)`,
		p.Name, p.Description, p.Actor)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrProfileExists, p.Name)
	}
	for _, r := range types {
		if _, err := tx.ExecContext(ctx, insertProfileTypeSQL,
			p.Name, r.Type, r.Membership, r.VersionDefault,
			expansionOrDefault(r.Expansion), r.Actor); err != nil {
			return fmt.Errorf("%s: %w", r.Type, err)
		}
	}
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx, insertProfileEntrySQL,
			p.Name, e.Type, e.Name, e.Constraint, e.Version, e.Origin,
			e.Reason, e.ReviewAfter, e.Actor); err != nil {
			return fmt.Errorf("%s/%s: %w", e.Type, e.Name, err)
		}
	}
	return tx.Commit()
}

// validateProfileTypeRule and validateProfileEntry hold the checks the single-
// row writers make, so the whole-document path can run them before the first
// write rather than discovering the third one halfway through.
func validateProfileTypeRule(r ProfileTypeRule) error {
	if !ValidMembership(r.Membership) {
		return fmt.Errorf("membership %q is not one of: %s", r.Membership, strings.Join(Memberships(), ", "))
	}
	if !ValidVersionDefault(r.VersionDefault) {
		return fmt.Errorf("version default %q is not one of: %s", r.VersionDefault, strings.Join(VersionDefaults(), ", "))
	}
	if r.Expansion != "" && !ValidExpansion(r.Expansion) {
		return fmt.Errorf("expansion %q is not one of: %s", r.Expansion, strings.Join(Expansions(), ", "))
	}
	return nil
}

func validateProfileEntry(e ProfileEntry) error {
	if strings.TrimSpace(e.Name) == "" {
		return errors.New("an entry needs a package name")
	}
	if e.Constraint != "" && !ValidProfileConstraint(e.Constraint) {
		return fmt.Errorf("constraint %q is not one of: %s",
			e.Constraint, strings.Join(ProfileConstraints(), ", "))
	}
	return nil
}
