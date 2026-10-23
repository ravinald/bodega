package audit

import (
	"database/sql"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func profileTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestProfileRoundTrip(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)

	if err := db.CreateProfile(ctx, Profile{Name: "web", Description: "web tier", Actor: "ravi"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.CreateProfile(ctx, Profile{Name: "web"}); !errors.Is(err, ErrProfileExists) {
		t.Fatalf("a second create of the same name returned %v, want ErrProfileExists", err)
	}
	if err := db.SetProfileTypeRule(ctx, ProfileTypeRule{
		Profile: "web", Type: manifest.TypeApt,
		Membership: MembershipClosed, VersionDefault: VersionFloating,
	}); err != nil {
		t.Fatalf("set type rule: %v", err)
	}
	created, err := db.PutProfileEntry(ctx, ProfileEntry{
		Profile: "web", Type: manifest.TypeApt, Name: "nginx", Origin: "db01",
	})
	if err != nil || !created {
		t.Fatalf("put entry: created=%v err=%v", created, err)
	}

	d, err := db.GetProfile(ctx, "web")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if d.Profile.Description != "web tier" || len(d.Types) != 1 || len(d.Entries) != 1 {
		t.Fatalf("round trip lost something: %+v", d)
	}
	if d.Entries[0].Origin != "db01" {
		t.Errorf("origin did not survive the round trip: %q", d.Entries[0].Origin)
	}
	if d.Profile.CreatedAt.IsZero() {
		t.Error("created_at came back zero, so `profile list` has no date to print")
	}
}

// A replaced entry is the ordinary edit: changing the version a package is
// held at. A store that refused would make an operator remove and re-add,
// which loses the reason and the review date in the gap.
func TestPutProfileEntryReplaces(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)
	if err := db.CreateProfile(ctx, Profile{Name: "web"}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.PutProfileEntry(ctx, ProfileEntry{
		Profile: "web", Type: manifest.TypeApt, Name: "postgresql",
		Constraint: manifest.ConstraintExact, Version: "14.10", Reason: "old",
	}); err != nil {
		t.Fatal(err)
	}
	created, err := db.PutProfileEntry(ctx, ProfileEntry{
		Profile: "web", Type: manifest.TypeApt, Name: "postgresql",
		Constraint: manifest.ConstraintExact, Version: "14.11", Reason: "15 breaks the config",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("a replacement reported itself as a creation, so the audit row would name the wrong event")
	}
	d, err := db.GetProfile(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("replacing left %d entries", len(d.Entries))
	}
	if d.Entries[0].Version != "14.11" || d.Entries[0].Reason != "15 breaks the config" {
		t.Errorf("the replacement did not land: %+v", d.Entries[0])
	}
}

// Foreign keys are off on this connection, so requireProfile is the whole of
// that check. Without it a typo writes an entry no profile reads.
func TestProfileWritesRefuseAnUnknownProfile(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)

	if _, err := db.PutProfileEntry(ctx, ProfileEntry{
		Profile: "typo", Type: manifest.TypeApt, Name: "nginx",
	}); !errors.Is(err, ErrNoProfile) {
		t.Errorf("entry write against an unknown profile returned %v, want ErrNoProfile", err)
	}
	if err := db.SetProfileTypeRule(ctx, ProfileTypeRule{
		Profile: "typo", Type: manifest.TypeApt,
		Membership: MembershipOpen, VersionDefault: VersionFloating,
	}); !errors.Is(err, ErrNoProfile) {
		t.Errorf("type rule against an unknown profile returned %v, want ErrNoProfile", err)
	}
	if _, err := db.BindProfile(ctx, ProfileBinding{Identity: "db01", Profile: "typo"}); !errors.Is(err, ErrNoProfile) {
		t.Errorf("binding to an unknown profile returned %v, want ErrNoProfile", err)
	}
	if _, err := db.GetProfile(ctx, "typo"); !errors.Is(err, ErrNoProfile) {
		t.Errorf("get of an unknown profile returned %v, want ErrNoProfile", err)
	}
}

// One identity resolves to at most one profile. Rebinding moves it and reports
// where it came from, because a silent move is how a host ends up governed by
// a profile nobody remembers assigning.
func TestBindProfileMovesAnIdentity(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)
	for _, name := range []string{"web", "db"} {
		if err := db.CreateProfile(ctx, Profile{Name: name}); err != nil {
			t.Fatal(err)
		}
	}

	previous, err := db.BindProfile(ctx, ProfileBinding{Identity: "host01", Profile: "web"})
	if err != nil || previous != "" {
		t.Fatalf("first bind: previous=%q err=%v", previous, err)
	}
	previous, err = db.BindProfile(ctx, ProfileBinding{Identity: "host01", Profile: "db"})
	if err != nil {
		t.Fatal(err)
	}
	if previous != "web" {
		t.Errorf("the rebind reported %q as the previous profile, want web", previous)
	}
	bindings, err := db.ListProfileBindings(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Profile != "db" {
		t.Fatalf("one identity resolved to %d bindings: %+v", len(bindings), bindings)
	}
	removed, err := db.UnbindProfile(ctx, "host01")
	if err != nil || !removed {
		t.Fatalf("unbind: removed=%v err=%v", removed, err)
	}
}

// The stored constraint vocabulary is manifest's. A fifth spelling here is a
// defect waiting for the day the two disagree about what "^" matches.
func TestProfileConstraintsAreTheManifestFour(t *testing.T) {
	want := []string{
		manifest.ConstraintExact,
		manifest.ConstraintCompatible,
		manifest.ConstraintPatch,
		manifest.ConstraintAny,
	}
	got := ProfileConstraints()
	if len(got) != len(want) {
		t.Fatalf("ProfileConstraints() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ProfileConstraints()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if ValidProfileConstraint("pinned") {
		t.Error("a version-default word was accepted as a constraint kind")
	}
	if ValidProfileConstraint("") {
		t.Error("the empty constraint validated; it means 'no override' and callers test for it directly")
	}
}

// The CHECK clauses are the store's half of the same rule, and they are the
// half a hand-written INSERT still meets.
func TestProfileStoreRefusesAnUnknownVocabulary(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)
	if err := db.CreateProfile(ctx, Profile{Name: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProfileTypeRule(ctx, ProfileTypeRule{
		Profile: "web", Type: manifest.TypeApt, Membership: "partial", VersionDefault: VersionFloating,
	}); err == nil {
		t.Error("membership 'partial' was accepted")
	}
	if _, err := db.db.ExecContext(ctx,
		`INSERT INTO profile_entries (profile, pkg_type, pkg_name, constraint_kind) VALUES ('web','apt','x','tilde')`,
	); err == nil {
		t.Error("the profile_entries CHECK accepted a fifth constraint spelling")
	}
}

func TestProfileNameIsAddressable(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)
	for _, bad := range []string{"", "web tier", "web/db", "a,b"} {
		if err := db.CreateProfile(ctx, Profile{Name: bad}); err == nil {
			t.Errorf("profile name %q was accepted; the CLI could not address it again", bad)
		}
	}
}

// seedDeletableProfile writes a profile carrying a row in every table
// DeleteProfile clears, plus a second profile it must leave alone.
func seedDeletableProfile(t *testing.T, db *DB, name string) {
	t.Helper()
	ctx := t.Context()
	if err := db.CreateProfileWith(ctx, Profile{Name: name},
		[]ProfileTypeRule{
			{Type: manifest.TypeApt, Membership: MembershipOpen, VersionDefault: VersionFloating},
			{Type: manifest.TypePypi, Membership: MembershipOpen, VersionDefault: VersionFloating},
		},
		[]ProfileEntry{
			{Type: manifest.TypeApt, Name: "nginx"},
			{Type: manifest.TypeApt, Name: "curl"},
			{Type: manifest.TypePypi, Name: "requests"},
		}); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if _, err := db.AcceptInventoryBaseline(ctx, InventoryBaseline{
		Profile:    name,
		Components: []BaselineComponent{{Ecosystem: "deb", Name: "nginx"}},
	}); err != nil {
		t.Fatalf("accept baseline for %s: %v", name, err)
	}
}

// profileRowCounts counts every row stored under a profile's name, so a
// refusal can be shown to have removed nothing.
func profileRowCounts(t *testing.T, db *DB, name string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for table, query := range map[string]string{
		"profiles":         `SELECT COUNT(*) FROM profiles WHERE name = ?`,
		"profile_types":    `SELECT COUNT(*) FROM profile_types WHERE profile = ?`,
		"profile_entries":  `SELECT COUNT(*) FROM profile_entries WHERE profile = ?`,
		"profile_bindings": `SELECT COUNT(*) FROM profile_bindings WHERE profile = ?`,
		"baselines":        `SELECT COUNT(*) FROM inventory_baselines WHERE profile = ?`,
		"components": `SELECT COUNT(*) FROM inventory_baseline_components
			WHERE baseline_id IN (SELECT id FROM inventory_baselines WHERE profile = ?)`,
	} {
		var n int
		if err := db.db.QueryRowContext(t.Context(), query, name).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

func TestDeleteProfileRemovesEveryRow(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)
	seedDeletableProfile(t, db, "web")
	seedDeletableProfile(t, db, "db")
	untouched := profileRowCounts(t, db, "db")

	d, err := db.DeleteProfile(ctx, "web", false)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if d.Types != 2 || d.Entries != 3 || d.Baselines != 1 || d.BaselineComponents != 1 || len(d.Unbound) != 0 {
		t.Errorf("deletion counts = %+v, want 2 types, 3 entries, 1 baseline, 1 component, none unbound", d)
	}
	for table, n := range profileRowCounts(t, db, "web") {
		if n != 0 {
			t.Errorf("%s still holds %d rows for a deleted profile", table, n)
		}
	}
	if _, err := db.GetProfile(ctx, "web"); !errors.Is(err, ErrNoProfile) {
		t.Errorf("GetProfile after delete returned %v, want ErrNoProfile", err)
	}
	if got := profileRowCounts(t, db, "db"); !maps.Equal(got, untouched) {
		t.Errorf("deleting web changed db: before %v, after %v", untouched, got)
	}
	if b, err := db.CurrentInventoryBaseline(ctx, "", "web"); err != nil || b != nil {
		t.Errorf("a profile re-created as web would adopt baseline %+v (err %v)", b, err)
	}
}

func TestDeleteProfileRefusesABoundProfile(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)
	seedDeletableProfile(t, db, "web")
	for _, id := range []string{"web02", "web01"} {
		if _, err := db.BindProfile(ctx, ProfileBinding{Identity: id, Profile: "web"}); err != nil {
			t.Fatalf("bind %s: %v", id, err)
		}
	}
	before := profileRowCounts(t, db, "web")

	_, err := db.DeleteProfile(ctx, "web", false)
	if !errors.Is(err, ErrProfileBound) {
		t.Fatalf("deleting a bound profile returned %v, want ErrProfileBound", err)
	}
	if !strings.Contains(err.Error(), "web01, web02") {
		t.Errorf("the refusal does not name the bound identities: %v", err)
	}
	if after := profileRowCounts(t, db, "web"); !maps.Equal(before, after) {
		t.Errorf("a refused delete removed rows: before %v, after %v", before, after)
	}
}

func TestDeleteProfileUnbindRemovesTheBindings(t *testing.T) {
	ctx := t.Context()
	db := profileTestDB(t)
	seedDeletableProfile(t, db, "web")
	seedDeletableProfile(t, db, "db")
	for id, p := range map[string]string{"web01": "web", "web02": "web", "db01": "db"} {
		if _, err := db.BindProfile(ctx, ProfileBinding{Identity: id, Profile: p}); err != nil {
			t.Fatalf("bind %s: %v", id, err)
		}
	}

	d, err := db.DeleteProfile(ctx, "web", true)
	if err != nil {
		t.Fatalf("delete --unbind: %v", err)
	}
	if !slices.Equal(d.Unbound, []string{"web01", "web02"}) {
		t.Errorf("unbound = %v, want [web01 web02]", d.Unbound)
	}
	for table, n := range profileRowCounts(t, db, "web") {
		if n != 0 {
			t.Errorf("%s still holds %d rows for a deleted profile", table, n)
		}
	}
	bindings, err := db.ListProfileBindings(ctx, "")
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 || bindings[0].Identity != "db01" {
		t.Errorf("bindings after delete = %+v, want db01 alone", bindings)
	}
}

func TestDeleteProfileRefusesAnUnknownName(t *testing.T) {
	db := profileTestDB(t)
	_, err := db.DeleteProfile(t.Context(), "nope", false)
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("deleting an unknown profile returned %v, want ErrNoProfile", err)
	}
	for _, want := range []string{`"nope"`, "bodega profile list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
}

func TestDeleteProfileRefusesAReadOnlyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	seed, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	seedDeletableProfile(t, seed, "web")
	_ = seed.Close()
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	ro, err := Open(path)
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer ro.Close()
	if !ro.ReadOnly() {
		t.Skip("the file opened writable, as it does for root")
	}
	if _, err := ro.DeleteProfile(t.Context(), "web", true); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("delete on a read-only db returned %v, want a read-only error", err)
	}
}

const profileAptArchivesVersion = 40

// Migration 040 on a database the schema before it wrote: a scoped apt rule
// keeps every field it had and reads back with no vendor archive listed,
// which is the empty list a scoped profile refuses every vendor archive under.
func TestProfileAptArchivesMigrationKeepsExistingRules(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "audit.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	m := migrator(t, raw)
	if err := m.Migrate(profileAptArchivesVersion - 1); err != nil {
		t.Fatalf("migrate to %d: %v", profileAptArchivesVersion-1, err)
	}
	for _, q := range []string{
		`INSERT INTO profiles (name, description, actor) VALUES ('edge', '', 'ravi')`,
		`INSERT INTO profile_types (profile, pkg_type, membership, version_default, expansion, apt_base, actor)
		 VALUES ('edge', 'apt', 'closed', 'floating', 'block', 'noble', 'ravi')`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	_ = raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open audit db past %d: %v", profileAptArchivesVersion, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := db.GetProfile(ctx, "edge")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if len(d.Types) != 1 {
		t.Fatalf("types = %+v, want the one apt rule", d.Types)
	}
	r := d.Types[0]
	if r.AptBase != "noble" || r.Membership != MembershipClosed || r.Expansion != ExpansionBlock || r.AptArchives != nil {
		t.Errorf("migrated rule = %+v, want base noble, closed, block and no archives", r)
	}

	r.AptArchives = []string{"stable", "noble-pgdg", "stable", ""}
	if err := db.SetProfileTypeRule(ctx, r); err != nil {
		t.Fatalf("set archives: %v", err)
	}
	d, err = db.GetProfile(ctx, "edge")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if got := strings.Join(d.Types[0].AptArchives, ","); got != "noble-pgdg,stable" {
		t.Errorf("stored archives = %q, want noble-pgdg,stable", got)
	}

	r.AptArchives = nil
	if err := db.SetProfileTypeRule(ctx, r); err != nil {
		t.Fatalf("clear archives: %v", err)
	}
	if d, _ = db.GetProfile(ctx, "edge"); d.Types[0].AptArchives != nil {
		t.Errorf("cleared archives read back as %v", d.Types[0].AptArchives)
	}

	if err := db.SetProfileTypeRule(ctx, ProfileTypeRule{Profile: "edge", Type: manifest.TypeNpm,
		Membership: MembershipOpen, VersionDefault: VersionFloating, AptArchives: []string{"stable"}}); err == nil {
		t.Error("archives on an npm rule were stored; nothing reads them there")
	}
}
