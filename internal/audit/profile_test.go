package audit

import (
	"errors"
	"path/filepath"
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
