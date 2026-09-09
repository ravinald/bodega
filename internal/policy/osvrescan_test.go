package policy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// osvRecord builds one npm advisory covering [introduced, fixed).
func npmAdvisory(id, pkg, introduced, fixed string) map[string]any {
	return map[string]any{
		"id":       id,
		"modified": "2026-09-01T00:00:00Z",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "npm", "name": pkg},
			"ranges": []any{map[string]any{
				"type":   "SEMVER",
				"events": []any{map[string]any{"introduced": introduced}, map[string]any{"fixed": fixed}},
			}},
		}},
		"severity": []any{map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}
}

// dbWithNpm syncs a database holding exactly the supplied npm records. Two
// calls with different records stand in for the same mirror before and after
// an OSV refresh, which is the only way to drive a withdrawal from a test.
func dbWithNpm(t *testing.T, dir string, records ...map[string]any) *OSVDatabase {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, rec := range records {
			f, err := zw.Create(rec["id"].(string) + ".json")
			if err != nil {
				t.Errorf("zip create: %v", err)
				return
			}
			if err := json.NewEncoder(f).Encode(rec); err != nil {
				t.Errorf("zip write: %v", err)
				return
			}
		}
		if err := zw.Close(); err != nil {
			t.Errorf("zip close: %v", err)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)

	db := NewOSVDatabase(dir)
	db.ExportBase = srv.URL
	if _, err := db.Sync(context.Background(), "npm"); err != nil {
		t.Fatalf("sync npm: %v", err)
	}
	return db
}

func rescanChecker(db *OSVDatabase) *OSVChecker {
	ck := NewOSVChecker(nil) // Rescan reads no policy row
	ck.LocalDB = db
	return ck
}

func npmPkg() *manifest.PackageManifest {
	return &manifest.PackageManifest{Name: "minimist", Type: manifest.TypeNpm}
}

// TestOSVRescan_UncheckedToClean is the transition the check date exists for:
// before the run the version carries nothing, and afterwards it carries a date
// and still no findings. Without the date those two states are the same bytes.
func TestOSVRescan_UncheckedToClean(t *testing.T) {
	db := dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-old", "minimist", "0", "1.2.3"))
	ve := &manifest.VersionEntry{Version: "1.2.8"}

	ch := rescanChecker(db).Rescan(context.Background(), npmPkg(), ve)
	if !ch.Answered {
		t.Fatalf("a synced database must answer: %+v", ch)
	}
	if ch.Flagged || ch.Cleared {
		t.Errorf("a first clean answer is neither flagged nor cleared: %+v", ch)
	}
	if ve.Metadata[OSVMetaVulns] != "" {
		t.Errorf("clean version must carry no ids: %q", ve.Metadata[OSVMetaVulns])
	}
	if _, err := time.Parse(time.RFC3339, ve.Metadata[OSVMetaCheckedAt]); err != nil {
		t.Fatalf("clean version must carry a check date, got %q (%v)",
			ve.Metadata[OSVMetaCheckedAt], err)
	}
	if st := OSVStampOf(*ve); st.State() != "clean" {
		t.Errorf("state should read clean, got %q", st.State())
	}
}

// TestOSVRescan_CleanToFlagged is the case admission cannot cover: the version
// was imported clean and an advisory was published against it afterwards.
func TestOSVRescan_CleanToFlagged(t *testing.T) {
	dir := t.TempDir()
	ve := &manifest.VersionEntry{Version: "1.2.8"}

	first := rescanChecker(dbWithNpm(t, dir, npmAdvisory("GHSA-old", "minimist", "0", "1.2.3")))
	first.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	if ch := first.Rescan(context.Background(), npmPkg(), ve); !ch.Answered || ch.Flagged {
		t.Fatalf("setup: 1.2.8 is outside the old advisory: %+v", ch)
	}
	firstCheck := ve.Metadata[OSVMetaCheckedAt]

	// A new advisory lands upstream and the mirror is re-synced.
	refreshed := dbWithNpm(t, dir,
		npmAdvisory("GHSA-old", "minimist", "0", "1.2.3"),
		npmAdvisory("GHSA-new", "minimist", "1.2.4", "1.2.9"))
	ch := rescanChecker(refreshed).Rescan(context.Background(), npmPkg(), ve)
	if !ch.Flagged {
		t.Fatalf("a version that became vulnerable must report newly flagged: %+v", ch)
	}
	if ve.Metadata[OSVMetaVulns] != "GHSA-new" {
		t.Errorf("ids not restamped: %q", ve.Metadata[OSVMetaVulns])
	}
	if ve.Metadata[OSVMetaSeverity] == "" {
		t.Error("severity should be restamped alongside the ids")
	}
	if ve.Metadata[OSVMetaCheckedAt] == firstCheck {
		t.Error("the check date must move with the answer")
	}
	if ve.Hidden || ve.Frozen {
		t.Error("rescan records; it must not hide or freeze a version it flagged")
	}
}

// TestOSVRescan_FlaggedToClearedOnWithdrawal covers the reverse: OSV withdraws
// the advisory, the mirror stops carrying it, and the stamp has to come off.
// A flag nothing can clear is one an operator learns to ignore.
func TestOSVRescan_FlaggedToClearedOnWithdrawal(t *testing.T) {
	dir := t.TempDir()
	ve := &manifest.VersionEntry{Version: "1.2.5"}

	flagged := dbWithNpm(t, dir, npmAdvisory("GHSA-doomed", "minimist", "1.2.4", "1.2.9"))
	if ch := rescanChecker(flagged).Rescan(context.Background(), npmPkg(), ve); !ch.Flagged {
		t.Fatalf("setup: 1.2.5 should match the advisory: %+v", ch)
	}
	if ve.Metadata[OSVMetaSeverity] == "" {
		t.Fatal("setup: severity should be stamped")
	}

	// The advisory is withdrawn: sync drops it, so the refreshed mirror holds
	// an unrelated record and nothing that names 1.2.5.
	withdrawn := dbWithNpm(t, dir, npmAdvisory("GHSA-other", "leftpad", "0", "1.0.0"))
	ch := rescanChecker(withdrawn).Rescan(context.Background(), npmPkg(), ve)
	if !ch.Cleared {
		t.Fatalf("a withdrawn advisory must report newly cleared: %+v", ch)
	}
	if _, ok := ve.Metadata[OSVMetaVulns]; ok {
		t.Errorf("the ids must come off, got %q", ve.Metadata[OSVMetaVulns])
	}
	if _, ok := ve.Metadata[OSVMetaSeverity]; ok {
		t.Errorf("the severity must come off with the ids, got %q", ve.Metadata[OSVMetaSeverity])
	}
	if ve.Metadata[OSVMetaCheckedAt] == "" {
		t.Error("clearing a flag is still an answer and still gets a date")
	}
}

// TestOSVRescan_UnreadableDatabaseKeepsStamp is the failure that would make
// the whole feature dangerous: a rescan that cannot read the database must not
// overwrite a real finding with a blank one and report a clean fleet.
func TestOSVRescan_UnreadableDatabaseKeepsStamp(t *testing.T) {
	dir := t.TempDir()
	ve := &manifest.VersionEntry{Version: "1.2.5"}

	db := dbWithNpm(t, dir, npmAdvisory("GHSA-doomed", "minimist", "1.2.4", "1.2.9"))
	if ch := rescanChecker(db).Rescan(context.Background(), npmPkg(), ve); !ch.Flagged {
		t.Fatalf("setup: expected a flag: %+v", ch)
	}
	want := map[string]string{}
	for k, v := range ve.Metadata {
		want[k] = v
	}

	for _, tc := range []struct {
		name string
		ck   func() *OSVChecker
	}{
		{"no database configured", func() *OSVChecker { return rescanChecker(nil) }},
		{"ecosystem never synced", func() *OSVChecker { return rescanChecker(NewOSVDatabase(t.TempDir())) }},
		{"archive corrupt", func() *OSVChecker {
			broken := t.TempDir()
			for _, name := range []string{"npm.json.gz", "npm.meta.json"} {
				src, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatalf("read %s: %v", name, err)
				}
				if name == "npm.json.gz" {
					src = []byte("not a gzip stream")
				}
				if err := os.WriteFile(filepath.Join(broken, name), src, 0o644); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}
			return rescanChecker(NewOSVDatabase(broken))
		}},
		{"database too old to date an answer against", func() *OSVChecker {
			ck := rescanChecker(dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-doomed", "minimist", "1.2.4", "1.2.9")))
			ck.MaxAge = 7 * 24 * time.Hour
			ck.Now = func() time.Time { return time.Now().Add(400 * 24 * time.Hour) }
			return ck
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := tc.ck().Rescan(context.Background(), npmPkg(), ve)
			if ch.Answered {
				t.Fatalf("%s must not count as an answer: %+v", tc.name, ch)
			}
			if ch.Reason == "" {
				t.Error("an unanswered version must carry a reason")
			}
			for k, v := range want {
				if ve.Metadata[k] != v {
					t.Errorf("%s must survive: %s = %q, want %q", k, k, ve.Metadata[k], v)
				}
			}
			if len(ve.Metadata) != len(want) {
				t.Errorf("nothing may be added either: %v", ve.Metadata)
			}
		})
	}
}

// TestOSVRescanSummary_SilenceIsNotSuccess pins requirement 3's second
// sentence: a run that flagged nothing and a run that could not read the
// database both print zero, so only the unanswered block separates them.
func TestOSVRescanSummary_SilenceIsNotSuccess(t *testing.T) {
	var clean OSVRescanSummary
	for range 3 {
		clean.Add(OSVRescanChange{Answered: true})
	}
	var blind OSVRescanSummary
	for range 3 {
		blind.Add(OSVRescanChange{Reason: "no local OSV database for npm in /tmp/x; run `bodega policy osv sync`"})
	}

	var a, b strings.Builder
	clean.Report(&a)
	blind.Report(&b)
	if a.String() == b.String() {
		t.Fatalf("a clean run and a blind run must not read the same:\n%s", a.String())
	}
	if !strings.Contains(a.String(), "3 answered") {
		t.Errorf("clean run must report what it answered: %q", a.String())
	}
	if !strings.Contains(b.String(), "0 answered") || !strings.Contains(b.String(), "3 x no local OSV database") {
		t.Errorf("blind run must name the count and the reason: %q", b.String())
	}
	if blind.Unanswered() != 3 {
		t.Errorf("unanswered = %d, want 3", blind.Unanswered())
	}
}

// TestOSVRescan_SkipsEcosystemsOSVCannotAnswer keeps an apt version out of the
// answered count instead of stamping it clean, which would claim a check
// against a database that has no apt records at all.
func TestOSVRescan_SkipsEcosystemsOSVCannotAnswer(t *testing.T) {
	db := dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-old", "minimist", "0", "1.2.3"))
	ve := &manifest.VersionEntry{Version: "5.2"}
	ch := rescanChecker(db).Rescan(context.Background(),
		&manifest.PackageManifest{Name: "bash", Type: manifest.TypeApt}, ve)
	if ch.Answered {
		t.Fatalf("apt has no OSV ecosystem: %+v", ch)
	}
	if len(ve.Metadata) != 0 {
		t.Errorf("nothing may be stamped, got %v", ve.Metadata)
	}
}

// TestOSVRescan_NonExactConstraintIsUnanswered covers the range a point
// lookup cannot settle. The server resolves a non-exact constraint against
// upstream and serves releases the manifest never lists, so asking OSV about
// the base version and writing a check date on the answer dates a query that
// covered one of them.
func TestOSVRescan_NonExactConstraintIsUnanswered(t *testing.T) {
	// ^1.2.0 and ~1.2.0 both cover 1.2.5, which this advisory flags; 1.2.0
	// itself is outside it, so the point lookup comes back clean.
	db := dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-doomed", "minimist", "1.2.4", "1.2.6"))

	for _, constraint := range []string{
		manifest.ConstraintCompatible,
		manifest.ConstraintPatch,
		manifest.ConstraintAny,
	} {
		t.Run(constraint, func(t *testing.T) {
			ve := &manifest.VersionEntry{
				Version:           "1.2.0",
				VersionConstraint: constraint,
				Metadata:          map[string]string{OSVMetaCheckedAt: "2026-01-01T00:00:00Z"},
			}
			ch := rescanChecker(db).Rescan(context.Background(), npmPkg(), ve)
			if ch.Answered {
				t.Fatalf("constraint %q serves versions the point lookup never saw: %+v", constraint, ch)
			}
			if !strings.Contains(ch.Reason, constraint) {
				t.Errorf("the reason must name the constraint, got %q", ch.Reason)
			}
			if got := ve.Metadata[OSVMetaCheckedAt]; got != "2026-01-01T00:00:00Z" {
				t.Errorf("an unanswered version keeps its previous stamp, got %q", got)
			}
		})
	}

	// The controls: an exact constraint and the empty default name one
	// version, so both still answer and still carry a date.
	for _, constraint := range []string{"", manifest.ConstraintExact} {
		t.Run("answers/"+constraint, func(t *testing.T) {
			ve := &manifest.VersionEntry{Version: "1.2.0", VersionConstraint: constraint}
			if ch := rescanChecker(db).Rescan(context.Background(), npmPkg(), ve); !ch.Answered {
				t.Fatalf("constraint %q names one version: %+v", constraint, ch)
			}
			if ve.Metadata[OSVMetaCheckedAt] == "" {
				t.Errorf("constraint %q must still be dated", constraint)
			}
		})
	}
}

// TestOSVCheck_NonExactConstraintDoesNotStampClean is the same blind spot at
// admission. A record found against the base version is still reported, so the
// guard costs no finding it would otherwise have made.
func TestOSVCheck_NonExactConstraintDoesNotStampClean(t *testing.T) {
	db := dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-doomed", "minimist", "1.2.4", "1.2.6"))
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db

	clean := &manifest.VersionEntry{Version: "1.2.0", VersionConstraint: manifest.ConstraintAny}
	if r := ck.Check(context.Background(), npmPkg(), clean); r.Action != ActionWarn {
		t.Fatalf("an unevaluated range warns rather than passing: %+v", r)
	}
	if got := clean.Metadata[OSVMetaCheckedAt]; got != "" {
		t.Errorf("admission stamped a check date on an %q constraint entry: %q",
			manifest.ConstraintAny, got)
	}

	flagged := &manifest.VersionEntry{Version: "1.2.5", VersionConstraint: manifest.ConstraintAny}
	if r := ck.Check(context.Background(), npmPkg(), flagged); r.Action != ActionBlock {
		t.Fatalf("a record against the base version still blocks: %+v", r)
	}
	if flagged.Metadata[OSVMetaVulns] != "GHSA-doomed" {
		t.Errorf("the ids are still recorded, got %q", flagged.Metadata[OSVMetaVulns])
	}
	if got := flagged.Metadata[OSVMetaCheckedAt]; got != "" {
		t.Errorf("a range nobody evaluated carries no date, got %q", got)
	}
}

// TestOSVCheck_StampsCleanAtAdmission keeps admission and rescan writing the
// same three keys. A version admitted clean after this lands must not read as
// unchecked until somebody runs a rescan.
func TestOSVCheck_StampsCleanAtAdmission(t *testing.T) {
	db := dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-old", "minimist", "0", "1.2.3"))
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db

	ve := &manifest.VersionEntry{Version: "1.2.8"}
	if r := ck.Check(context.Background(), npmPkg(), ve); r.Action != ActionPass {
		t.Fatalf("1.2.8 is clean: %+v", r)
	}
	if ve.Metadata[OSVMetaCheckedAt] == "" {
		t.Error("an admission-time clean result must carry a check date")
	}
}

// TestOSVStamp_UndatableFindingsDropTheOldDate pins the pairing R2 exists for:
// the date beside a set of ids has to be the date those ids were found. Data
// too old to date a verdict against still names records, and the stamp keeps
// them, but the date left over from the clean check before it would otherwise
// render as "1 vuln(s), checked <the day it was clean>".
func TestOSVStamp_UndatableFindingsDropTheOldDate(t *testing.T) {
	dir := t.TempDir()
	dbWithNpm(t, dir, npmAdvisory("GHSA-doomed", "minimist", "1.2.4", "1.2.9"))

	clean := "2026-01-01T00:00:00Z"
	ve := &manifest.VersionEntry{
		Version:  "1.2.5",
		Metadata: map[string]string{OSVMetaCheckedAt: clean},
	}

	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = NewOSVDatabase(dir)
	ck.MaxAge = 7 * 24 * time.Hour
	ck.Now = func() time.Time { return time.Now().Add(400 * 24 * time.Hour) }

	r := ck.Check(context.Background(), npmPkg(), ve)
	if r.Action != ActionBlock {
		t.Fatalf("stale data still names a vulnerable version: %+v", r)
	}
	if !strings.Contains(ve.Metadata[OSVMetaVulns], "GHSA-doomed") {
		t.Errorf("the ids are worth keeping: %q", ve.Metadata[OSVMetaVulns])
	}
	if got := ve.Metadata[OSVMetaCheckedAt]; got != "" {
		t.Errorf("a clean check's date must not label findings it never saw: %q", got)
	}
	if st := OSVStampOf(*ve); !st.Flagged() || !st.Checked.IsZero() {
		t.Errorf("stamp should read flagged with no date, got %+v", st)
	}
}

// TestOSVRescan_NonExactConstraintStillNamesItsRecords is the other half of
// the range rule. The entry is not stamped and not counted, but a record
// matched against the base version is a real record: admission blocks on it,
// and a rescan that reported nothing would be silent on the exact case it
// exists for.
func TestOSVRescan_NonExactConstraintStillNamesItsRecords(t *testing.T) {
	db := dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-range-hit", "minimist", "1.2.9", "1.3.0"))
	ve := &manifest.VersionEntry{
		Version:           "1.2.9",
		VersionConstraint: manifest.ConstraintCompatible,
	}

	ch := rescanChecker(db).Rescan(context.Background(), npmPkg(), ve)
	if ch.Answered || ch.Flagged {
		t.Fatalf("a range entry is still unanswered and uncounted: %+v", ch)
	}
	if len(ch.Vulns) != 1 || ch.Vulns[0] != "GHSA-range-hit" {
		t.Errorf("the matched record must reach the report, got %v", ch.Vulns)
	}
	if len(ve.Metadata) != 0 {
		t.Errorf("an unanswered version is written nothing, got %v", ve.Metadata)
	}
}

// TestOSVDatable pins the predicate the writer and the renderer share. They
// drifted apart once already: the writer stopped dating a range entry and
// `show pkg` kept printing any date one carried as a clean verdict.
func TestOSVDatable(t *testing.T) {
	for _, tc := range []struct {
		constraint string
		want       bool
	}{
		{"", true},
		{manifest.ConstraintExact, true},
		{manifest.ConstraintCompatible, false},
		{manifest.ConstraintPatch, false},
		{manifest.ConstraintAny, false},
		{"constraint-from-a-later-build", false},
	} {
		if got := OSVDatable(manifest.VersionEntry{VersionConstraint: tc.constraint}); got != tc.want {
			t.Errorf("OSVDatable(%q) = %v, want %v", tc.constraint, got, tc.want)
		}
	}
}

// npmVersionList builds an advisory that names its affected versions
// explicitly. OSV's `versions` list matches by string equality, so it is the
// one way a record can cover a version string no ordering can place.
func npmVersionList(id, pkg string, versions ...string) map[string]any {
	list := make([]any, 0, len(versions))
	for _, v := range versions {
		list = append(list, v)
	}
	return map[string]any{
		"id":       id,
		"modified": "2026-09-01T00:00:00Z",
		"affected": []any{map[string]any{
			"package":  map[string]any{"ecosystem": "npm", "name": pkg},
			"versions": list,
		}},
	}
}

// TestOSVRescan_MatchBesideUnreadRecordIsNotDated pins the dating rule against
// the case that reads as complete and is not: a version one record covers by
// name while a second record naming the same package went unread. Matching
// something says nothing about what the unread record would have said, and the
// same version with zero matches beside that record is already unanswered.
// Without this, one hit buys a date and the two halves of the same lookup are
// dated by different rules.
func TestOSVRescan_MatchBesideUnreadRecordIsNotDated(t *testing.T) {
	db := dbWithNpm(t, t.TempDir(),
		npmVersionList("GHSA-exact-2026", "minimist", "nightly-2026"),
		npmAdvisory("GHSA-ranged-2026", "minimist", "0", "9.9.9"),
	)
	ve := &manifest.VersionEntry{Version: "nightly-2026"}

	ch := rescanChecker(db).Rescan(context.Background(), npmPkg(), ve)
	if ch.Answered || ch.Flagged {
		t.Fatalf("an answer missing a record is not one to date: %+v", ch)
	}
	if len(ch.Vulns) != 1 || ch.Vulns[0] != "GHSA-exact-2026" {
		t.Errorf("the matched record must still reach the report, got %v", ch.Vulns)
	}
	if !strings.Contains(ch.Reason, "GHSA-ranged-2026") {
		t.Errorf("the reason must name the record nobody read, got %q", ch.Reason)
	}
	if got := ve.Metadata[OSVMetaCheckedAt]; got != "" {
		t.Errorf("no date is owed for a partial read, got %q", got)
	}
}

// TestOSVCheck_MatchBesideUnreadRecordIsNotDated keeps admission on the same
// rule. Both paths date through conclusive(), so a change that lets one of
// them date a partial read silently moves the other.
func TestOSVCheck_MatchBesideUnreadRecordIsNotDated(t *testing.T) {
	db := dbWithNpm(t, t.TempDir(),
		npmVersionList("GHSA-exact-2026", "minimist", "nightly-2026"),
		npmAdvisory("GHSA-ranged-2026", "minimist", "0", "9.9.9"),
	)
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db

	ve := &manifest.VersionEntry{
		Version:  "nightly-2026",
		Metadata: map[string]string{OSVMetaCheckedAt: "2026-01-01T00:00:00Z"},
	}
	r := ck.Check(context.Background(), npmPkg(), ve)
	if r.Action != ActionBlock {
		t.Fatalf("a matched record still blocks: %+v", r)
	}
	if !strings.Contains(r.Reason, "GHSA-ranged-2026") {
		t.Errorf("admission must name the record nobody read, got %q", r.Reason)
	}
	if ve.Metadata[OSVMetaVulns] != "GHSA-exact-2026" {
		t.Errorf("the ids are still recorded, got %q", ve.Metadata[OSVMetaVulns])
	}
	if got := ve.Metadata[OSVMetaCheckedAt]; got != "" {
		t.Errorf("the stale date must not survive a partial read, got %q", got)
	}
}
