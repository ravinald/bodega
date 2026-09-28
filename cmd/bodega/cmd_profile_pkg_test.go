package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// R1: a freebsd rule is keyed by package name and takes the whole membership
// and expansion vocabulary. Every shape stores, and the stored rule filters by
// the full predicate: with curl pinned, open membership and closed with warn
// or ignore still refuse curl 8.9.1 while permitting the unlisted tree, which
// is what the server's filtered catalogue keeps.
func TestFreeBSDRuleTakesEveryMembershipAndExpansion(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		keepTree bool
	}{
		{[]string{"--membership", "open"}, true},
		{[]string{"--membership", "closed", "--expansion", "warn"}, true},
		{[]string{"--membership", "closed", "--expansion", "ignore"}, true},
		{[]string{"--membership", "closed", "--expansion", "block"}, false},
	} {
		env := newDiscoverEnv(t)
		mustRunProfile(t, "create", "web")
		mustRunProfile(t, "add", "web", "freebsd", "curl", "--constraint", "exact", "--version", "8.8.0")
		out := mustRunProfile(t, append([]string{"set", "web", "freebsd"}, tc.args...)...)
		if !strings.Contains(out, "/freebsd-profile/web/") {
			t.Errorf("set %v does not say where the filtered catalogue is served:\n%s", tc.args, out)
		}
		if says := strings.Contains(out, "drops only versions"); says != tc.keepTree {
			t.Errorf("set %v: says the catalogue keeps unlisted packages = %v, want %v:\n%s", tc.args, says, tc.keepTree, out)
		}
		p := storedProfile(t, env, "web")
		if p.Permits(manifest.TypeFreeBSD, "curl", "8.9.1").Permitted {
			t.Errorf("set %v: curl 8.9.1 is permitted past its pin", tc.args)
		}
		if got := p.Permits(manifest.TypeFreeBSD, "tree", "2.0").Permitted; got != tc.keepTree {
			t.Errorf("set %v: the unlisted tree permitted = %v, want %v", tc.args, got, tc.keepTree)
		}
	}
}

// The baseline file takes the same shapes as the flags.
func TestFreeBSDBaselineFileTakesAWarnRule(t *testing.T) {
	env := newDiscoverEnv(t)
	path := filepath.Join(t.TempDir(), "web.json")
	body := `{"config_version": 1, "name": "web",
  "types": [{"type": "freebsd", "membership": "closed", "version_default": "floating", "expansion": "warn"}],
  "entries": [{"type": "freebsd", "name": "curl", "constraint_kind": "exact", "version": "8.8.0"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the baseline: %v", err)
	}
	mustRunProfile(t, "create", "web", "--from-file", path)
	p := storedProfile(t, env, "web")
	if p.Permits(manifest.TypeFreeBSD, "curl", "8.9.1").Permitted || !p.Permits(manifest.TypeFreeBSD, "tree", "2.0").Permitted {
		t.Errorf("the imported warn rule does not filter by its pin alone")
	}
}

// storedProfile reads a profile back the way the server resolves one.
func storedProfile(t *testing.T, env *discoverEnv, name string) *entitle.Profile {
	t.Helper()
	db, err := audit.Open(env.auditDB)
	if err != nil {
		t.Fatalf("open the audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	d, err := db.GetProfile(context.Background(), name)
	if err != nil {
		t.Fatalf("read profile %s: %v", name, err)
	}
	return entitle.New(d)
}

// R1: compatible and patch compare semantic versions, and a pkg version is
// not one, so an entry carrying either would drop every version it names.
func TestFreeBSDEntryRefusesAConstraintPkgVersionsCannotMeet(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	for _, kind := range []string{manifest.ConstraintCompatible, manifest.ConstraintPatch} {
		_, err := runProfile(t, "add", "web", "freebsd", "nginx", "--constraint", kind, "--version", "1.26.2_1")
		if err == nil {
			t.Fatalf("--constraint %s was accepted on a freebsd entry", kind)
		}
		if !strings.Contains(err.Error(), "port revision") || !strings.Contains(err.Error(), "--constraint exact") {
			t.Errorf("--constraint %s: the refusal does not say why or what to use instead:\n%s", kind, err)
		}
	}
	// The same constraint on another type is untouched.
	mustRunProfile(t, "add", "web", "npm", "left-pad", "--constraint", manifest.ConstraintCompatible, "--version", "1.3.0")
}

// The baseline road reaches the constraint refusal too.
func TestFreeBSDBaselineIsCheckedLikeTheFlags(t *testing.T) {
	doc := profileDoc{
		ConfigVersion: 1,
		Name:          "web",
		Types: []profileDocType{{
			Type: manifest.TypeFreeBSD, Membership: audit.MembershipClosed,
			VersionDefault: audit.VersionFloating, Expansion: audit.ExpansionWarn,
		}},
		Entries: []profileDocEntry{{Type: manifest.TypeFreeBSD, Name: "nginx"}},
	}
	if err := validateDoc(&doc); err != nil {
		t.Errorf("a baseline with a warn freebsd rule was refused: %v", err)
	}
	doc.Entries[0].Constraint, doc.Entries[0].Version = manifest.ConstraintPatch, "1.26.2"
	if err := validateDoc(&doc); err == nil || !strings.Contains(err.Error(), "entries[0]") {
		t.Errorf("a baseline with a patch freebsd entry = %v, want a refusal naming entries[0]", err)
	}
	doc.Entries[0].Constraint = manifest.ConstraintExact
	if err := validateDoc(&doc); err != nil {
		t.Errorf("a closed, block freebsd baseline with an exact entry was refused: %v", err)
	}
}

// A freebsd entry names a package inside a repository, which the manifest
// store never holds, so profile check reports it as unchecked rather than
// failing CI on every one.
func TestProfileCheckDoesNotFailOnFreeBSDEntries(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "freebsd", "nginx")
	out, err := runProfile(t, "check", "web")
	if err != nil {
		t.Fatalf("profile check failed on a freebsd entry: %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 freebsd entry not checked") {
		t.Errorf("profile check does not say the freebsd entry went unchecked:\n%s", out)
	}
}
